mod api;
mod audit;
mod config;
mod creds;
mod detections;
mod http_proxy;
mod limiter;
mod models;
mod policy;
mod redact;
mod sessions;
mod state;
mod stdio_proxy;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use config::Config;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(run());
}

async fn run() {
    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "gatehouse.toml".to_string());
    let cfg = if std::path::Path::new(&cfg_path).exists() {
        match Config::load(&cfg_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("gatehouse: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!(
            "gatehouse: no {cfg_path} found — using defaults (one stdio echo tool, listen on {})",
            Config::default_cfg().listen
        );
        Config::default_cfg()
    };

    std::fs::create_dir_all("data").ok();
    let policies = policy::PolicyStore::new(Some("policies.json".to_string()));
    let audit = audit::AuditChain::new(Some("data/audit.log".to_string()));
    let creds = creds::CredBroker::new();

    // Pull real upstream credentials out of the environment, once, at boot.
    // They never appear in config dumps, the console, or audit entries.
    for tool in &cfg.tools {
        if let Some(env_name) = &tool.upstream_auth_env {
            if creds.register_from_env(&tool.name, env_name) {
                tracing::info!("credential for server '{}' loaded from env (value withheld)", tool.name);
            } else {
                tracing::warn!("env var {env_name} for server '{}' not set — upstream auth disabled", tool.name);
            }
        }
    }

    // Spawn configured stdio MCP servers up front.
    let mut stdio: HashMap<String, stdio_proxy::StdioTransport> = HashMap::new();
    for tool in &cfg.tools {
        if let Some(cmd) = &tool.command {
            match stdio_proxy::StdioTransport::spawn(cmd, &tool.args) {
                Ok(t) => {
                    let arglist = tool.args.join(" ");
                    tracing::info!("stdio server '{}' spawned ({cmd} {arglist})", tool.name);
                    stdio.insert(tool.name.clone(), t);
                }
                Err(e) => tracing::warn!("server '{}' not started: {e}", tool.name),
            }
        }
    }

    let (tx, _rx) = tokio::sync::broadcast::channel::<Arc<audit::AuditEntry>>(512);
    let state = Arc::new(state::AppState {
        cfg: cfg.clone(),
        engine: detections::Engine::new(),
        policies,
        audit,
        sessions: sessions::SessionStore::new(),
        limiter: limiter::Limiter::new(),
        creds,
        tx,
        seq: std::sync::atomic::AtomicU64::new(0),
        pending: Mutex::new(HashMap::new()),
        stdio: Mutex::new(stdio),
    });

    let app = api::router().merge(http_proxy::router()).with_state(state.clone());

    // Serve the built console from console/dist when present — one binary,
    // one command, no separate frontend process.
    let app = if std::path::Path::new("console/dist/index.html").exists() {
        let serve = tower_http::services::ServeDir::new("console/dist");
        app.fallback_service(serve)
    } else {
        app
    };

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .expect("bind listen address");
    tracing::info!(
        "gatehouse listening on http://{} — console at /, MCP gate at /:server",
        cfg.listen
    );
    tracing::info!(
        "audit chain continuing from entry {} (last hash {}…)",
        audit::AuditChain::len(&state.audit),
        &state.audit.last_hash()[..16.min(state.audit.last_hash().len())]
    );

    axum::serve(listener, app).await.expect("server error");
}
