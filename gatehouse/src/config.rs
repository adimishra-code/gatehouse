use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Optional Postgres URL for durable policy/audit storage. The MVP
    /// gateway persists to local append-only files under data/; this field
    /// exists so the docker-compose profile can point at Postgres later.
    #[serde(default)]
    #[allow(dead_code)]
    pub database_url: Option<String>,
    /// Optional Redis URL for shared rate-limit state across replicas.
    #[serde(default)]
    #[allow(dead_code)]
    pub redis_url: Option<String>,
    #[serde(default = "default_tools")]
    pub tools: Vec<ToolConfig>,
    /// Per-agent budget. Every forwarded tools/call consumes one unit;
    /// exceeding it trips the circuit breaker for 60 seconds (ASI08).
    #[serde(default = "default_spend")]
    pub spend_limit_usd: f64,
    /// Per-agent call rate ceiling per minute (ASI08).
    #[serde(default = "default_rate")]
    pub max_calls_per_min: u64,
    /// Estimated cost added per forwarded call (ASI08 spend accounting).
    #[serde(default = "default_cost")]
    pub cost_per_call: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolConfig {
    pub name: String,
    /// HTTP MCP endpoint (streamable HTTP / SSE servers).
    #[serde(default)]
    pub upstream_url: Option<String>,
    /// stdio MCP server: command + args, spawned and proxied by the gateway.
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// Env var holding the real upstream credential. The gateway injects it
    /// as Authorization when forwarding; agents never see it (ASI03).
    #[serde(default)]
    pub upstream_auth_env: Option<String>,
}

fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_spend() -> f64 {
    50.0
}
fn default_rate() -> u64 {
    60
}
fn default_cost() -> f64 {
    0.01
}
fn default_tools() -> Vec<ToolConfig> {
    vec![ToolConfig {
        name: "mcp-echo".into(),
        upstream_url: None,
        command: Some("node".into()),
        args: vec!["demo/mcp-echo-server.mjs".into()],
        upstream_auth_env: None,
    }]
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("invalid TOML in {path}: {e}"))
    }

    pub fn default_cfg() -> Config {
        toml::from_str("").expect("empty TOML with all defaults must parse")
    }

    pub fn tool(&self, name: &str) -> Option<&ToolConfig> {
        self.tools.iter().find(|t| t.name == name)
    }
}
