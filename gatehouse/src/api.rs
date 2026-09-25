use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::models::CallEvent;
use crate::state::SharedState;

/// Operator-facing REST + WebSocket API backing the console.
/// Endpoints are named for what an operator does, not for internal shapes.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/api/stats", get(stats))
        .route("/api/events", get(events))
        .route("/api/stream", get(stream))
        .route("/api/policies", get(get_policies).post(set_policy))
        .route("/api/pending", get(pending))
        .route("/api/pending/{id}/resolve", post(resolve))
        .route("/api/agents/{name}/kill", post(kill_agent))
        .route("/api/sessions", get(sessions))
        .route("/api/owasp", get(owasp))
        .route("/api/settings", get(settings))
}

async fn stats(State(st): State<SharedState>) -> Json<Value> {
    let tail = st.audit.tail(1000);
    let total = tail.len() as u64;
    let blocked = tail.iter().filter(|e| matches!(e.event.decision, crate::models::Decision::Blocked)).count() as u64;
    let pending = tail.iter().filter(|e| matches!(e.event.decision, crate::models::Decision::Pending)).count() as u64;
    let mut lat: Vec<u64> = tail.iter().map(|e| e.event.latency_us).collect();
    lat.sort_unstable();
    let pick = |p: f64| -> u64 {
        if lat.is_empty() { return 0; }
        let idx = ((lat.len() as f64 - 1.0) * p).round() as usize;
        lat[idx.min(lat.len() - 1)]
    };
    let chain_ok = st.audit.verify().is_ok();
    Json(json!({
        "callsTotal": total,
        "blocked": blocked,
        "pendingApprovals": st.pending.lock().unwrap().len(),
        "pendingRecent": pending,
        "activeAgents": st.sessions.active_agents(),
        "p50Us": pick(0.50),
        "p95Us": pick(0.95),
        "auditEntries": st.audit.len(),
        "chainVerified": chain_ok,
        "lastChainHash": st.audit.last_hash(),
    }))
}

async fn events(Query(q): Query<EventsQuery>, State(st): State<SharedState>) -> Json<Value> {
    let n = q.limit.unwrap_or(100).min(1000);
    let entries = st.audit.tail(n);
    Json(json!({ "entries": entries }))
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
}

/// The live call stream. Every audit entry is broadcast to every console.
async fn stream(ws: WebSocketUpgrade, State(st): State<SharedState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        let mut rx = st.tx.subscribe();
        let (mut sink, mut read) = socket.split();
        // Welcome frame so an open console immediately shows the connection.
        let _ = sink
            .send(Message::text(json!({"hello": "gatehouse live stream"}).to_string()))
            .await;
        loop {
            tokio::select! {
                entry = rx.recv() => {
                    if let Ok(e) = entry {
                        if sink.send(Message::text(serde_json::to_string(e.as_ref()).unwrap_or_default())).await.is_err() {
                            break;
                        }
                    }
                }
                msg = read.next() => {
                    if matches!(msg, None | Some(Err(_))) { break; }
                }
            }
        }
    })
}

async fn get_policies(State(st): State<SharedState>) -> Json<Value> {
    Json(serde_json::to_value(st.policies.snapshot()).unwrap_or(json!({})))
}

async fn set_policy(State(st): State<SharedState>, Json(body): Json<Value>) -> Json<Value> {
    let parsed: Result<crate::policy::ToolPolicy, _> = serde_json::from_value(body.clone());
    match parsed {
        Ok(pol) => {
            let version = st.policies.set(pol.clone());
            // Policy changes are themselves audited events.
            let ev = policy_event(st.next_id(), &pol.tool, format!("policy set to {:?} ({})", pol.action, pol.note));
            st.publish(st.audit.append(&ev));
            Json(json!({ "ok": true, "version": version }))
        }
        Err(e) => Json(json!({ "ok": false, "error": format!("invalid policy: {e}") })),
    }
}

fn policy_event(id: u64, tool: &str, detail: String) -> CallEvent {
    CallEvent {
        id,
        ts: chrono::Utc::now(),
        agent: "operator".into(),
        session_id: "console".into(),
        server: "-".into(),
        tool: tool.into(),
        action: "policy.update".into(),
        decision: crate::models::Decision::Allowed,
        reasons: vec![detail],
        latency_us: 0,
        request: json!({}),
        response: None,
        redactions: 0,
    }
}

async fn pending(State(st): State<SharedState>) -> Json<Value> {
    let map = st.pending.lock().unwrap();
    let items: Vec<Value> = map
        .iter()
        .map(|(id, r)| {
            json!({
                "id": id,
                "agent": r.agent,
                "sessionId": r.session_id,
                "server": r.server,
                "tool": r.tool,
                "request": r.request,
                "created": r.created,
                "ageSecs": (chrono::Utc::now() - r.created).num_seconds(),
            })
        })
        .collect();
    Json(json!({ "items": items }))
}

#[derive(Deserialize)]
struct ResolveBody {
    approve: bool,
}

async fn resolve(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    Json(body): Json<ResolveBody>,
) -> Json<Value> {
    let req = st.pending.lock().unwrap().remove(&id);
    match req {
        Some(r) => {
            let _ = r.resolver.send(body.approve);
            Json(json!({ "ok": true, "resolved": id }))
        }
        None => Json(json!({ "ok": false, "error": "no such pending approval (already resolved or expired)" })),
    }
}

/// Kill switch (ASI10): one call revokes an agent mid-session. Also revokes
/// every short-lived assertion the agent currently holds.
async fn kill_agent(State(st): State<SharedState>, Path(name): Path<String>) -> Json<Value> {
    let revoked_assertions = st.creds.revoke_agent(&name);
    st.sessions.kill(&name);
    let ev = CallEvent {
        id: st.next_id(),
        ts: chrono::Utc::now(),
        agent: "operator".into(),
        session_id: "console".into(),
        server: "-".into(),
        tool: name.clone(),
        action: "agent.kill".into(),
        decision: crate::models::Decision::Allowed,
        reasons: vec![format!(
            "kill switch engaged: agent '{name}' revoked mid-session, {revoked_assertions} assertion(s) invalidated"
        )],
        latency_us: 0,
        request: json!({}),
        response: None,
        redactions: 0,
    };
    st.publish(st.audit.append(&ev));
    Json(json!({ "ok": true, "agent": name, "revokedAssertions": revoked_assertions }))
}

async fn sessions(State(st): State<SharedState>) -> Json<Value> {
    let snap = st.sessions.snapshot();
    let items: Vec<Value> = snap
        .into_iter()
        .map(|(sid, r)| {
            json!({
                "sessionId": sid,
                "agent": r.agent,
                "started": r.started,
                "lastSeen": r.last_seen,
                "calls": r.calls,
                "blocked": r.blocked,
                "toolsUsed": r.tools_used,
            })
        })
        .collect();
    Json(json!({ "items": items, "killed": st.sessions.killed_list() }))
}

/// The OWASP Agentic Top 10 coverage map — the same data rendered in the
/// console coverage view and the README table. Single source of truth.
async fn owasp() -> Json<Value> {
    let items = vec![
        json!({"id":"ASI01","name":"Agent goal hijack","status":"covered","how":"Tier-1 injection scanner on every request path; response scanner flags instructions re-entering context","view":"Live stream reasons + Alerts"}),
        json!({"id":"ASI02","name":"Tool misuse and exploitation","status":"covered","how":"Per-tool allow / deny / require-approval policies with masking, versioned and audited","view":"Policies"}),
        json!({"id":"ASI03","name":"Identity and privilege abuse","status":"covered","how":"Gateway holds real upstream credentials; agents receive 120s tool-scoped signed assertions","view":"Agents & tools"}),
        json!({"id":"ASI04","name":"Agentic supply chain","status":"partial","how":"MVP tracks server inventory and spawn commands; provenance verification is roadmap","view":"Agents & tools"}),
        json!({"id":"ASI05","name":"Unexpected code execution","status":"covered","how":"Command-substitution, shell-chaining, traversal and .ssh/.env patterns blocked on request and response","view":"Alerts"}),
        json!({"id":"ASI06","name":"Memory and context poisoning","status":"covered","how":"Tool responses scanned for injected instructions and redacted before returning to the agent","view":"Live stream (flagged in response)"}),
        json!({"id":"ASI07","name":"Insecure inter-agent comms","status":"roadmap","how":"Out of MVP scope; agent-to-agent trust brokering planned","view":"Roadmap"}),
        json!({"id":"ASI08","name":"Cascading failures","status":"covered","how":"Per-agent call rate, spend ceiling and 60s circuit breaker on breach","view":"Overview + Settings"}),
        json!({"id":"ASI09","name":"Human-agent trust exploitation","status":"covered","how":"Require-approval policies park calls in an operator queue; silence means denied after 120s","view":"Approvals in Live stream + Policies"}),
        json!({"id":"ASI10","name":"Rogue agents","status":"covered","how":"Kill switch revokes an agent or session instantly, mid-flight, with audit entry","view":"Agents & tools"}),
    ];
    Json(json!({ "items": items }))
}

async fn settings(State(st): State<SharedState>) -> Json<Value> {
    Json(json!({
        "listen": st.cfg.listen,
        "spendLimitUsd": st.cfg.spend_limit_usd,
        "maxCallsPerMin": st.cfg.max_calls_per_min,
        "costPerCall": st.cfg.cost_per_call,
        "servers": st.cfg.tools.iter().map(|t| json!({
            "name": t.name,
            "transport": if t.upstream_url.is_some() { "http" } else { "stdio" },
            "command": t.command,
            "args": t.args,
            "upstreamUrl": t.upstream_url,
            "authFromEnv": t.upstream_auth_env.is_some(),
            "hasCredential": t.upstream_auth_env.as_deref().map(|e| st.creds.has_token(e)).unwrap_or(false),
        })).collect::<Vec<_>>(),
        "redactionRules": [
            {"name": "openai-key", "applies": "sk-… API keys"},
            {"name": "aws-access-key", "applies": "AKIA… access key ids"},
            {"name": "github-pat", "applies": "ghp_/gho_/ghu_/ghs_/ghr_ tokens"},
            {"name": "slack-token", "applies": "xoxa-/xoxb-/xoxp- tokens"},
            {"name": "google-api-key", "applies": "AIza… keys"},
            {"name": "jwt", "applies": "three-segment JWTs"},
            {"name": "private-key-block", "applies": "PEM private keys"},
            {"name": "high-entropy-blob", "applies": "credential-shaped random strings"},
            {"name": "email", "applies": "email addresses, domain partially kept"},
            {"name": "card", "applies": "Luhn-validated card numbers only"},
            {"name": "ssn", "applies": "US SSN format"}
        ]
    }))
}
