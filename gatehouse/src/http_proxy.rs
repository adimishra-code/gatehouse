use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

use crate::models::{CallEvent, Decision};
use crate::redact::redact_json;
use crate::state::SharedState;

/// Agents always talk HTTP to the gatehouse. Upstream may be an HTTP MCP
/// server or a stdio subprocess — the handler below picks per config, so
/// the agent never knows or cares which.
pub fn router() -> Router<SharedState> {
    Router::new().route("/{server}", post(gate))
}

async fn gate(
    State(st): State<SharedState>,
    Path(server): Path<String>,
    req: Request<Body>,
) -> Response {
    let t0 = Instant::now();
    let agent = req
        .headers()
        .get("x-gatehouse-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown-agent")
        .to_string();
    let fallback = format!("{agent}-default");
    let session_id = req
        .headers()
        .get("x-gatehouse-session")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&fallback)
        .to_string();

    let cfg = st.cfg.clone();
    let tool_cfg = match cfg.tool(&server) {
        Some(c) => c.clone(),
        None => return err_response(StatusCode::NOT_FOUND, &format!("unknown MCP server '{server}' not configured in gatehouse")),
    };

    let body_bytes = match axum::body::to_bytes(req.into_body(), 2 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return err_response(StatusCode::BAD_REQUEST, "unreadable request body"),
    };
    let mut payload: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return err_response(StatusCode::BAD_REQUEST, "request body is not valid JSON-RPC"),
    };
    let method = payload
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string();
    let action = method.clone();
    let tool = payload
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("-")
        .to_string();

    // Kill switch first (ASI10): a killed agent gets nothing, even a
    // new session id, and the attempt is recorded.
    if st.sessions.is_killed(&session_id, &agent) {
        let ev = build_event(st.next_id(), &agent, &session_id, &server, &tool, &action, Decision::Blocked, vec!["kill switch active: this agent was revoked by an operator".into()], t0, payload.clone(), None, 0);
        st.publish(st.audit.append(&ev));
        return err_response(StatusCode::FORBIDDEN, "kill switch active: agent revoked by operator");
    }

    // Rate/spend limits with circuit breaker (ASI08).
    let limit = st.limiter.check(&agent, &cfg);
    if !limit.allowed {
        let why = limit.reason.clone().unwrap_or_else(|| "rate limited".into());
        let ev = build_event(st.next_id(), &agent, &session_id, &server, &tool, &action, Decision::Blocked, vec![why.clone()], t0, payload.clone(), None, 0);
        st.publish(st.audit.append(&ev));
        return err_response(StatusCode::TOO_MANY_REQUESTS, &why);
    }

    // Redact request params before anything else sees them (LLM06).
    let mut redactions = 0usize;
    if let Some(params) = payload.get_mut("params") {
        redactions += redact_json(params);
    }

    // Tier-1 detection on the serialized request (ASI01, ASI05, LLM06).
    let request_text = payload.to_string();
    let mut reasons: Vec<String> = Vec::new();
    let mut blocked = false;
    if !st.engine.excluded(&action) {
        for f in st.engine.scan(&request_text) {
            blocked = true;
            reasons.push(format!(
                "blocked: {} — rule '{}' matched '{}' [{}]",
                f.family, f.rule, f.evidence, crate::detections::owasp_for(f.family, false)
            ));
        }
    }

    // Session-aware policy (ASI02 + the multi-step rules single-call
    // gateways can't express). Recording before the verdict so session
    // history reflects attempts, not only successes.
    let uses = st.sessions.record(&session_id, &agent, &tool);
    // denyIfSessionUsed fires only when this session actually invoked the
    // dependency tool earlier — pulled from observed session history, not
    // from the policy text itself.
    let dep = {
        let snap = st.policies.snapshot();
        snap.tools.get(&tool).and_then(|p| p.deny_if_session_used.clone())
    };
    let session_used_dep = match &dep {
        Some(d) if st.sessions.session_used(&session_id, d) => Some(d.clone()),
        _ => None,
    };
    let verdict = st.policies.verdict(
        &tool,
        uses,
        session_used_dep.as_deref(),
    );

    match verdict.action {
        crate::policy::Action::Deny => {
            blocked = true;
            reasons.push(format!("policy: tool '{tool}' is denied ({})", verdict.policy.note));
        }
        crate::policy::Action::RequireApproval if !blocked => {
            let sess_rule = verdict
                .session_rule
                .clone()
                .unwrap_or_else(|| "policy: this tool requires human approval".into());
            reasons.push(sess_rule);
            return approval_gate(st, agent, session_id, server, tool, action, payload, reasons, redactions, t0, cfg.spend_limit_usd).await;
        }
        _ => {}
    }
    if let Some(rule) = &verdict.session_rule {
        reasons.push(rule.clone());
    }
    if blocked {
        st.sessions.mark_blocked(&session_id);
        let msg = reasons.first().cloned().unwrap_or_else(|| "blocked by policy".into());
        let ev = build_event(st.next_id(), &agent, &session_id, &server, &tool, &action, Decision::Blocked, reasons, t0, payload.clone(), None, redactions);
        st.publish(st.audit.append(&ev));
        return err_response(StatusCode::FORBIDDEN, &msg);
    }

    // Forward upstream.
    let (response, forward_err) = forward(&st, &server, &tool_cfg, &method, &payload, &agent).await;
    if let Some(e) = forward_err {
        reasons.push(format!("upstream error: {e}"));
        let ev = build_event(st.next_id(), &agent, &session_id, &server, &tool, &action, Decision::Blocked, reasons, t0, payload, None, redactions);
        st.publish(st.audit.append(&ev));
        return err_response(StatusCode::BAD_GATEWAY, &format!("upstream MCP server unreachable: {e}"));
    }
    let mut response = response.unwrap();

    // Tool RESPONSES get their own pass: flag injected instructions before
    // they re-enter the agent's context (ASI06) and redact secrets/PII.
    if let Some(res_params) = response.get_mut("params") {
        redactions += redact_json(res_params);
    }
    let res_text = response.to_string();
    for f in st.engine.scan_response(&res_text) {
        reasons.push(format!(
            "flagged in response: {} — rule '{}' matched '{}' [{}]",
            f.family, f.rule, f.evidence, crate::detections::owasp_for(f.family, true)
        ));
    }

    let latency = t0.elapsed();
    let ev = build_event(
        st.next_id(), &agent, &session_id, &server, &tool, &action,
        Decision::Allowed, reasons, t0, payload, Some(response.clone()), redactions,
    );
    st.publish(st.audit.append(&ev));
    let _ = latency; // latency recorded inside build_event via t0
    axum::Json(response).into_response()
}

/// The human-in-the-loop parking lot (ASI09). The call waits here until an
/// operator approves or denies it from the console, or it times out denied.
#[allow(clippy::too_many_arguments)]
async fn approval_gate(
    st: SharedState,
    agent: String,
    session_id: String,
    server: String,
    tool: String,
    action: String,
    payload: Value,
    reasons: Vec<String>,
    redactions: usize,
    t0: Instant,
    _spend: f64,
) -> Response {
    use tokio::sync::oneshot;
    let (tx, rx) = oneshot::channel::<bool>();
    let id = uuid::Uuid::new_v4().to_string();
    st.pending.lock().unwrap().insert(
        id.clone(),
        crate::state::ApprovalRequest {
            agent: agent.clone(),
            session_id: session_id.clone(),
            server: server.clone(),
            tool: tool.clone(),
            request: payload.clone(),
            created: chrono::Utc::now(),
            resolver: tx,
        },
    );
    let ev = build_event(st.next_id(), &agent, &session_id, &server, &tool, &action, Decision::Pending, reasons, t0, payload.clone(), None, redactions);
    st.publish(st.audit.append(&ev));

    match tokio::time::timeout(Duration::from_secs(120), rx).await {
        Ok(Ok(true)) => {
            // Operator approved. Re-run the gate as an approved call.
            let (response, forward_err) = forward(&st, &server, &tool_cfg_of(&st, &server), &action, &payload, &agent).await;
            match (response, forward_err) {
                (Some(mut r), None) => {
                    let mut red = redactions;
                    if let Some(p) = r.get_mut("params") {
                        red += redact_json(p);
                    }
                    let ev = build_event(st.next_id(), &agent, &session_id, &server, &tool, &action, Decision::Approved, vec!["operator approved this call from the console".into()], t0, payload, Some(r.clone()), red);
                    st.publish(st.audit.append(&ev));
                    axum::Json(r).into_response()
                }
                (_, Some(e)) => err_response(StatusCode::BAD_GATEWAY, &format!("upstream MCP server unreachable: {e}")),
                _ => err_response(StatusCode::BAD_GATEWAY, "upstream failure"),
            }
        }
        _ => {
            st.pending.lock().unwrap().remove(&id);
            let ev = build_event(st.next_id(), &agent, &session_id, &server, &tool, &action, Decision::Denied, vec!["timed out waiting for operator approval — denied by default".into()], t0, payload, None, redactions);
            st.publish(st.audit.append(&ev));
            err_response(StatusCode::FORBIDDEN, "approval timeout: no operator response in 120s, call denied by default")
        }
    }
}

fn tool_cfg_of(st: &SharedState, server: &str) -> crate::config::ToolConfig {
    st.cfg.tool(server).cloned().unwrap_or(crate::config::ToolConfig {
        name: server.into(),
        upstream_url: None,
        command: None,
        args: vec![],
        upstream_auth_env: None,
    })
}

async fn forward(
    st: &SharedState,
    server: &str,
    tool_cfg: &crate::config::ToolConfig,
    method: &str,
    payload: &Value,
    agent: &str,
) -> (Option<Value>, Option<String>) {
    let id = json!(st.next_id());
    let tool_name = payload
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("-")
        .to_string();

    // ASI03: every forwarded call carries a fresh, 120-second assertion
    // scoped to (server, tool, agent). It is verified before anything goes
    // upstream — and a killed agent's outstanding assertions are worthless.
    let assertion = st.creds.issue(server, &tool_name, agent);
    if let Err(e) = st.creds.verify(&assertion, server, &tool_name) {
        return (None, Some(format!("credential assertion rejected: {e}")));
    }

    let rpc = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": payload.get("params").cloned().unwrap_or(json!({})),
    });

    if let Some(url) = &tool_cfg.upstream_url {
        return http_post(url, &rpc, tool_cfg, st, &assertion).await;
    }
    if let Some(_cmd) = &tool_cfg.command {
        let transport = match st.stdio.lock().unwrap().get(server) {
            Some(t) => t.clone(),
            None => return (None, Some("stdio server not running".into())),
        };
        match transport.request(rpc).await {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, Some("tool has no upstream configured".into()))
    }
}

async fn http_post(
    url: &str,
    rpc: &Value,
    tool_cfg: &crate::config::ToolConfig,
    st: &SharedState,
    assertion: &str,
) -> (Option<Value>, Option<String>) {
    use http_body_util::BodyExt;
    // The real upstream credential is looked up by server name and injected
    // here — the agent never held it. The assertion rides along as evidence
    // of a gateway-authorized call.
    let auth = if st.creds.has_token(&tool_cfg.name) {
        format!("Bearer {}", st.creds.real_token(&tool_cfg.name).unwrap_or_default())
    } else {
        String::new()
    };
    let req = hyper::Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .header("authorization", auth)
        .header("x-gatehouse-assertion", assertion)
        .body(Body::from(rpc.to_string()));
    let req = match req {
        Ok(r) => r,
        Err(e) => return (None, Some(e.to_string())),
    };
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
    match tokio::time::timeout(Duration::from_secs(30), client.request(req)).await {
        Ok(Ok(resp)) => match resp.into_body().collect().await {
            Ok(collected) => match serde_json::from_slice::<Value>(&collected.to_bytes()) {
                Ok(v) => (Some(v), None),
                Err(e) => (None, Some(format!("upstream returned non-JSON: {e}"))),
            },
            Err(e) => (None, Some(e.to_string())),
        },
        Ok(Err(e)) => (None, Some(e.to_string())),
        Err(_) => (None, Some("upstream timed out after 30s".into())),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_event(
    id: u64,
    agent: &str,
    session_id: &str,
    server: &str,
    tool: &str,
    action: &str,
    decision: Decision,
    reasons: Vec<String>,
    t0: Instant,
    request: Value,
    response: Option<Value>,
    redactions: usize,
) -> CallEvent {
    CallEvent {
        id,
        ts: chrono::Utc::now(),
        agent: agent.into(),
        session_id: session_id.into(),
        server: server.into(),
        tool: tool.into(),
        action: action.into(),
        decision,
        reasons,
        latency_us: t0.elapsed().as_micros() as u64,
        request,
        response,
        redactions,
    }
}

fn err_response(code: StatusCode, msg: &str) -> Response {
    let body = json!({
        "jsonrpc": "2.0",
        "error": { "code": -32000, "message": msg },
        "gatehouse": { "blocked": true, "reason": msg }
    });
    (code, axum::Json(body)).into_response()
}
