use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What the gateway decided about a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allowed,
    Blocked,
    Pending,
    Approved,
    Denied,
}

/// One call that passed through the gate. Stored in the audit chain and
/// streamed to the console. Request/response payloads are redacted BEFORE
/// they reach this struct — the audit trail never holds live secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallEvent {
    pub id: u64,
    pub ts: DateTime<Utc>,
    pub agent: String,
    pub session_id: String,
    /// The MCP server the call was addressed to.
    pub server: String,
    /// The tool invoked on that server ("-" for non tools/call traffic).
    pub tool: String,
    /// MCP method, e.g. "tools/call", "initialize", "tools/list".
    pub action: String,
    pub decision: Decision,
    pub reasons: Vec<String>,
    /// Hot-path time spent by the gateway itself (detection + policy),
    /// excluding upstream tool execution and human approval waits.
    pub latency_us: u64,
    pub request: serde_json::Value,
    pub response: Option<serde_json::Value>,
    pub redactions: usize,
}
