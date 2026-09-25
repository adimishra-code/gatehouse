use crate::audit::AuditChain;
use crate::config::Config;
use crate::creds::CredBroker;
use crate::limiter::Limiter;
use crate::policy::PolicyStore;
use crate::sessions::SessionStore;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, oneshot};

use crate::stdio_proxy::StdioTransport;

/// A human-approval request created by a require-approval policy (ASI09).
/// The in-flight tool call parks until an operator approves or denies it
/// from the console (or it times out and is denied).
pub struct ApprovalRequest {
    pub agent: String,
    pub session_id: String,
    pub server: String,
    pub tool: String,
    pub request: serde_json::Value,
    pub created: chrono::DateTime<chrono::Utc>,
    pub resolver: oneshot::Sender<bool>,
}

pub struct AppState {
    pub cfg: Config,
    pub engine: crate::detections::Engine,
    pub policies: PolicyStore,
    pub audit: AuditChain,
    pub sessions: SessionStore,
    pub limiter: Limiter,
    pub creds: CredBroker,
    /// Live event bus feeding every connected console WebSocket.
    pub tx: broadcast::Sender<Arc<crate::audit::AuditEntry>>,
    pub seq: AtomicU64,
    pub pending: Mutex<HashMap<String, ApprovalRequest>>,
    /// Long-lived stdio connections to MCP servers we spawn ourselves.
    pub stdio: Mutex<HashMap<String, StdioTransport>>,
}

impl AppState {
    pub fn publish(&self, entry: crate::audit::AuditEntry) {
        let _ = self.tx.send(Arc::new(entry));
    }

    pub fn next_id(&self) -> u64 {
        self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    }
}

pub type SharedState = Arc<AppState>;
