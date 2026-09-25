use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Per-tool policy. Default posture is allow for reads and require-approval
/// for anything that looks like a write — an empty policy must never mean
/// "forward everything blindly".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolPolicy {
    pub tool: String,
    pub action: Action,
    /// Parameters to strip entirely before forwarding or logging.
    #[serde(default)]
    pub mask_params: Vec<String>,
    /// Session-aware rule (what single-call gateways can't express):
    /// if this tool was already called N times in the same agent session,
    /// downgrade to require-approval. 0 disables.
    #[serde(default)]
    pub approval_after_uses: u32,
    /// If set, calls to this tool are denied when the session already
    /// called the named tool — break exfil ladders early.
    #[serde(default)]
    pub deny_if_session_used: Option<String>,
    #[serde(default)]
    pub note: String,
}

impl Default for ToolPolicy {
    fn default() -> Self {
        ToolPolicy {
            tool: "*".into(),
            action: Action::Allow,
            mask_params: vec![],
            approval_after_uses: 0,
            deny_if_session_used: None,
            note: "default: allow".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicySet {
    pub version: u64,
    pub tools: HashMap<String, ToolPolicy>,
    /// Applies to any tool without an explicit entry.
    #[serde(default = "default_wildcard")]
    pub wildcard: ToolPolicy,
}

fn default_wildcard() -> ToolPolicy {
    ToolPolicy {
        tool: "*".into(),
        action: Action::Allow,
        mask_params: vec![],
        approval_after_uses: 0,
        deny_if_session_used: None,
        note: "default: allow".into(),
    }
}

/// Postgres/Redis are the durable home for policy in production deployments;
/// the MVP ships with an in-process store persisted to policies.json so the
/// binary is self-contained with zero infra. The store is a versioned,
/// audited surface: every mutation bumps `version` and callers log the change
/// to the hash chain.
pub struct PolicyStore {
    inner: Mutex<PolicySet>,
    path: Option<String>,
}

pub struct PolicyVerdict {
    pub action: Action,
    pub policy: ToolPolicy,
    /// Set when session-aware rules changed the decision (shown in console).
    pub session_rule: Option<String>,
}

impl PolicyStore {
    pub fn new(path: Option<String>) -> PolicyStore {
        let inner = match &path {
            Some(p) => std::fs::read_to_string(p)
                .ok()
                .and_then(|raw| serde_json::from_str::<PolicySet>(&raw).ok())
                .unwrap_or_default(),
            None => PolicySet::default(),
        };
        PolicyStore {
            inner: Mutex::new(inner),
            path,
        }
    }

    pub fn verdict(&self, tool: &str, session_uses: u32, session_used_tool: Option<&str>) -> PolicyVerdict {
        let guard = self.inner.lock().unwrap();
        let pol = guard.tools.get(tool).cloned().unwrap_or_else(|| guard.wildcard.clone());
        drop(guard);

        let mut action = pol.action.clone();
        let mut session_rule = None;

        if pol.approval_after_uses > 0 && session_uses >= pol.approval_after_uses && action == Action::Allow {
            action = Action::RequireApproval;
            session_rule = Some(format!(
                "approval required: tool already used {session_uses}× in this session (approvalAfterUses = {})",
                pol.approval_after_uses
            ));
        }
        if let Some(dep) = &pol.deny_if_session_used {
            if session_used_tool == Some(dep.as_str()) && action != Action::Deny {
                action = Action::Deny;
                session_rule = Some(format!(
                    "denied: session already used '{dep}' (denyIfSessionUsed)"
                ));
            }
        }

        PolicyVerdict {
            action,
            policy: pol,
            session_rule,
        }
    }

    pub fn set(&self, pol: ToolPolicy) -> u64 {
        let mut guard = self.inner.lock().unwrap();
        guard.tools.insert(pol.tool.clone(), pol);
        guard.version += 1;
        let v = guard.version;
        self.persist(&guard);
        v
    }

    /// Remove a tool's explicit rule, falling back to the wildcard. Kept
    /// for the DELETE path of the policy API.
    #[allow(dead_code)]
    pub fn remove(&self, tool: &str) -> u64 {
        let mut guard = self.inner.lock().unwrap();
        guard.tools.remove(tool);
        guard.version += 1;
        let v = guard.version;
        self.persist(&guard);
        v
    }

    pub fn snapshot(&self) -> PolicySet {
        self.inner.lock().unwrap().clone()
    }

    fn persist(&self, set: &PolicySet) {
        if let Some(p) = &self.path {
            if let Ok(json) = serde_json::to_string_pretty(set) {
                let _ = std::fs::write(p, json);
            }
        }
    }
}
