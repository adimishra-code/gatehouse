use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Session awareness is the thing single-call gateways can't do: policy
/// decisions here consider what the agent already did in this workflow,
/// not just the current request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRec {
    pub agent: String,
    pub started: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub calls: u64,
    pub blocked: u64,
    /// Tools this session has already invoked, in order.
    pub tools_used: Vec<String>,
}

#[derive(Default)]
pub struct SessionStore {
    map: Mutex<HashMap<String, SessionRec>>,
    killed_sessions: Mutex<HashSet<String>>,
    killed_agents: Mutex<HashSet<String>>,
}

impl SessionStore {
    pub fn new() -> SessionStore {
        SessionStore::default()
    }

    /// Record a call and return how many times this session already used
    /// the tool (0 on first use) — feeds approvalAfterUses policy rules.
    pub fn record(&self, session_id: &str, agent: &str, tool: &str) -> u32 {
        let mut map = self.map.lock().unwrap();
        let rec = map.entry(session_id.to_string()).or_insert_with(|| SessionRec {
            agent: agent.to_string(),
            started: Utc::now(),
            last_seen: Utc::now(),
            calls: 0,
            blocked: 0,
            tools_used: vec![],
        });
        let uses = rec.tools_used.iter().filter(|t| *t == tool).count() as u32;
        rec.calls += 1;
        rec.last_seen = Utc::now();
        if !rec.tools_used.iter().any(|t| t == tool) {
            rec.tools_used.push(tool.to_string());
        }
        uses
    }

    pub fn mark_blocked(&self, session_id: &str) {
        if let Some(rec) = self.map.lock().unwrap().get_mut(session_id) {
            rec.blocked += 1;
            rec.last_seen = Utc::now();
        }
    }

    pub fn session_used(&self, session_id: &str, tool: &str) -> bool {
        self.map
            .lock()
            .unwrap()
            .get(session_id)
            .map(|r| r.tools_used.iter().any(|t| t == tool))
            .unwrap_or(false)
    }

    /// Kill switch (ASI10): revoke by session id or by agent name, effective
    /// for every subsequent call, mid-session, no restart.
    pub fn kill(&self, target: &str) -> bool {
        let by_session = self.map.lock().unwrap().contains_key(target);
        if by_session {
            self.killed_sessions.lock().unwrap().insert(target.to_string());
        }
        self.killed_agents.lock().unwrap().insert(target.to_string());
        // Also kill any session belonging to an agent with this name.
        let mut sessions = self.killed_sessions.lock().unwrap();
        for (sid, rec) in self.map.lock().unwrap().iter() {
            if rec.agent == target {
                sessions.insert(sid.clone());
            }
        }
        true
    }

    pub fn is_killed(&self, session_id: &str, agent: &str) -> bool {
        if self.killed_agents.lock().unwrap().contains(agent) {
            return true;
        }
        self.killed_sessions.lock().unwrap().contains(session_id)
    }

    pub fn killed_list(&self) -> Vec<String> {
        let mut v: Vec<String> = self.killed_agents.lock().unwrap().iter().cloned().collect();
        v.sort();
        v
    }

    pub fn active_agents(&self) -> usize {
        let map = self.map.lock().unwrap();
        let mut agents: Vec<&str> = map.values().map(|r| r.agent.as_str()).collect();
        agents.sort();
        agents.dedup();
        agents.len()
    }

    pub fn snapshot(&self) -> Vec<(String, SessionRec)> {
        let map = self.map.lock().unwrap();
        let mut v: Vec<(String, SessionRec)> =
            map.iter().map(|(k, r)| (k.clone(), r.clone())).collect();
        v.sort_by_key(|(_, r)| r.last_seen);
        v.reverse();
        v
    }
}
