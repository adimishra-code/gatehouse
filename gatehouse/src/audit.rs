use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

use crate::models::CallEvent;

/// Append-only, tamper-evident audit trail.
///
/// Every entry stores H(prev_hash ‖ canonical_json(entry_without_hash)).
/// Any retroactive edit or deletion breaks every subsequent link, and
/// `verify()` detects it. Entries are also persisted append-only to
/// data/audit.log (one JSON per line) so the chain survives restarts.
/// In Postgres deployments this table is the evidence store; the file is
/// the zero-infra default.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: String,
    pub event: CallEvent,
    pub prev_hash: String,
    pub hash: String,
}

pub struct AuditChain {
    inner: Mutex<ChainState>,
    file_path: Option<String>,
}

struct ChainState {
    seq: u64,
    prev_hash: String,
    entries: Vec<AuditEntry>,
}

fn canonical(event: &CallEvent, seq: u64, ts: &str, prev: &str) -> String {
    // Deterministic serialization: serde_json on a struct with fixed field
    // order is stable for the same data — good enough for chain integrity.
    format!("{seq}|{ts}|{prev}|{}", serde_json::to_string(event).unwrap_or_default())
}

fn digest(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

impl AuditChain {
    pub fn new(file_path: Option<String>) -> AuditChain {
        // Rebuild from disk so the chain continues across restarts.
        let mut seq = 0u64;
        let mut prev_hash = String::from("GENESIS");
        let mut entries = Vec::new();
        if let Some(p) = &file_path {
            if let Ok(raw) = std::fs::read_to_string(p) {
                for line in raw.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(e) = serde_json::from_str::<AuditEntry>(line) {
                        seq = e.seq;
                        prev_hash = e.hash.clone();
                        entries.push(e);
                    }
                }
            }
        }
        AuditChain {
            inner: Mutex::new(ChainState { seq, prev_hash, entries }),
            file_path,
        }
    }

    pub fn append(&self, event: &CallEvent) -> AuditEntry {
        let mut guard = self.inner.lock().unwrap();
        guard.seq += 1;
        let seq = guard.seq;
        let ts = Utc::now().to_rfc3339();
        let prev_hash = guard.prev_hash.clone();
        let hash = digest(&canonical(event, seq, &ts, &prev_hash));
        let entry = AuditEntry {
            seq,
            ts,
            event: event.clone(),
            prev_hash,
            hash,
        };
        guard.prev_hash = entry.hash.clone();
        guard.entries.push(entry.clone());
        if guard.entries.len() > 5000 {
            guard.entries.drain(0..2500);
        }
        drop(guard);

        if let Some(p) = &self.file_path {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                if let Ok(line) = serde_json::to_string(&entry) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        entry
    }

    /// Walk the whole chain; returns Ok(count) when unbroken, Err at the
    /// first sequence number whose recomputed hash doesn't match.
    pub fn verify(&self) -> Result<u64, String> {
        let guard = self.inner.lock().unwrap();
        let mut prev = String::from("GENESIS");
        for e in &guard.entries {
            let expect = digest(&canonical(&e.event, e.seq, &e.ts, &prev));
            if expect != e.hash {
                return Err(format!(
                    "chain broken at entry {}: stored hash does not match recomputed hash",
                    e.seq
                ));
            }
            if e.prev_hash != prev {
                return Err(format!("chain broken at entry {}: prev_hash mismatch", e.seq));
            }
            prev = e.hash.clone();
        }
        Ok(guard.seq)
    }

    pub fn tail(&self, n: usize) -> Vec<AuditEntry> {
        let guard = self.inner.lock().unwrap();
        guard.entries.iter().rev().take(n).cloned().collect()
    }

    pub fn last_hash(&self) -> String {
        self.inner.lock().unwrap().prev_hash.clone()
    }

    /// Total entries appended since genesis (including rotated-out ones).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.inner.lock().unwrap().seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CallEvent, Decision};

    fn event(id: u64) -> CallEvent {
        CallEvent {
            id,
            ts: Utc::now(),
            agent: "test-agent".into(),
            session_id: "s1".into(),
            server: "mcp-echo".into(),
            tool: "echo".into(),
            action: "tools/call".into(),
            decision: Decision::Allowed,
            reasons: vec![],
            latency_us: 42,
            request: serde_json::json!({}),
            response: None,
            redactions: 0,
        }
    }

    #[test]
    fn chain_verifies_and_detects_tamper() {
        let dir = std::env::temp_dir().join(format!("gh-chain-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        let _ = std::fs::remove_file(&log);
        let chain = AuditChain::new(Some(log.to_string_lossy().to_string()));
        for i in 1..=5 {
            chain.append(&event(i));
        }
        assert_eq!(chain.verify().unwrap(), 5);

        // Tamper: rewrite the second line's event in the file.
        let raw = std::fs::read_to_string(&log).unwrap();
        let mut lines: Vec<String> = raw.lines().map(String::from).collect();
        let mut e: AuditEntry = serde_json::from_str(&lines[1]).unwrap();
        e.event.agent = "tampered".into();
        lines[1] = serde_json::to_string(&e).unwrap();
        std::fs::write(&log, lines.join("\n") + "\n").unwrap();

        // A fresh chain loaded from disk must detect the break.
        let reloaded = AuditChain::new(Some(log.to_string_lossy().to_string()));
        assert!(reloaded.verify().is_err());
        let _ = std::fs::remove_file(&log);
    }
}
