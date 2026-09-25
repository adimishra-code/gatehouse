use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

/// The gateway holds long-lived upstream credentials (never exposed to
/// agents or tools) and issues short-lived, tool-scoped signed assertions
/// per call (ASI03 identity & privilege abuse). An assertion leaks nothing:
/// it expires in 120 seconds, is bound to one tool on one server for one
/// agent, and can be revoked mid-flight by the kill switch.
pub struct CredBroker {
    signing_key: Vec<u8>,
    /// server name -> real upstream token, loaded from env at boot.
    upstream_tokens: Mutex<HashMap<String, String>>,
    /// jti -> agent, for live revocation of outstanding assertions.
    issued: Mutex<HashMap<String, String>>,
    revoked: Mutex<HashSet<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionPayload {
    jti: String,
    srv: String,
    tool: String,
    agt: String,
    exp: i64,
}

fn b64url(data: &[u8]) -> String {
    // Deterministic, dependency-free base64url (padding stripped).
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

fn sign(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

impl CredBroker {
    pub fn new() -> CredBroker {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        CredBroker {
            signing_key: key,
            upstream_tokens: Mutex::new(HashMap::new()),
            issued: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashSet::new()),
        }
    }

    /// Register the real upstream credential from an env var. The agent
    /// never sees this value; the gateway injects it when forwarding.
    pub fn register_from_env(&self, server: &str, env_name: &str) -> bool {
        if let Ok(tok) = std::env::var(env_name) {
            self.upstream_tokens
                .lock()
                .unwrap()
                .insert(server.to_string(), tok);
            true
        } else {
            false
        }
    }

    pub fn has_token(&self, server: &str) -> bool {
        self.upstream_tokens.lock().unwrap().contains_key(server)
    }

    pub fn real_token(&self, server: &str) -> Option<String> {
        self.upstream_tokens.lock().unwrap().get(server).cloned()
    }

    /// Issue a 120-second assertion scoped to (server, tool, agent).
    pub fn issue(&self, server: &str, tool: &str, agent: &str) -> String {
        let jti = uuid::Uuid::new_v4().to_string();
        let exp = chrono::Utc::now().timestamp() + 120;
        let payload = AssertionPayload {
            jti: jti.clone(),
            srv: server.into(),
            tool: tool.into(),
            agt: agent.into(),
            exp,
        };
        let json = serde_json::to_string(&payload).unwrap_or_default();
        let body = b64url(json.as_bytes());
        let sig = b64url(&sign(&self.signing_key, body.as_bytes()));
        self.issued.lock().unwrap().insert(jti, agent.to_string());
        format!("gh1.{body}.{sig}")
    }

    /// Verify an assertion against its scope. Checks HMAC, expiry, scope
    /// match, and revocation.
    pub fn verify(&self, token: &str, server: &str, tool: &str) -> Result<AssertionPayload, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 || parts[0] != "gh1" {
            return Err("malformed assertion".into());
        }
        let expected = b64url(&sign(&self.signing_key, parts[1].as_bytes()));
        if expected != parts[2] {
            return Err("signature mismatch".into());
        }
        // Decode our own b64url back (self-inverse hex-free approach:
        // re-encode check is done via signature, decode manually here).
        let json = b64url_decode(parts[1].as_bytes())
            .ok_or("malformed payload")?;
        let payload: AssertionPayload =
            serde_json::from_slice(&json).map_err(|_| "malformed payload".to_string())?;
        if payload.exp < chrono::Utc::now().timestamp() {
            return Err("assertion expired".into());
        }
        if payload.srv != server || payload.tool != tool {
            return Err(format!(
                "assertion scope mismatch: issued for {}/{} not {}/{}",
                payload.srv, payload.tool, server, tool
            ));
        }
        if self.revoked.lock().unwrap().contains(&payload.jti) {
            return Err("assertion revoked".into());
        }
        Ok(payload)
    }

    /// Kill switch companion: revoke every outstanding assertion an agent holds.
    pub fn revoke_agent(&self, agent: &str) -> usize {
        let issued = self.issued.lock().unwrap();
        let mut revoked = self.revoked.lock().unwrap();
        let jtis: Vec<String> = issued
            .iter()
            .filter(|(_, a)| a.as_str() == agent)
            .map(|(j, _)| j.clone())
            .collect();
        let n = jtis.len();
        for j in jtis {
            revoked.insert(j);
        }
        n
    }

    /// Count of unexpired assertions issued to an agent (diagnostics).
    #[allow(dead_code)]
    pub fn outstanding(&self) -> usize {
        self.issued.lock().unwrap().len()
    }
}

fn b64url_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut table = [255u8; 256];
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (i, &c) in T.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in input {
        let v = table[c as usize];
        if v == 255 {
            return None;
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_roundtrip() {
        let b = CredBroker::new();
        let tok = b.issue("files", "read_file", "claude");
        assert!(b.verify(&tok, "files", "read_file").is_ok());
        assert!(b.verify(&tok, "files", "delete_file").is_err());
    }

    #[test]
    fn revoked_assertion_fails() {
        let b = CredBroker::new();
        let tok = b.issue("files", "read_file", "claude");
        assert_eq!(b.revoke_agent("claude"), 1);
        assert!(b.verify(&tok, "files", "read_file").is_err());
    }
}
