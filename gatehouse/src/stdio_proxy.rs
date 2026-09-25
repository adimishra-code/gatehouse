use serde_json::Value;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

/// Transport for MCP servers that speak JSON-RPC over stdio — the dominant
/// form today. The gateway spawns the server as a child process, multiplexes
/// request ids over its stdin/stdout, and fails pending calls fast if the
/// process dies. One transport per configured stdio server, reused by all
/// agents; the agent just talks HTTP to the gatehouse.
#[derive(Clone)]
pub struct StdioTransport {
    inner: Arc<Inner>,
}

struct Inner {
    tx: mpsc::Sender<String>,
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
}

impl StdioTransport {
    pub fn spawn(command: &str, args: &[String]) -> Result<StdioTransport, String> {
        let mut child = tokio::process::Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot spawn '{command}': {e}"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "child stdin unavailable".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "child stdout unavailable".to_string())?;

        // Writer: everything agents send goes out as one JSON line.
        let (tx, mut rx) = mpsc::channel::<String>(256);
        tokio::spawn(async move {
            let mut stdin = stdin;
            while let Some(line) = rx.recv().await {
                if stdin.write_all(line.as_bytes()).await.is_err()
                    || stdin.write_all(b"\n").await.is_err()
                {
                    break;
                }
                let _ = stdin.flush().await;
            }
        });

        let transport = StdioTransport {
            inner: Arc::new(Inner {
                tx,
                pending: Mutex::new(HashMap::new()),
            }),
        };

        // Reader: route each response line to whoever owns its id.
        let pending_ref = Arc::clone(&transport.inner);
        tokio::spawn(async move {
            let mut child = child;
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            loop {
                tokio::select! {
                    line = lines.next_line() => {
                        match line {
                            Ok(Some(l)) => {
                                if let Ok(v) = serde_json::from_str::<Value>(&l) {
                                    let id = v.get("id").map(id_key).unwrap_or_default();
                                    if let Some(tx) = pending_ref.pending.lock().unwrap().remove(&id) {
                                        let _ = tx.send(v);
                                    }
                                }
                            }
                            _ => break,
                        }
                    }
                    _ = child.wait() => break,
                }
            }
            // Process is gone: fail everything waiting on it.
            let mut map = pending_ref.pending.lock().unwrap();
            for (_, tx) in map.drain() {
                let _ = tx.send(serde_json::json!({
                    "error": { "code": -32001, "message": "stdio MCP server exited" }
                }));
            }
        });

        Ok(transport)
    }

    /// Send one JSON-RPC request and await its matching response (60s cap).
    pub async fn request(&self, rpc: Value) -> Result<Value, String> {
        let id = rpc
            .get("id")
            .map(id_key)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let (tx, rx) = oneshot::channel::<Value>();
        self.inner.pending.lock().unwrap().insert(id.clone(), tx);
        let line = serde_json::to_string(&rpc).map_err(|e| e.to_string())?;
        self.inner
            .tx
            .send(line)
            .await
            .map_err(|_| "stdio writer closed".to_string())?;
        match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(_)) => Err("response channel dropped".into()),
            Err(_) => {
                self.inner.pending.lock().unwrap().remove(&id);
                Err("stdio server did not answer within 60s".into())
            }
        }
    }
}

fn id_key(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
