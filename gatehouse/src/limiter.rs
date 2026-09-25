use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::config::Config;

/// Per-agent token-bucket-ish limiting + spend ceiling with automatic
/// circuit breaking (ASI08 cascading failures). Single-process for the MVP
/// with an interface shaped so the counters can move to Redis INCR/EXPIRE
/// for multi-replica deployments without changing call sites.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitStatus {
    pub allowed: bool,
    pub reason: Option<String>,
    pub calls_this_minute: u64,
    pub est_spend_usd: f64,
    pub circuit_tripped: bool,
    pub circuit_resets_in_secs: Option<u64>,
}

#[derive(Debug)]
struct Budget {
    minute_bucket: u64,
    calls_this_minute: u64,
    day_bucket: u64,
    est_spend_usd: f64,
    tripped_until: Option<Instant>,
}

pub struct Limiter {
    map: Mutex<HashMap<String, Budget>>,
}

fn minute_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0)
}

fn day_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

impl Limiter {
    pub fn new() -> Limiter {
        Limiter { map: Mutex::new(HashMap::new()) }
    }

    pub fn check(&self, agent: &str, cfg: &Config) -> LimitStatus {
        let mut map = self.map.lock().unwrap();
        let b = map.entry(agent.to_string()).or_insert(Budget {
            minute_bucket: 0,
            calls_this_minute: 0,
            day_bucket: 0,
            est_spend_usd: 0.0,
            tripped_until: None,
        });

        let m = minute_now();
        if b.minute_bucket != m {
            b.minute_bucket = m;
            b.calls_this_minute = 0;
        }
        let d = day_now();
        if b.day_bucket != d {
            b.day_bucket = d;
            b.est_spend_usd = 0.0;
        }

        if let Some(until) = b.tripped_until {
            if Instant::now() < until {
                return LimitStatus {
                    allowed: false,
                    reason: Some(format!(
                        "circuit breaker open after spend ceiling breach — resets in {}s",
                        (until - Instant::now()).as_secs()
                    )),
                    calls_this_minute: b.calls_this_minute,
                    est_spend_usd: b.est_spend_usd,
                    circuit_tripped: true,
                    circuit_resets_in_secs: Some((until - Instant::now()).as_secs()),
                };
            }
            b.tripped_until = None;
        }

        if b.calls_this_minute >= cfg.max_calls_per_min {
            return LimitStatus {
                allowed: false,
                reason: Some(format!(
                    "rate limit: {} calls/min exceeded for agent '{agent}'",
                    cfg.max_calls_per_min
                )),
                calls_this_minute: b.calls_this_minute,
                est_spend_usd: b.est_spend_usd,
                circuit_tripped: false,
                circuit_resets_in_secs: None,
            };
        }
        if b.est_spend_usd >= cfg.spend_limit_usd {
            b.tripped_until = Some(Instant::now() + std::time::Duration::from_secs(60));
            return LimitStatus {
                allowed: false,
                reason: Some(format!(
                    "spend ceiling ${:.2} reached for agent '{agent}' — circuit open 60s",
                    cfg.spend_limit_usd
                )),
                calls_this_minute: b.calls_this_minute,
                est_spend_usd: b.est_spend_usd,
                circuit_tripped: true,
                circuit_resets_in_secs: Some(60),
            };
        }

        b.calls_this_minute += 1;
        b.est_spend_usd += cfg.cost_per_call;
        LimitStatus {
            allowed: true,
            reason: None,
            calls_this_minute: b.calls_this_minute,
            est_spend_usd: b.est_spend_usd,
            circuit_tripped: false,
            circuit_resets_in_secs: None,
        }
    }

    /// Display-only snapshot for the console; returns agent keys with
    /// neutral statuses until the Redis-backed counters land.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<(String, LimitStatus)> {
        // Snapshot with a neutral Config so numbers are display-only.
        let map = self.map.lock().unwrap();
        map.keys()
            .map(|k| {
                (
                    k.clone(),
                    LimitStatus {
                        allowed: true,
                        reason: None,
                        calls_this_minute: 0,
                        est_spend_usd: 0.0,
                        circuit_tripped: false,
                        circuit_resets_in_secs: None,
                    },
                )
            })
            .collect()
    }
}
