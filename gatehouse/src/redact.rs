use once_cell_sync::Lazy;
use regex::Regex;

/// Redaction applied to request params and tool responses BEFORE anything is
/// logged, stored, or streamed to the console (LLM06, also feeds ASI06).
/// The audit trail holds masked values, never live secrets.

mod once_cell_sync {
    pub use std::sync::LazyLock as Lazy;
}

static EMAIL: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap());
static OPENAI: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bsk-[A-Za-z0-9_-]{20,}\b").unwrap());
static AWS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap());
static GITHUB: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b").unwrap());
static SLACK: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").unwrap());
static GOOGLE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap());
static JWT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{5,}\b").unwrap());
static PRIVKEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----[^\x00]*?-----END [^\x00]*?-----").unwrap());
static ENTROPY: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Za-z0-9_-]{28,}\b").unwrap());
static CARD: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d[ -]?){13,16}\b").unwrap());
static SSN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

fn mask(value: &str, keep: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= keep {
        return "●".repeat(chars.len());
    }
    let head: String = chars.iter().take(3).collect();
    let tail_start = chars.len().saturating_sub(keep);
    let tail: String = chars[tail_start..].iter().collect();
    format!("{head}●●●●●●{tail}")
}

fn looks_like_key(s: &str) -> bool {
    // High entropy + mixed classes ⇒ treat as a credential-shaped blob.
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    (has_digit && has_upper && has_lower) || entropy(s) > 4.2
}

fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn luhn_ok(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).map(|c| c as u32 - '0' as u32).collect();
    if digits.len() < 13 || digits.len() > 16 {
        return false;
    }
    let mut sum = 0u32;
    let mut dbl = false;
    for &d in digits.iter().rev() {
        let mut d = d;
        if dbl {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        dbl = !dbl;
    }
    sum % 10 == 0
}

/// Redact one string; returns (redacted, number of redactions made).
pub fn redact_text(input: &str) -> (String, usize) {
    let mut count = 0usize;
    let mut s = input.to_string();

    for re in [&PRIVKEY, &OPENAI, &AWS, &GITHUB, &SLACK, &GOOGLE, &JWT] {
        let hits: Vec<String> = re.find_iter(&s).map(|m| m.as_str().to_string()).collect();
        for h in hits {
            let replacement = if h.starts_with("-----BEGIN") {
                "[private-key]".to_string()
            } else {
                mask(&h, 4)
            };
            s = s.replace(&h, &replacement);
            count += 1;
        }
    }

    // Entropy scan for unformatted credential blobs.
    let blobs: Vec<String> = ENTROPY
        .find_iter(&s)
        .map(|m| m.as_str().to_string())
        .filter(|b| looks_like_key(b) && !EMAIL.is_match(b))
        .collect();
    for b in blobs {
        s = s.replace(&b, &mask(&b, 3));
        count += 1;
    }

    let emails: Vec<String> = EMAIL.find_iter(&s).map(|m| m.as_str().to_string()).collect();
    for e in emails {
        let masked = {
            let (user, domain) = e.split_once('@').unwrap_or((e.as_str(), ""));
            let prefix: String = user.chars().take(3).collect();
            let dm = domain
                .split('.')
                .next()
                .map(|d| format!("{}***", &d[..d.len().min(2)]))
                .unwrap_or_default();
            format!("{prefix}…@{dm}")
        };
        s = s.replace(&e, &masked);
        count += 1;
    }

    let cards: Vec<String> = CARD
        .find_iter(&s)
        .map(|m| m.as_str().to_string())
        .filter(|c| luhn_ok(c))
        .collect();
    for c in cards {
        s = s.replace(&c, "****-****-****-LAST4");
        count += 1;
    }

    let ssns: Vec<String> = SSN.find_iter(&s).map(|m| m.as_str().to_string()).collect();
    for n in ssns {
        s = s.replace(&n, "***-**-****");
        count += 1;
    }

    (s, count)
}

/// Redact every string leaf of a JSON value in place. Returns the count.
pub fn redact_json(v: &mut serde_json::Value) -> usize {
    use serde_json::Value;
    let mut n = 0;
    match v {
        Value::String(s) => {
            let (redacted, c) = redact_text(s);
            if c > 0 {
                *s = redacted;
                n += c;
            }
        }
        Value::Array(items) => {
            for it in items.iter_mut() {
                n += redact_json(it);
            }
        }
        Value::Object(map) => {
            for (_k, val) in map.iter_mut() {
                n += redact_json(val);
            }
        }
        _ => {}
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_openai_style_key() {
        let (out, n) = redact_text("key=sk-abcdefghij1234567890abcdEFGH end");
        assert_eq!(n, 1);
        assert!(!out.contains("sk-abcdefghij1234567890abcdEFGH"));
        assert!(out.contains("●●●"));
    }

    #[test]
    fn masks_luhn_card_only() {
        let (out, n) = redact_text("pay with 4111 1111 1111 1111 please");
        assert_eq!(n, 1);
        assert!(out.contains("****"));
        // 1234 5678 9012 3456 fails Luhn — must stay.
        let (out2, n2) = redact_text("ref 1234 5678 9012 3456 only");
        assert_eq!(n2, 0);
        assert!(out2.contains("1234 5678 9012 3456"));
    }

    #[test]
    fn masks_private_key_block() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ\n-----END RSA PRIVATE KEY-----";
        let (out, n) = redact_text(pem);
        assert_eq!(n, 1);
        assert!(out.contains("[private-key]"));
    }

    #[test]
    fn normal_text_untouched() {
        let (out, n) = redact_text("ship the order to the warehouse by Friday");
        assert_eq!(n, 0);
        assert_eq!(out, "ship the order to the warehouse by Friday");
    }
}
