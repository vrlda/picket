//! Best-effort secret redaction for context handed to agents: tokens,
//! cookies, passwords, JWTs, private keys, URL credentials and payment card
//! numbers in event attributes, summaries and evidence.

use serde_json::Value;

pub const MASK: &str = "[REDACTED]";

/// Attribute names whose values are always masked (case-insensitive
/// substring match).
const SENSITIVE_KEYS: &[&str] = &[
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "private_key",
    "privatekey",
    "credential",
    "session",
    "card_number",
    "cardnumber",
    "pan",
    "cvv",
    "cvc",
    "database_url",
    "dsn",
    "signature",
];

pub fn is_sensitive_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|s| {
        if *s == "pan" {
            // whole-word only ("pan", "card_pan") — not "company"/"panel"
            k == "pan" || k.ends_with("_pan") || k.starts_with("pan_")
        } else {
            k.contains(s)
        }
    })
}

fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = (*d - b'0') as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// Mask card-number-looking digit runs (13–19 digits, spaces/dashes
/// allowed, Luhn-valid).
fn mask_cards(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let mut j = i;
            let mut digits = Vec::new();
            while j < bytes.len()
                && (bytes[j].is_ascii_digit()
                    || ((bytes[j] == b' ' || bytes[j] == b'-')
                        && j + 1 < bytes.len()
                        && bytes[j + 1].is_ascii_digit()))
            {
                if bytes[j].is_ascii_digit() {
                    digits.push(bytes[j]);
                }
                j += 1;
            }
            let boundary = j == bytes.len() || !bytes[j].is_ascii_alphanumeric();
            if boundary && (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
                out.push_str(MASK);
                i = j;
                continue;
            }
            out.push_str(&s[i..j]);
            i = j;
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Mask the token after `prefix` (case-insensitive), up to whitespace or a
/// quote.
fn mask_after(s: &str, prefix: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::new();
    let mut last = 0;
    let mut from = 0;
    while let Some(pos) = lower[from..].find(prefix) {
        let start = from + pos + prefix.len();
        let end = s[start..]
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',')
            .map(|e| start + e)
            .unwrap_or(s.len());
        if end > start {
            out.push_str(&s[last..start]);
            out.push_str(MASK);
            last = end;
        }
        from = end.max(start);
        if from >= s.len() {
            break;
        }
    }
    out.push_str(&s[last..]);
    out
}

/// Redact secrets inside free text.
pub fn redact_text(s: &str) -> String {
    let mut t = s.to_string();
    if t.contains("-----BEGIN") && t.contains("PRIVATE KEY-----") {
        return MASK.into();
    }
    for p in [
        "bearer ",
        "basic ",
        "token=",
        "password=",
        "api_key=",
        "apikey=",
        "secret=",
    ] {
        t = mask_after(&t, p);
    }
    // JWTs: three base64url segments starting with "eyJ"
    let mut out = String::new();
    for (i, word) in t.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let core = word
            .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.');
        if core.starts_with("eyJ") && core.matches('.').count() == 2 && core.len() > 20 {
            out.push_str(&word.replace(core, MASK));
        } else if let Some(at) = word.find('@').filter(|_| word.contains("://")) {
            // scheme://user:pass@host → scheme://[REDACTED]@host
            let scheme_end = word.find("://").unwrap() + 3;
            if scheme_end < at && word[scheme_end..at].contains(':') {
                out.push_str(&word[..scheme_end]);
                out.push_str(MASK);
                out.push_str(&word[at..]);
            } else {
                out.push_str(word);
            }
        } else {
            out.push_str(word);
        }
    }
    mask_cards(&out)
}

/// Redact a JSON value in place: sensitive keys masked wholesale, strings
/// scanned for secrets.
pub fn redact_value(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if is_sensitive_key(k) && !val.is_null() {
                    *val = Value::String(MASK.into());
                } else {
                    redact_value(val);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        Value::String(s) => *s = redact_text(s),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sensitive_keys_are_masked() {
        let mut v = json!({
            "merchant_id": "mer_1",
            "Authorization": "Bearer abc",
            "nested": { "db_password": "hunter2", "company": "Acme", "card_pan": "4111" },
            "headers": [{ "Cookie": "sid=1" }]
        });
        redact_value(&mut v);
        assert_eq!(v["merchant_id"], "mer_1");
        assert_eq!(v["Authorization"], MASK);
        assert_eq!(v["nested"]["db_password"], MASK);
        assert_eq!(v["nested"]["company"], "Acme");
        assert_eq!(v["nested"]["card_pan"], MASK);
        assert_eq!(v["headers"][0]["Cookie"], MASK);
    }

    #[test]
    fn secrets_in_text_are_masked() {
        let t = redact_text("auth failed: Bearer sk_live_123 for card 4111 1111 1111 1111 ok");
        assert!(!t.contains("sk_live_123"), "{t}");
        assert!(!t.contains("4111 1111 1111 1111"), "{t}");
        assert!(t.contains("auth failed"));
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVl";
        assert!(!redact_text(&format!("token {jwt} rejected")).contains(jwt));
        assert_eq!(
            redact_text("db postgres://app:s3cret@db:5432/x down"),
            "db postgres://[REDACTED]@db:5432/x down"
        );
        assert_eq!(
            redact_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"),
            MASK
        );
        // non-card numbers survive
        assert_eq!(
            redact_text("order 1234567890123 failed"),
            "order 1234567890123 failed"
        );
        assert_eq!(redact_text("status 500"), "status 500");
    }
}
