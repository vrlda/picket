//! Minimal picket SDK. Apps call [`Client::capture`] with an
//! exception (type, message, level, stack frames; the server fingerprints
//! and groups them) or [`Client::capture_event`] with a custom
//! application/business event ("payment.request_failed") that rules turn
//! into incidents. Blocking, no async, no external services beyond the
//! picket server.

use std::time::Duration;

/// PICKET_<name>, falling back to the pre-rename WATCHTOWER_<name>.
fn env(name: &str) -> Option<String> {
    std::env::var(format!("PICKET_{name}"))
        .or_else(|_| std::env::var(format!("WATCHTOWER_{name}")))
        .ok()
}

/// SDK configuration. All fields have env defaults (the PICKET_* family).
#[derive(Debug, Clone)]
pub struct Client {
    pub endpoint: String,
    pub token: String,
    pub host_id: String,
    pub service: String,
    pub environment: String,
}

impl Client {
    /// Build from the PICKET_ENDPOINT / PICKET_TOKEN /
    /// PICKET_HOST_ID / PICKET_SERVICE / PICKET_ENVIRONMENT
    /// env vars (host_id defaults to the OS hostname, service to "app",
    /// environment to "prod"). The pre-rename WATCHTOWER_* names are still
    /// read as a fallback.
    pub fn from_env() -> Option<Client> {
        let endpoint = env("ENDPOINT")?;
        let token = env("TOKEN")?;
        let host_id = env("HOST_ID")
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "host".into());
        let service = env("SERVICE").unwrap_or_else(|| "app".into());
        let environment = env("ENVIRONMENT").unwrap_or_else(|| "prod".into());
        Some(Client {
            endpoint,
            token,
            host_id,
            service,
            environment,
        })
    }

    /// Report an exception. Frames: (file, line, function) — innermost
    /// first. Best-effort with one retry; never panics.
    pub fn capture(
        &self,
        level: &str,
        kind: &str,
        message: &str,
        frames: &[(String, u32, String)],
    ) -> bool {
        let body = serde_json::json!({
            "host_id": self.host_id,
            "service": self.service,
            "environment": self.environment,
            "exception": {
                "type": kind,
                "message": message,
                "level": level,
                "frames": frames.iter().map(|(file, line, function)| serde_json::json!({
                    "file": file, "line": line, "function": function
                })).collect::<Vec<_>>(),
            }
        });
        self.post("/v1/errors", &body)
    }

    /// Report a custom event (POST /v1/events). `event` needs at least
    /// `kind` (dotted, e.g. "payment.request_failed") and `summary`;
    /// `source`/`environment` default to the client's service and
    /// environment. Best-effort with one retry; never panics.
    ///
    /// ```no_run
    /// # let client = picket_sdk::Client::from_env().unwrap();
    /// client.capture_event(serde_json::json!({
    ///     "kind": "payment.request_failed",
    ///     "summary": "Payment request failed",
    ///     "severity": "warning",
    ///     "subject": "merchant:mer_1",
    ///     "attributes": { "merchant_id": "mer_1", "status_code": 502 },
    ///     "measurements": { "latency_ms": 812 }
    /// }));
    /// ```
    pub fn capture_event(&self, mut event: serde_json::Value) -> bool {
        let Some(obj) = event.as_object_mut() else {
            return false;
        };
        obj.entry("source")
            .or_insert_with(|| self.service.clone().into());
        obj.entry("environment")
            .or_insert_with(|| self.environment.clone().into());
        self.post("/v1/events", &event)
    }

    fn post(&self, path: &str, body: &serde_json::Value) -> bool {
        let url = format!("{}{}", self.endpoint.trim_end_matches('/'), path);
        for attempt in 0..2 {
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build();
            let res = agent
                .post(&url)
                .set("Content-Type", "application/json")
                .set("Authorization", &format!("Bearer {}", self.token))
                .send_string(&body.to_string());
            match res {
                Ok(r) if (200..300).contains(&r.status()) => return true,
                // rejected (invalid event / auth): retrying won't help
                Err(ureq::Error::Status(code, _)) if (400..500).contains(&code) => return false,
                _ => {
                    if attempt == 0 {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        }
        false
    }

    /// Convenience for panics: capture a formatted panic message
    /// (type "Panic", level "fatal").
    pub fn capture_panic(&self, message: &str) -> bool {
        self.capture("fatal", "Panic", message, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn env_falls_back_to_pre_rename_names() {
        // the only test touching these variables
        std::env::set_var("WATCHTOWER_ENDPOINT", "http://old");
        std::env::set_var("WATCHTOWER_TOKEN", "old-token");
        std::env::set_var("PICKET_TOKEN", "new-token");
        let c = Client::from_env().unwrap();
        assert_eq!(c.endpoint, "http://old");
        assert_eq!(c.token, "new-token", "the new name wins");
        for k in ["WATCHTOWER_ENDPOINT", "WATCHTOWER_TOKEN", "PICKET_TOKEN"] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn capture_posts_expected_payload() {
        let (url, handle) = mock();
        let client = Client {
            endpoint: url,
            token: "tok".into(),
            host_id: "h-1".into(),
            service: "api".into(),
            environment: "prod".into(),
        };
        let frames = [("app.rs".into(), 42, "validate".into())];
        assert!(client.capture("error", "ValueError", "bad input", &frames));
        let req = handle.join().unwrap();
        assert!(req.starts_with("POST /v1/errors HTTP/1.1"), "{req}");
        assert!(req.contains("Authorization: Bearer tok"), "auth header");
        let body: serde_json::Value =
            serde_json::from_str(&req[req.find("\r\n\r\n").unwrap() + 4..]).unwrap();
        assert_eq!(body["host_id"], "h-1");
        assert_eq!(body["service"], "api");
        assert_eq!(body["exception"]["type"], "ValueError");
        assert_eq!(body["exception"]["level"], "error");
        assert_eq!(body["exception"]["frames"][0]["file"], "app.rs");
        assert_eq!(body["exception"]["frames"][0]["line"], 42);
    }

    #[test]
    fn capture_retries_once_then_returns_false() {
        let client = Client {
            endpoint: "http://127.0.0.1:1".into(),
            token: "t".into(),
            host_id: "h".into(),
            service: "s".into(),
            environment: "e".into(),
        };
        assert!(!client.capture("error", "T", "m", &[]));
    }

    /// One-request mock server: returns (base url, handle → raw request).
    fn mock() -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(end) = text.find("\r\n\r\n") {
                    let len = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().to_string())
                        })
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    if end + 4 + len <= buf.len() {
                        break;
                    }
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            String::from_utf8_lossy(&buf).to_string()
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn capture_event_posts_custom_event() {
        let (url, handle) = mock();
        let client = Client {
            endpoint: url,
            token: "tok".into(),
            host_id: "h".into(),
            service: "payment-api".into(),
            environment: "production".into(),
        };
        assert!(client.capture_event(serde_json::json!({
            "kind": "payment.request_failed",
            "summary": "failed",
            "attributes": { "merchant_id": "mer_1" }
        })));
        let req = handle.join().unwrap();
        assert!(req.starts_with("POST /v1/events"), "{req}");
        let body: serde_json::Value =
            serde_json::from_str(&req[req.find("\r\n\r\n").unwrap() + 4..]).unwrap();
        assert_eq!(body["kind"], "payment.request_failed");
        assert_eq!(body["source"], "payment-api");
        assert_eq!(body["environment"], "production");
        assert_eq!(body["attributes"]["merchant_id"], "mer_1");
        assert!(!client.capture_event(serde_json::json!("not an object")));
    }
}
