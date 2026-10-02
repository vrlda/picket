//! Shared test helpers.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

/// One request through the router: (status, JSON body or Null). `body` is
/// sent raw as application/json.
pub async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    if body.is_some() {
        req = req.header("content-type", "application/json");
    }
    let body = body
        .map(|b| Body::from(b.to_string()))
        .unwrap_or_else(Body::empty);
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// GET with the test token; asserts 200 and returns the JSON.
pub async fn get_ok(app: &axum::Router, uri: &str) -> Value {
    let (status, body) = call(app, "GET", uri, Some("test-token"), None).await;
    assert_eq!(status, StatusCode::OK, "GET {uri}: {body}");
    body
}

/// POST JSON with the test token.
pub async fn post(app: &axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
    call(app, "POST", uri, Some("test-token"), Some(body)).await
}

/// A mock HTTP server answering every request with `status` and `body`;
/// returns its base URL and the raw requests it received (each fully read,
/// headers + body). It stops after `max` requests or when dropped by the
/// test process.
pub fn mock_http(
    status: u16,
    body: &'static str,
    max: usize,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for _ in 0..max {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let mut total = usize::MAX;
            while buf.len() < total {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    total = end + 4 + len;
                }
            }
            log2.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf).into_owned());
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    (format!("http://{addr}"), log)
}

/// Body of a raw HTTP request.
pub fn req_body(raw: &str) -> &str {
    raw.split("\r\n\r\n").nth(1).unwrap_or("")
}
