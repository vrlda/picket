use std::fs;
use std::io::Write;
use std::path::PathBuf;

use wt_common::{AgentEvent, Heartbeat};

/// Spool refuses to grow beyond this (10 MB) — drops new batches with a
/// loud log rather than filling the disk. MVP trade-off, documented.
pub const MAX_SPOOL_BYTES: u64 = 10 * 1024 * 1024;

/// JSONL spool: one event per line, appended on failure. Reads are
/// non-destructive; files are acked (deleted) only after delivery.
pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
}

/// One spool file's contents, read non-destructively.
pub struct SpoolFile {
    pub path: PathBuf,
    pub events: Vec<AgentEvent>,
}

/// Result of a drain pass.
#[derive(Debug, Default)]
pub struct DrainStats {
    pub delivered: usize,
    pub dropped: usize,
    pub deferred: usize,
}

impl Spool {
    pub fn new(dir: PathBuf) -> Self {
        fs::create_dir_all(&dir).ok();
        Spool {
            dir,
            max_bytes: MAX_SPOOL_BYTES,
        }
    }

    /// Spool with a custom size cap — tests use a tiny cap instead of
    /// writing 10 MB to hit the limit.
    #[cfg(test)]
    pub fn with_cap(dir: PathBuf, max_bytes: u64) -> Self {
        fs::create_dir_all(&dir).ok();
        Spool { dir, max_bytes }
    }

    pub fn append(&self, events: &[AgentEvent]) -> std::io::Result<()> {
        let mut payload = Vec::new();
        for ev in events {
            let line = serde_json::to_string(ev).map_err(std::io::Error::other)?;
            payload.extend_from_slice(line.as_bytes());
            payload.push(b'\n');
        }
        let current: u64 = fs::read_dir(&self.dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0);
        if current + payload.len() as u64 > self.max_bytes {
            return Err(std::io::Error::other(format!(
                "spool at max_bytes cap ({} bytes); dropping {} bytes",
                self.max_bytes,
                payload.len()
            )));
        }
        let path = self.dir.join(format!("spool-{}.jsonl", std::process::id()));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(&payload)
    }

    /// Read all spool files oldest-first WITHOUT deleting them. Unreadable
    /// files are skipped (fail-open); individual corrupt lines are skipped.
    /// Ordering is by file mtime then name — filename-only sorting would
    /// mis-order `spool-999` vs `spool-1000` across restarts.
    pub fn read_all(&self) -> Vec<SpoolFile> {
        let mut out = Vec::new();
        let mut entries: Vec<_> = match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| {
                    let modified = e.metadata().ok().and_then(|m| m.modified().ok());
                    (modified, e)
                })
                .collect(),
            Err(e) => {
                eprintln!("spool read_dir failed: {e}");
                Vec::new()
            }
        };
        entries.sort_by_key(|(modified, e)| (*modified, e.file_name()));
        for (_, entry) in entries {
            let text = match fs::read_to_string(entry.path()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("spool skip unreadable {}: {e}", entry.path().display());
                    continue;
                }
            };
            let mut events = Vec::new();
            for line in text.lines() {
                if let Ok(ev) = serde_json::from_str::<AgentEvent>(line) {
                    events.push(ev);
                }
            }
            out.push(SpoolFile {
                path: entry.path(),
                events,
            });
        }
        out
    }

    /// Delete a spool file — call ONLY after its events were delivered.
    pub fn ack(&self, path: &std::path::Path) {
        std::fs::remove_file(path).ok();
    }

    /// Number of spooled events (non-destructive).
    pub fn count(&self) -> usize {
        self.read_all().iter().map(|f| f.events.len()).sum()
    }

    /// Post all spooled files oldest-first, in chunks of at most
    /// CHUNK_SIZE events so no single request exceeds the server body cap.
    /// Ack what delivered; drop only permanent 4xx failures (bad payload);
    /// keep transport/5xx, 408/429 and auth (401/403) failures spooled and
    /// stop the drain. Auth failures are an operator-fixable misconfig
    /// (wrong or rotated token) — dropping on them would silently discard
    /// everything buffered during an outage the moment the token is wrong.
    pub fn drain(&self, url: &str, token: &str) -> DrainStats {
        const CHUNK_SIZE: usize = 512;
        let mut stats = DrainStats::default();
        for file in self.read_all() {
            let mut delivered_in_file = 0usize;
            let mut failed = None;
            for chunk in file.events.chunks(CHUNK_SIZE) {
                match post_batch(url, token, chunk) {
                    Ok(()) => {
                        delivered_in_file += chunk.len();
                    }
                    Err(e) => {
                        failed = Some(e);
                        break;
                    }
                }
            }
            match failed {
                None => {
                    stats.delivered += delivered_in_file;
                    self.ack(&file.path);
                }
                Some(PostError::HttpStatus(code))
                    if (400..500).contains(&code) && !matches!(code, 401 | 403 | 408 | 429) =>
                {
                    let remaining = file.events.len() - delivered_in_file;
                    eprintln!(
                        "permanent failure ({}): dropping {} of {} spooled events",
                        code,
                        remaining,
                        file.events.len()
                    );
                    self.ack(&file.path);
                    stats.delivered += delivered_in_file;
                    stats.dropped += remaining;
                }
                Some(e) => {
                    let remaining = file.events.len() - delivered_in_file;
                    eprintln!(
                        "drain deferred ({}): {} of {} events stay spooled",
                        e,
                        remaining,
                        file.events.len()
                    );
                    stats.delivered += delivered_in_file;
                    stats.deferred += remaining;
                    break;
                }
            }
        }
        stats
    }
}

/// Distinguishes retryable failures (transport, 5xx) from permanent ones
/// (4xx: bad token, bad payload — retrying is pointless).
#[derive(Debug)]
pub enum PostError {
    Transport(String),
    HttpStatus(u16),
}

impl std::fmt::Display for PostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PostError::Transport(msg) => write!(f, "transport: {msg}"),
            PostError::HttpStatus(code) => write!(f, "http {code}"),
        }
    }
}

pub fn post_batch(url: &str, token: &str, events: &[AgentEvent]) -> Result<(), PostError> {
    let body = serde_json::to_string(&serde_json::json!({ "batch": events }))
        .map_err(|e| PostError::Transport(e.to_string()))?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let resp = agent
        .post(&format!("{}/v1/telemetry", url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => PostError::HttpStatus(code),
            ureq::Error::Transport(t) => PostError::Transport(t.to_string()),
        })?;
    if !(200..300).contains(&resp.status()) {
        return Err(PostError::HttpStatus(resp.status()));
    }
    Ok(())
}

pub fn post_heartbeat(url: &str, token: &str, hb: &Heartbeat) -> Result<(), PostError> {
    let body = serde_json::to_string(hb).map_err(|e| PostError::Transport(e.to_string()))?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let resp = agent
        .post(&format!("{}/v1/heartbeat", url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => PostError::HttpStatus(code),
            ureq::Error::Transport(t) => PostError::Transport(t.to_string()),
        })?;
    if !(200..300).contains(&resp.status()) {
        return Err(PostError::HttpStatus(resp.status()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use wt_common::{AgentEvent, EventKind, Heartbeat, Severity};

    fn sample_event(ts: i64) -> AgentEvent {
        AgentEvent {
            id: format!("e-{}", ts),
            ts,
            host_id: "h-1".into(),
            key: "svc:nginx".into(),
            kind: EventKind::ServiceFailed.into(),
            severity: Severity::Critical,
            summary: "nginx failed".into(),
            evidence: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn spool_roundtrips_events_in_order() {
        let dir = std::env::temp_dir().join(format!("wt-spool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1), sample_event(2)]).unwrap();
        let files = spool.read_all();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].events.len(), 2);
        assert_eq!(files[0].events[0].ts, 1);
        assert_eq!(files[0].events[1].ts, 2);
        spool.ack(&files[0].path);
        assert!(spool.read_all().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn post_batch_sends_json_with_auth_header() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut req = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                    Err(_) => break, // read timeout: client finished sending
                }
            }
            let req = String::from_utf8_lossy(&req).into_owned();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
            req
        });
        let url = format!("http://{}", addr);
        post_batch(&url, "secret-token", &[sample_event(1)]).unwrap();
        let req = handle.join().unwrap();
        assert!(req.contains("Authorization: Bearer secret-token"));
        assert!(req.contains("\"kind\":\"ServiceFailed\""));
    }

    #[test]
    fn heartbeat_ships_minimal_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut req = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                    Err(_) => break, // read timeout: client finished sending
                }
            }
            let req = String::from_utf8_lossy(&req).into_owned();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
            req
        });
        let url = format!("http://{}", addr);
        let hb = Heartbeat {
            host_id: "h-1".into(),
            ts: 9,
            version: "0.1.0".into(),
            queue_len: 3,
        };
        post_heartbeat(&url, "secret-token", &hb).unwrap();
        let req = handle.join().unwrap();
        assert!(req.contains("\"queue_len\":3"));
    }

    #[test]
    fn post_batch_reports_http_status_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut req = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                    Err(_) => break, // read timeout: client finished sending
                }
            }
            stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        let url = format!("http://{}", addr);
        let err = post_batch(&url, "secret-token", &[sample_event(1)]).unwrap_err();
        assert!(matches!(err, PostError::HttpStatus(500)));
        handle.join().unwrap();
    }

    #[test]
    fn spool_read_does_not_delete_until_acked() {
        let dir = std::env::temp_dir().join(format!("wt-spool-2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(42)]).unwrap();
        assert_eq!(spool.read_all().len(), 1);
        assert_eq!(spool.count(), 1);
        spool.ack(&spool.read_all()[0].path);
        assert!(spool.read_all().is_empty());
        assert_eq!(spool.count(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spool_read_all_skips_unreadable_files() {
        let dir = std::env::temp_dir().join(format!("wt-spool-3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        std::fs::create_dir_all(dir.join("spool-bad.jsonl")).unwrap();
        spool.append(&[sample_event(7)]).unwrap();
        let files = spool.read_all();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].events[0].ts, 7);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn append_refuses_above_cap() {
        let dir = std::env::temp_dir().join(format!("wt-spool-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ev = sample_event(1);
        let ev_bytes = serde_json::to_string(&ev).unwrap().len() as u64 + 1;
        let cap = 3 * ev_bytes;
        let spool = Spool::with_cap(dir.clone(), cap);
        assert!(
            spool.append(std::slice::from_ref(&ev)).is_ok(),
            "first batch under cap must append"
        );
        assert_eq!(spool.count(), 1, "under-cap append must persist");
        for _ in 0..10 {
            if spool.append(std::slice::from_ref(&ev)).is_err() {
                break;
            }
        }
        let err = spool
            .append(std::slice::from_ref(&ev))
            .expect_err("append above cap must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("max_bytes cap"),
            "error must mention the cap, got: {msg}"
        );
        let spooled_bytes: u64 = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum();
        assert!(
            spooled_bytes <= cap + ev_bytes,
            "spool must stay near the cap, got {spooled_bytes} bytes"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_all_orders_by_mtime_not_filename() {
        let dir = std::env::temp_dir().join(format!("wt-spool-order-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        std::fs::write(dir.join("spool-999.jsonl"), "{\"old\":true}\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(dir.join("spool-1000.jsonl"), "{\"new\":true}\n").unwrap();
        let files = spool.read_all();
        assert_eq!(files.len(), 2);
        assert_eq!(
            files[0].path.file_name().unwrap().to_string_lossy(),
            "spool-999.jsonl",
            "older mtime sorts first despite lexically-larger name"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Spawn a mock server answering every request with the given status line.
    fn mock_server(status: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut req = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                    Err(_) => break, // read timeout: client finished sending
                }
            }
            let _ = String::from_utf8_lossy(&req).into_owned();
            stream
                .write_all(format!("{status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        (format!("http://{}", addr), handle)
    }

    fn drain_spool_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("wt-spool-drain-{name}-{}", std::process::id()))
    }

    #[test]
    fn drain_acks_on_success() {
        let (url, handle) = mock_server("HTTP/1.1 200 OK");
        let dir = drain_spool_dir("ok");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1)]).unwrap();
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.deferred, 0);
        assert!(spool.read_all().is_empty(), "delivered file must be acked");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drain_keeps_events_on_500() {
        let (url, handle) = mock_server("HTTP/1.1 500 Internal Server Error");
        let dir = drain_spool_dir("500");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1)]).unwrap();
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.deferred, 1);
        assert_eq!(spool.count(), 1, "5xx must stay spooled");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drain_keeps_spool_on_401() {
        let (url, handle) = mock_server("HTTP/1.1 401 Unauthorized");
        let dir = drain_spool_dir("401");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1)]).unwrap();
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.deferred, 1);
        assert_eq!(
            spool.count(),
            1,
            "auth failure keeps events for a token fix"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drain_drops_on_400() {
        let (url, handle) = mock_server("HTTP/1.1 400 Bad Request");
        let dir = drain_spool_dir("400");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1)]).unwrap();
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.dropped, 1);
        assert!(spool.read_all().is_empty(), "permanent 4xx must be acked");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drain_defers_on_429_rate_limit() {
        let (url, handle) = mock_server("HTTP/1.1 429 Too Many Requests");
        let dir = drain_spool_dir("429");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1)]).unwrap();
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.deferred, 1);
        assert_eq!(spool.count(), 1, "429 must stay spooled, not dropped");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drain_chunks_large_files() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reqs = requests.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                reqs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                    .unwrap();
                let mut req = Vec::new();
                loop {
                    let mut chunk = [0u8; 4096];
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => req.extend_from_slice(&chunk[..n]),
                        Err(_) => break, // read timeout: client finished sending
                    }
                }
                let _ = String::from_utf8_lossy(&req).into_owned();
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
                stream.shutdown(std::net::Shutdown::Write).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
        let dir = drain_spool_dir("chunks");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        let events: Vec<AgentEvent> = (0..1100).map(sample_event).collect();
        spool.append(&events).unwrap();
        let stats = spool.drain(&format!("http://{}", addr), "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 1100);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.deferred, 0);
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "1100 events must span 3 chunks (512+512+76), not one request"
        );
        assert!(spool.read_all().is_empty(), "delivered file must be acked");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drain_keeps_file_after_partial_chunk_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reqs = requests.clone();
        let handle = std::thread::spawn(move || {
            // request 1 → 200, request 2 → 500
            for _ in 0..2 {
                if let Ok((mut stream, _)) = listener.accept() {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                        .unwrap();
                    let mut req = Vec::new();
                    loop {
                        let mut chunk = [0u8; 4096];
                        match stream.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => req.extend_from_slice(&chunk[..n]),
                            Err(_) => break, // read timeout: client finished sending
                        }
                    }
                    let _ = String::from_utf8_lossy(&req).into_owned();
                    let n = reqs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let status = if n == 0 {
                        "HTTP/1.1 200 OK"
                    } else {
                        "HTTP/1.1 500 Internal Server Error"
                    };
                    let resp = format!("{status}\r\nContent-Length: 0\r\n\r\n");
                    stream.write_all(resp.as_bytes()).unwrap();
                    stream.shutdown(std::net::Shutdown::Write).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        });
        let dir = drain_spool_dir("partial");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        let events: Vec<AgentEvent> = (0..600).map(sample_event).collect();
        spool.append(&events).unwrap();
        let url = format!("http://{}", addr);
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 512);
        assert_eq!(stats.deferred, 88);
        assert_eq!(stats.dropped, 0);
        assert_eq!(
            spool.count(),
            600,
            "partial-delivery 5xx failure must keep the whole file spooled"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
