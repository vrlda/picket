//! Dedicated notification consumer: the correlation runner enqueues incident
//! JSON; this task delivers via the notify module and pushes failures to the
//! retry queue. Decouples webhook latency from the correlation scan loop.

use crate::app::AppState;
use crate::notify::NotifyConfig;

/// Bounded queue: on overflow the runner drops loudly (incidents remain in
/// the UI; notifications are best-effort under load).
pub const NOTIFY_QUEUE_CAP: usize = 64;

/// Consume incidents forever. `delivered` counts fully-delivered incidents
/// (test hook; production passes a dummy). `pool` persists a Telegram chat
/// discovered while sending (None in tests).
pub async fn notify_loop(
    mut rx: tokio::sync::mpsc::Receiver<serde_json::Value>,
    cfg: NotifyConfig,
    ui_base_url: String,
    queue: std::sync::Arc<std::sync::Mutex<crate::notify::RetryQueue>>,
    delivered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pool: Option<sqlx::AnyPool>,
) {
    while let Some(incident) = rx.recv().await {
        let failed = crate::notify::notify_incident(&cfg, &incident, &ui_base_url).await;
        if let (Some(pool), Some(client)) = (&pool, crate::notify::configured_telegram(&cfg)) {
            crate::notify::persist_telegram_chat(pool, client).await;
        }
        if failed.is_empty() {
            delivered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        for (url, payload) in failed {
            queue.lock().unwrap().push(url, payload);
        }
    }
}

pub fn spawn_notifier(state: AppState, rx: tokio::sync::mpsc::Receiver<serde_json::Value>) {
    let cfg = state.notify.clone();
    let ui = state.ui_base_url.clone();
    let queue = state.notify_queue.clone();
    let pool = state.pool.clone();
    tokio::spawn(async move {
        // NOT supervised: the channel is single-use; a supervised restart
        // could not re-bind the receiver. The loop exits only on shutdown.
        notify_loop(
            rx,
            cfg,
            ui,
            queue,
            std::sync::Arc::new(Default::default()),
            Some(pool),
        )
        .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn consumes_incidents_and_delivers() {
        let (tx, rx) = tokio::sync::mpsc::channel::<serde_json::Value>(64);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut buf = [0u8; 65536];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            let req = String::from_utf8_lossy(&buf).into_owned();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            req
        });
        let cfg = crate::notify::NotifyConfig {
            webhook_url: format!("http://{}", addr),
            slack_url: String::new(),
            telegram_token: None,
            telegram_chat_id: None,
            telegram_password: None,
            routing: std::collections::HashMap::from([
                ("Critical".into(), vec!["webhook".into()]),
                ("Warning".into(), vec!["webhook".into()]),
            ]),
        };
        let delivered = Arc::new(AtomicUsize::new(0));
        let d2 = delivered.clone();
        let task = tokio::spawn(async move {
            notify_loop(
                rx,
                cfg,
                "http://ui".to_string(),
                Arc::new(Default::default()),
                d2,
                None,
            )
            .await;
        });
        tx.send(serde_json::json!({
            "severity": "Critical",
            "headline": "myapp.service became unhealthy after a configuration change",
            "status": "open",
            "id": "inc-1",
        }))
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            1,
            "one incident delivered"
        );
        let req = handle.join().unwrap();
        assert!(req.contains("watchtower.incident"));
        task.abort();
    }

    #[tokio::test]
    async fn overflow_drops_loudly_and_keeps_going() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(2);
        tx.try_send(serde_json::json!({"id": "a"})).unwrap();
        tx.try_send(serde_json::json!({"id": "b"})).unwrap();
        assert!(
            tx.try_send(serde_json::json!({"id": "c"})).is_err(),
            "channel full → send fails (runner logs + drops)"
        );
        drop(tx);
        let mut got = Vec::new();
        while let Ok(v) = rx.try_recv() {
            got.push(v);
        }
        assert_eq!(got.len(), 2);
    }
}
