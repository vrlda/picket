use std::collections::HashMap;

use uuid::Uuid;
use wt_common::{AgentEvent, EventKind, Evidence, Severity};

use crate::app::AppState;

/// Watchdog episode state per host: per-episode emission tracking for
/// heartbeat-missing and queue-growth alerts.
#[derive(Default)]
pub struct WatchdogState {
    /// last_seen at which AgentHeartbeatMissing was emitted, per host. A
    /// fresh heartbeat advances last_seen and opens a new episode.
    missing_emitted: HashMap<String, i64>,
    /// Whether AgentQueueGrowing was emitted in the current queue episode,
    /// per host. Reset when the queue drops to/below the threshold.
    queue_emitted: HashMap<String, bool>,
}

/// Scan hosts for liveness + queue growth. Emits server-generated events
/// (they flow into the correlation engine like any other event).
pub async fn watchdog_scan(state: &AppState, now: i64) -> Result<Vec<AgentEvent>, sqlx::Error> {
    let mut evs = Vec::new();
    let grace = state.cfg.watchdog_heartbeat_grace_secs.max(1) * 1000;
    let queue_threshold = state.cfg.watchdog_queue_threshold;
    let hosts =
        sqlx::query_as::<_, (String, i64, i64)>("SELECT host_id, last_seen, queue_len FROM hosts")
            .fetch_all(&state.pool)
            .await?;
    let mut tracker = state.watchdog.lock().unwrap();
    for (host_id, last_seen, queue_len) in hosts {
        let missing = now - last_seen > grace;
        if missing {
            let emitted_at = tracker
                .missing_emitted
                .entry(host_id.clone())
                .or_insert(i64::MIN);
            if *emitted_at != last_seen {
                *emitted_at = last_seen;
                evs.push(AgentEvent {
                    id: Uuid::new_v4().to_string(),
                    ts: now,
                    host_id: host_id.clone(),
                    key: format!("heartbeat:{}", host_id),
                    kind: EventKind::AgentHeartbeatMissing.into(),
                    severity: Severity::Critical,
                    summary: format!(
                        "{} stopped reporting (last heartbeat {}s ago)",
                        host_id,
                        (now - last_seen) / 1000
                    ),
                    evidence: vec![Evidence {
                        ts: now,
                        source: "watchdog".into(),
                        detail: format!("LastSeen={} GraceSecs={}", last_seen, grace / 1000),
                    }],
                    ..Default::default()
                });
            }
        } else {
            // host is reporting again — the episode is over
            tracker.missing_emitted.remove(&host_id);
        }
        let q_emitted = tracker
            .queue_emitted
            .entry(host_id.clone())
            .or_insert(false);
        if queue_len > queue_threshold && !*q_emitted {
            *q_emitted = true;
            evs.push(AgentEvent {
                id: Uuid::new_v4().to_string(),
                ts: now,
                host_id: host_id.clone(),
                key: format!("queue:{}", host_id),
                kind: EventKind::AgentQueueGrowing.into(),
                severity: Severity::Warning,
                summary: format!(
                    "{} telemetry queue is growing ({} events)",
                    host_id, queue_len
                ),
                evidence: vec![Evidence {
                    ts: now,
                    source: "watchdog".into(),
                    detail: format!("QueueLen={} Threshold={}", queue_len, queue_threshold),
                }],
                ..Default::default()
            });
        } else if queue_len <= queue_threshold {
            // queue recovered — the episode is over
            *q_emitted = false;
        }
    }
    Ok(evs)
}

/// Spawn the watchdog loop.
pub fn spawn_watchdog(state: AppState) {
    tokio::spawn(crate::supervise::spawn_supervised("watchdog", move || {
        watchdog_loop(state.clone())
    }));
}

async fn watchdog_loop(state: AppState) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let now = crate::ingest::now_ms();
        match watchdog_scan(&state, now).await {
            Ok(evs) => {
                for ev in &evs {
                    let _ =
                        crate::ingest::store_events(&state.pool, std::slice::from_ref(ev)).await;
                    eprintln!("watchdog: {}", ev.summary);
                }
            }
            Err(e) => eprintln!("watchdog scan failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::app::AppState;
    use crate::hosts::upsert_host;
    use wt_common::{EventKind, Severity};

    use super::watchdog_scan;

    #[tokio::test]
    async fn missing_heartbeat_emits_event_once_per_episode() {
        let state = AppState::for_tests().await;
        let grace = state.cfg.watchdog_heartbeat_grace_secs.max(1) * 1000;
        let hb = wt_common::Heartbeat {
            host_id: "h-1".into(),
            ts: crate::ingest::now_ms(),
            version: "0.1".into(),
            queue_len: 0,
        };
        upsert_host(&state.pool, &hb).await.unwrap();
        let now = crate::ingest::now_ms();
        let evs = watchdog_scan(&state, now + grace + 1000).await.unwrap();
        assert_eq!(evs.len(), 1);
        let ev = &evs[0];
        assert_eq!(ev.kind, EventKind::AgentHeartbeatMissing);
        assert_eq!(ev.severity, Severity::Critical);
        assert_eq!(ev.host_id, "h-1");
        // second scan: same episode, no new event
        let evs = watchdog_scan(&state, now + grace + 2000).await.unwrap();
        assert!(evs.is_empty());
        // heartbeat arrives → episode resets → next miss re-emits.
        // last_seen is server now_ms with millisecond granularity; if the
        // recovery upsert lands in the same ms as the first upsert, last_seen
        // is unchanged and the re-emit is suppressed. Sleep to force distinct ms.
        let (_, ls_before, _): (String, i64, i64) = sqlx::query_as::<_, (String, i64, i64)>(
            "SELECT host_id, last_seen, queue_len FROM hosts WHERE host_id = 'h-1'",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        upsert_host(&state.pool, &hb).await.unwrap();
        let (_, ls_after, _): (String, i64, i64) = sqlx::query_as::<_, (String, i64, i64)>(
            "SELECT host_id, last_seen, queue_len FROM hosts WHERE host_id = 'h-1'",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert!(
            ls_after > ls_before,
            "recovery upsert must advance last_seen"
        );
        let now2 = crate::ingest::now_ms();
        let evs = watchdog_scan(&state, now2 + grace + 1000).await.unwrap();
        assert_eq!(evs.len(), 1, "new episode after recovery re-emits");
    }

    #[tokio::test]
    async fn growing_queue_emits_throttled_warning() {
        let state = AppState::for_tests().await;
        let hb = wt_common::Heartbeat {
            host_id: "h-1".into(),
            ts: crate::ingest::now_ms(),
            version: "0.1".into(),
            queue_len: 150,
        };
        upsert_host(&state.pool, &hb).await.unwrap();
        let now = crate::ingest::now_ms();
        let evs = watchdog_scan(&state, now).await.unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, EventKind::AgentQueueGrowing);
        assert_eq!(evs[0].severity, Severity::Warning);
        // still above threshold → same episode → no re-emission
        let evs = watchdog_scan(&state, now + 1000).await.unwrap();
        assert!(
            evs.is_empty(),
            "one event per queue episode while above threshold"
        );
        // queue drains below threshold → episode resets, nothing to emit
        let hb = wt_common::Heartbeat {
            host_id: "h-1".into(),
            ts: crate::ingest::now_ms(),
            version: "0.1".into(),
            queue_len: 10,
        };
        upsert_host(&state.pool, &hb).await.unwrap();
        let now = crate::ingest::now_ms();
        let evs = watchdog_scan(&state, now).await.unwrap();
        assert!(evs.is_empty(), "below threshold: no event");
        // queue grows again → NEW episode → re-emits once
        let hb = wt_common::Heartbeat {
            host_id: "h-1".into(),
            ts: crate::ingest::now_ms(),
            version: "0.1".into(),
            queue_len: 150,
        };
        upsert_host(&state.pool, &hb).await.unwrap();
        let now = crate::ingest::now_ms();
        let evs = watchdog_scan(&state, now).await.unwrap();
        assert_eq!(
            evs.len(),
            1,
            "queue above threshold again re-emits (new episode)"
        );
    }
}
