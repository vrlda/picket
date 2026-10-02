use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use uuid::Uuid;
use wt_common::{AgentEvent, EventKind, Evidence, Severity};

use crate::app::AppState;

/// One external HTTP(S) endpoint to probe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ProbeConfig {
    pub url: String,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    /// Consecutive failures that trigger one HostUnreachable event.
    pub fail_threshold: u32,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            url: String::new(),
            interval_secs: 30,
            timeout_secs: 10,
            fail_threshold: 3,
        }
    }
}

/// GET the URL; true iff a 2xx response arrived within the timeout.
pub fn probe_once(url: &str, timeout_secs: u64) -> bool {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .build();
    match agent.get(url).call() {
        Ok(resp) => (200..300).contains(&resp.status()),
        Err(ureq::Error::Status(code, _)) => (200..300).contains(&code),
        Err(_) => false,
    }
}

/// Consecutive-failure episode state per probe URL.
#[derive(Clone, Default)]
pub struct EpisodeTracker {
    fails: u32,
}

impl EpisodeTracker {
    /// Observe one probe result. Returns true when this failure completes an
    /// episode (consecutive fails == threshold) — the caller emits the event.
    /// A success resets the counter.
    pub fn observe(&mut self, ok: bool, threshold: u32) -> bool {
        if ok {
            self.fails = 0;
            return false;
        }
        self.fails += 1;
        if self.fails >= threshold {
            self.fails = 0;
            true
        } else {
            false
        }
    }

    pub fn fails(&self) -> u32 {
        self.fails
    }
}

/// Shared checker state across probe tasks.
#[derive(Clone, Default)]
pub struct Checker {
    pub trackers: Arc<Mutex<HashMap<String, EpisodeTracker>>>,
}

impl Checker {
    pub fn new() -> Self {
        Checker {
            trackers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// One probe tick: probe, update episode state, emit HostUnreachable when
    /// an episode completes.
    pub async fn tick(&self, probe: &ProbeConfig, now: i64) -> Option<AgentEvent> {
        let url = probe.url.clone();
        let timeout = probe.timeout_secs;
        let ok = tokio::task::spawn_blocking(move || probe_once(&url, timeout))
            .await
            .unwrap_or(false);
        let mut trackers = self.trackers.lock().unwrap();
        let ep = trackers.entry(probe.url.clone()).or_default();
        if ep.observe(ok, probe.fail_threshold) {
            let id = Uuid::new_v4().to_string();
            Some(AgentEvent {
                id,
                ts: now,
                host_id: "uptime".into(),
                key: format!("uptime:{}", probe.url),
                kind: EventKind::HostUnreachable.into(),
                severity: Severity::Critical,
                summary: format!(
                    "{} unreachable after {} consecutive probe failures",
                    probe.url, probe.fail_threshold
                ),
                evidence: vec![Evidence {
                    ts: now,
                    source: "uptime".into(),
                    detail: format!(
                        "ProbeUrl={} FailThreshold={}",
                        probe.url, probe.fail_threshold
                    ),
                }],
                ..Default::default()
            })
        } else {
            None
        }
    }

    /// Run one tick for every configured probe.
    pub async fn tick_all(&self, probes: &[ProbeConfig], now: i64) -> Vec<AgentEvent> {
        let mut evs = Vec::new();
        for p in probes {
            if !p.url.is_empty() {
                if let Some(ev) = self.tick(p, now).await {
                    evs.push(ev);
                }
            }
        }
        evs
    }
}

/// Persist server-generated events (HostUnreachable) into the store.
pub async fn store_probe_events(pool: &sqlx::AnyPool, events: &[AgentEvent]) {
    for ev in events {
        if let Err(e) = crate::ingest::store_events(pool, std::slice::from_ref(ev)).await {
            eprintln!("probe store failed: {e}");
        }
    }
}

/// Spawn one supervised background task per probe. The first tick is skipped
/// (interval's immediate first tick) so probes don't all fire at startup.
pub fn spawn_probe_tasks(state: AppState, probes: Vec<ProbeConfig>) {
    for probe in probes {
        if probe.url.is_empty() {
            continue;
        }
        let state = state.clone();
        let url = probe.url.clone();
        tokio::spawn(crate::supervise::spawn_supervised("probe", move || {
            probe_loop(state.clone(), probe.clone())
        }));
        eprintln!("probe task started: {}", url);
    }
}

async fn probe_loop(state: AppState, probe: ProbeConfig) {
    let mut interval = tokio::time::interval(Duration::from_secs(probe.interval_secs.max(1)));
    interval.tick().await; // first tick fires immediately; skip it
    loop {
        interval.tick().await;
        let evs = state
            .checker
            .tick_all(std::slice::from_ref(&probe), crate::ingest::now_ms())
            .await;
        store_probe_events(&state.pool, &evs).await;
        for ev in &evs {
            eprintln!("probe: {}", ev.summary);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn probe_once_true_on_2xx_false_on_5xx() {
        let (ok, _) = crate::test_util::mock_http(200, "", 1);
        assert!(probe_once(&ok, 5));
        let (down, _) = crate::test_util::mock_http(503, "", 1);
        assert!(!probe_once(&down, 5));
    }

    #[test]
    fn probe_once_false_on_connection_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(!probe_once(&format!("http://{}", addr), 2));
    }

    #[test]
    fn episode_triggers_at_threshold_and_resets() {
        let mut ep = EpisodeTracker::default();
        assert!(!ep.observe(false, 3)); // 1st consecutive fail
        assert!(!ep.observe(false, 3)); // 2nd
        assert!(ep.observe(false, 3)); // 3rd → episode emitted
        assert!(!ep.observe(false, 3)); // counter reset, restart counting
    }

    #[test]
    fn recovery_resets_counter() {
        let mut ep = EpisodeTracker::default();
        assert!(!ep.observe(false, 3));
        assert!(!ep.observe(false, 3));
        ep.observe(true, 3); // recovery
        assert_eq!(ep.fails(), 0);
        assert!(!ep.observe(false, 3)); // only 1 fail again
    }
}
