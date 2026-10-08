use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::mpsc::Receiver;

use crate::sensors::fim_types::{change_event, FimEvent};
use crate::sensors::netflow::NetState;
use crate::sensors::sshauth::{base_ssh_event, classify, AuthKind, BruteForceTracker, SeenIps};
use picket_common::{AgentEvent, Config, EventKind, Evidence, Severity};

/// Milliseconds between persistence directory scans (cron.d + systemd units).
const PERSISTENCE_SCAN_MS: i64 = 300_000;

/// Rolling median baseline spike detector. A value is a spike when it exceeds
/// the median of the last `window` samples by `ratio`x.
pub struct SpikeDetector {
    samples: VecDeque<f64>,
    window: usize,
    ratio: f64,
}

impl SpikeDetector {
    pub fn new(window: usize, ratio: f64) -> Self {
        SpikeDetector {
            samples: VecDeque::with_capacity(window),
            window,
            ratio,
        }
    }

    pub fn push(&mut self, v: f64) {
        if !v.is_finite() {
            return; // never let a NaN/inf sample poison the baseline
        }
        if self.samples.len() >= self.window {
            self.samples.pop_front();
        }
        self.samples.push_back(v);
    }

    fn median(&self) -> f64 {
        let mut v: Vec<f64> = self.samples.iter().copied().collect();
        // total_cmp: a NaN sample (e.g. a 0/0 ratio) must not panic the agent
        v.sort_by(|a, b| a.total_cmp(b));
        let n = v.len();
        if n == 0 {
            return 0.0;
        }
        if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2.0
        }
    }

    /// Needs at least 2 samples to establish a baseline.
    pub fn is_spike(&self, v: f64) -> bool {
        let m = self.median();
        self.samples.len() >= 2 && m > 0.0 && v >= m * self.ratio
    }
}

/// Suppress re-emission of the same (kind, key) within `window_secs`.
pub struct Deduper {
    window_secs: i64,
    last_emitted: HashMap<(picket_common::EventType, String), i64>,
}

impl Deduper {
    pub fn new(window_secs: i64) -> Self {
        Deduper {
            window_secs,
            last_emitted: HashMap::new(),
        }
    }

    pub fn should_emit(&mut self, kind: &picket_common::EventType, key: &str, ts: i64) -> bool {
        let entry = self
            .last_emitted
            .entry((kind.clone(), key.to_string()))
            .or_insert(i64::MIN);
        if ts.saturating_sub(*entry) >= self.window_secs {
            *entry = ts;
            true
        } else {
            false
        }
    }
}

/// Detects boot-epoch changes (uptime resets) between polls. A reboot fires
/// only when BOTH the boot epoch jumped (>60s) AND the kernel boot id
/// changed (clock steps and VM suspension move the epoch alone; a real
/// reboot changes both). When the boot id is unreadable, the epoch
/// heuristic alone decides.
#[derive(Default)]
pub struct RebootDetector {
    boot_epoch: Option<i64>,
    boot_id: Option<String>,
}

impl RebootDetector {
    pub fn observe(&mut self, boot: i64, id: Option<String>, _ts_ms: i64) -> (bool, i64) {
        let epoch_jumped = match self.boot_epoch {
            Some(prev) => (boot - prev).abs() > 60_000,
            None => false,
        };
        let id_changed = match (&self.boot_id, &id) {
            (Some(prev), Some(cur)) => prev != cur,
            _ => true, // unavailable → don't block the epoch signal
        };
        let fired = epoch_jumped && id_changed;
        self.boot_epoch = Some(boot);
        if id.is_some() {
            self.boot_id = id;
        }
        (fired, boot)
    }
}

/// Boot epoch (unix millis) from a now and uptime; None when uptime is
/// unreadable.
pub fn boot_epoch(now_ms: i64, uptime_secs: f64) -> Option<i64> {
    Some(now_ms - (uptime_secs * 1000.0) as i64)
}

/// CPU usage state across polls: rolling baseline + spike event emission.
pub struct CpuState {
    host: String,
    total: u64,
    busy: u64,
    detector: SpikeDetector,
}

impl CpuState {
    pub fn new(window: usize, ratio: f64, host: &str) -> Self {
        CpuState {
            host: host.into(),
            total: 0,
            busy: 0,
            detector: SpikeDetector::new(window, ratio),
        }
    }

    /// Feed a fresh cpu usage percentage; emits a CpuSpike event when the
    /// current value deviates from the rolling median by the configured ratio.
    /// The poll `ts` (from run_once) is the single time source for the batch —
    /// all events in a batch share it. Note: id uniqueness relies on the
    /// Deduper suppressing a second CpuSpike for "cpu:usage" within its window,
    /// since two emits at the same ts would otherwise collide on `{host}-cpu-{ts}`.
    pub fn observe(&mut self, pct: f64, ts: i64) -> Vec<AgentEvent> {
        let mut evs = Vec::new();
        self.detector.push(pct);
        if self.detector.is_spike(pct) {
            evs.push(AgentEvent {
                id: format!("{}-cpu-{}", self.host, ts),
                ts,
                host_id: self.host.clone(),
                key: "cpu:usage".into(),
                kind: EventKind::CpuSpike.into(),
                severity: Severity::Warning,
                summary: format!("CPU usage spiked to {:.0}%", pct),
                evidence: vec![Evidence {
                    ts,
                    source: "engine".into(),
                    detail: format!("CpuUsagePct={:.1}", pct),
                }],
                ..Default::default()
            });
        }
        evs
    }
}

/// Mutable state shared by the sensors across polls.
pub struct AgentState {
    pub cpu: CpuState,
    pub crash: crate::sensors::systemd::CrashTracker,
    pub ssh_seen: SeenIps,
    pub ssh_brute: BruteForceTracker,
    pub net: NetState,
    pub docker: crate::sensors::docker::ContainerTracker,
    pub reboot: RebootDetector,
    /// Journal read cursor in unix MILLIS: the max line ts_ms seen. The
    /// journalctl @since arg (seconds) is derived as journal_since_ms / 1000.
    /// Lines with ts_ms <= cursor are skipped, so a line is never processed
    /// twice — even when the newest line is re-read on every poll.
    pub journal_since_ms: i64,
    /// FIM watcher channel (None when no files are watched).
    pub fim_rx: Option<Receiver<FimEvent>>,
    /// Compiled error patterns; empty when no error patterns are configured.
    pub error_regexes: Vec<(String, regex::Regex)>,
    /// Per (ident, pattern) line timestamps (ms) for sliding-window counting.
    pub error_counts: HashMap<(String, String), Vec<i64>>,
    /// Concrete cert paths to scan (glob-expanded at startup).
    pub cert_paths: Vec<String>,
    /// Last TLS cert scan time (ms); gates the openssl spawn.
    pub last_cert_scan: i64,
    /// Tail cursor per access log path.
    pub access_tails: HashMap<String, crate::logs::TailState>,
    /// (poll ts, lines read) pairs within the request-rate window.
    pub request_counts: VecDeque<(i64, u32)>,
    /// Last persistence directory snapshot (cron.d + systemd units); None
    /// until the first scan seeds the baseline.
    pub persistence_snapshot: Option<std::collections::HashMap<String, (i64, u64)>>,
    /// Last persistence scan time (ms); gates the directory walk.
    pub persistence_scan: i64,
    /// Executables outside system paths seen in the last process scan; None
    /// until the first scan seeds the baseline.
    pub known_exes: Option<std::collections::HashSet<String>>,
    /// Last process scan time (ms); gates the /proc walk.
    pub last_proc_scan: i64,
    /// Last seen RO flag per mount point; FsReadOnly fires only on a rw→ro
    /// transition (a boot-time ro mount is normal, not an event).
    pub mount_ro_baseline: HashMap<String, bool>,
    /// State persisted across restarts (seen-IPs, journal cursor, baselines).
    pub persisted: crate::state::PersistedState,
}

impl AgentState {
    pub fn new(cfg: &Config, host_id: &str) -> Self {
        let persisted = if cfg.state_file.is_empty() {
            crate::state::PersistedState::default()
        } else {
            crate::state::load(std::path::Path::new(&cfg.state_file))
        };
        let mut ssh_seen = SeenIps::default();
        ssh_seen.extend(persisted.seen_ips.iter().cloned());
        // Restore the journal cursor from persisted state — but only when it
        // is recent: a stale cursor (>1h old, or a long-down agent) reseeds to
        // now, otherwise the whole downtime gap would be re-read and old
        // events re-emitted. A zero cursor means nothing was ever saved;
        // main.rs seeds it to now on first run (a full-journal read since
        // epoch would blow the journalctl timeout).
        let journal_since_ms = {
            let c = persisted.journal_cursor_ms;
            if c > 0 && c < now_ms() - 3_600_000 {
                now_ms()
            } else {
                c
            }
        };
        // Only seed the exec baseline when a prior run actually saved one —
        // an empty persisted set is ambiguous, so a fresh/never-baselined
        // state leaves known_exes = None and this run re-baselines.
        let known_exes = if persisted.known_exes.is_empty() {
            None
        } else {
            Some(persisted.known_exes.iter().cloned().collect())
        };
        AgentState {
            cpu: CpuState::new(20, cfg.cpu_spike_ratio, host_id),
            crash: crate::sensors::systemd::CrashTracker::new(120),
            ssh_seen,
            ssh_brute: BruteForceTracker::new(cfg.ssh_brute_threshold, cfg.ssh_brute_window_secs),
            net: {
                // a saved baseline means this host was already seeded
                let mut net = NetState::default();
                net.seen_listen
                    .extend(persisted.seen_listen.iter().cloned());
                net.seen_remote
                    .extend(persisted.seen_remote.iter().cloned());
                net.seeded = !net.seen_listen.is_empty() || !net.seen_remote.is_empty();
                net
            },
            docker: crate::sensors::docker::ContainerTracker::default(),
            reboot: RebootDetector::default(),
            journal_since_ms,
            fim_rx: None,
            error_regexes: cfg
                .error_patterns
                .iter()
                .filter_map(|p| match regex::Regex::new(p) {
                    Ok(r) => Some((p.clone(), r)),
                    Err(e) => {
                        eprintln!("invalid error pattern {:?}: {}", p, e);
                        None
                    }
                })
                .collect(),
            error_counts: Default::default(),
            cert_paths: if cfg.cert_paths.is_empty() {
                crate::sensors::certs::expand_paths(&crate::sensors::certs::default_cert_paths())
            } else {
                crate::sensors::certs::expand_paths(&cfg.cert_paths)
            },
            last_cert_scan: persisted.last_cert_scan,
            access_tails: Default::default(),
            request_counts: Default::default(),
            persistence_snapshot: None,
            persistence_scan: 0,
            known_exes,
            last_proc_scan: 0,
            mount_ro_baseline: Default::default(),
            persisted,
        }
    }

    /// Copy the live sensor state back into `persisted` so the next periodic
    /// save captures it. known_exes is only written when a baseline exists —
    /// until then the previous baseline (if any) is preserved, not clobbered
    /// with an empty set.
    pub fn sync_persisted(&mut self) {
        self.persisted.seen_ips = self.ssh_seen.all();
        self.persisted.journal_cursor_ms = self.journal_since_ms;
        self.persisted.last_cert_scan = self.last_cert_scan;
        if self.net.seeded {
            let mut v: Vec<String> = self.net.seen_listen.iter().cloned().collect();
            v.sort();
            self.persisted.seen_listen = v;
            let mut v: Vec<String> = self.net.seen_remote.iter().cloned().collect();
            v.sort();
            self.persisted.seen_remote = v;
        }
        if let Some(exes) = &self.known_exes {
            let mut v: Vec<String> = exes.iter().cloned().collect();
            v.sort();
            self.persisted.known_exes = v;
        }
    }

    #[cfg(test)]
    /// Fresh state for tests. Never loads the default state file — on a
    /// machine where the agent has run, /var/lib/picket/agent-state.json
    /// carries a live journal cursor that silently filters test fixtures.
    pub fn for_tests() -> Self {
        let cfg = Config {
            state_file: String::new(),
            ..Config::default()
        };
        AgentState::new(&cfg, "h-1")
    }
}

/// Wall-clock unix millis — used only for first-run / stale-cursor seeding
/// in AgentState::new; run_once gets its ts from the caller, the single time
/// source for a batch.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// One detection pass: run all sensors against current state, apply dedup,
/// return events to ship. Called every poll interval and by `check`.
pub fn run_once(
    cfg: &Config,
    deduper: &mut Deduper,
    host_id: &str,
    ts: i64,
    procfs: &crate::procfs::ProcFs,
    runners: &crate::cmd::Runners,
    state: &mut AgentState,
) -> Vec<AgentEvent> {
    let mut evs = Vec::new();

    // resource sensor
    if let Ok(mem) = procfs.meminfo() {
        evs.extend(crate::sensors::resource::mem_events(mem, cfg, host_id, ts));
        evs.extend(crate::sensors::resource::swap_events(mem, cfg, host_id, ts));
    }
    if let Ok(load) = procfs.load_one_min() {
        let ncpu = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        evs.extend(crate::sensors::resource::load_events(
            load, ncpu, cfg, host_id, ts,
        ));
    }
    if let Ok(errs) = procfs.netdev_errors() {
        evs.extend(crate::sensors::resource::netdev_events(&errs, host_id, ts));
    }
    let (total, busy, pct) =
        crate::sensors::resource::cpu_usage_now(procfs, state.cpu.total, state.cpu.busy);
    state.cpu.total = total;
    state.cpu.busy = busy;
    evs.extend(state.cpu.observe(pct, ts));

    // reboot sensor: boot epoch = now - uptime; uptime resets = reboot
    if let Ok(uptime) = procfs.uptime_secs() {
        if let Some(boot) = boot_epoch(ts, uptime) {
            let id = procfs.boot_id().ok();
            let (fired, boot) = state.reboot.observe(boot, id, ts);
            if fired {
                evs.push(AgentEvent {
                    id: format!("reboot-{}", ts),
                    ts,
                    host_id: host_id.into(),
                    key: "system:reboot".into(),
                    kind: EventKind::Reboot.into(),
                    severity: Severity::Warning,
                    summary: "system rebooted (uptime and boot id reset)".into(),
                    evidence: vec![Evidence {
                        ts,
                        source: "procfs".into(),
                        detail: format!("BootEpoch={}", boot),
                    }],
                    ..Default::default()
                });
            }
        }
    }

    // systemd sensor
    if let Ok(states) = crate::sensors::systemd::systemctl_list_units(runners.sys.as_ref()) {
        for (unit, unit_state) in states {
            state
                .crash
                .observe(&unit, unit_state, (ts / 1000) as u64, host_id, &mut evs);
        }
    }

    // ssh/auth sensor (journald)
    let since_ms = state.journal_since_ms;
    if let Ok(lines) = crate::journald::read_since(runners.journal.as_ref(), since_ms / 1000, 0) {
        for line in &lines {
            // ms cursor: a line at or before the cursor was already processed.
            // Skipping <= (not <) means a line at exactly the cursor ms is not
            // re-read, so advancing to max(seen) never re-processes anything.
            if line.ts_ms <= state.journal_since_ms {
                continue;
            }
            state.journal_since_ms = state.journal_since_ms.max(line.ts_ms);
            if let Some(auth) = classify(line) {
                match auth.kind {
                    AuthKind::SshFailed => {
                        let (episode, count) = state
                            .ssh_brute
                            .observe_failure(&auth.user, &auth.ip, line.ts_ms);
                        if episode {
                            evs.push(AgentEvent {
                                id: format!(
                                    "brute-{}-{}-{}-{}",
                                    host_id, auth.user, auth.ip, line.ts_ms
                                ),
                                ts: line.ts_ms,
                                host_id: host_id.into(),
                                key: format!("ssh:brute:{}:{}", auth.user, auth.ip),
                                kind: EventKind::SshBruteForce.into(),
                                severity: Severity::Warning,
                                summary: format!(
                                    "{} failed SSH logins for {} from {} in {}s",
                                    count, auth.user, auth.ip, cfg.ssh_brute_window_secs
                                ),
                                evidence: vec![Evidence {
                                    ts: line.ts_ms,
                                    source: "journald".into(),
                                    detail: auth.detail.clone(),
                                }],
                                ..Default::default()
                            });
                        } else {
                            evs.push(AgentEvent {
                                id: format!("sshf-{}-{}", line.ts_ms, count),
                                ts: line.ts_ms,
                                host_id: host_id.into(),
                                key: format!("ssh:failed:{}:{}", auth.user, auth.ip),
                                kind: EventKind::SshFailed.into(),
                                severity: Severity::Warning,
                                summary: format!(
                                    "failed SSH login for {} from {}",
                                    auth.user, auth.ip
                                ),
                                evidence: vec![Evidence {
                                    ts: line.ts_ms,
                                    source: "journald".into(),
                                    detail: auth.detail.clone(),
                                }],
                                ..Default::default()
                            });
                        }
                    }
                    _ => {
                        let base_sev = match auth.kind {
                            AuthKind::RootLogin => Severity::Warning,
                            _ => Severity::Info,
                        };
                        let builder = base_ssh_event(&auth.user, &auth.ip, base_sev);
                        // Local events (sudo/su) have no source IP — never
                        // first-seen-escalate the empty string.
                        let ip_is_new = !auth.ip.is_empty() && state.ssh_seen.is_first(&auth.ip);
                        let sev = builder.suggest_severity(ip_is_new);
                        let kind = match auth.kind {
                            AuthKind::SshLogin => EventKind::SshLogin,
                            AuthKind::RootLogin => EventKind::RootLogin,
                            AuthKind::SudoUsed => EventKind::SudoUsed,
                            AuthKind::SshFailed => unreachable!(),
                        };
                        let summary = match auth.kind {
                            AuthKind::SshLogin => {
                                format!("SSH login by {} from {}", auth.user, auth.ip)
                            }
                            AuthKind::RootLogin => format!("root login from {}", auth.ip),
                            AuthKind::SudoUsed => format!("{} ran sudo", auth.user),
                            AuthKind::SshFailed => unreachable!(),
                        };
                        evs.push(AgentEvent {
                            id: format!("ssh-{}-{}", line.ts_ms, auth.user),
                            ts: line.ts_ms,
                            host_id: host_id.into(),
                            key: match auth.kind {
                                AuthKind::SudoUsed => format!("sudo:{}", auth.user),
                                _ => format!("ssh:login:{}", auth.user),
                            },
                            kind: kind.into(),
                            severity: sev,
                            summary,
                            evidence: vec![Evidence {
                                ts: line.ts_ms,
                                source: "journald".into(),
                                detail: auth.detail.clone(),
                            }],
                            ..Default::default()
                        });
                    }
                }
            }
            if let Some(unit) = crate::journald::service_start(line) {
                evs.push(AgentEvent {
                    id: format!("svcstart-{}-{}", line.ts_ms, unit),
                    ts: line.ts_ms,
                    host_id: host_id.into(),
                    key: format!("svc:{}", unit),
                    kind: EventKind::ServiceRestarted.into(),
                    severity: Severity::Info,
                    summary: format!("{} restarted", unit),
                    evidence: vec![Evidence {
                        ts: line.ts_ms,
                        source: "journald".into(),
                        detail: line.message.clone(),
                    }],
                    ..Default::default()
                });
            }
            if let Some(sig) = crate::sensors::health::classify(line) {
                let (kind, sev, key) = match sig {
                    crate::sensors::health::HealthSignal::OomKill => {
                        (EventKind::OomKill, Severity::Critical, "health:oom")
                    }
                    crate::sensors::health::HealthSignal::KernelPanic => {
                        (EventKind::KernelPanic, Severity::Critical, "health:panic")
                    }
                    crate::sensors::health::HealthSignal::ClockChange => {
                        (EventKind::ClockChange, Severity::Warning, "health:clock")
                    }
                };
                evs.push(AgentEvent {
                    id: format!("{}-{}", key, line.ts_ms),
                    ts: line.ts_ms,
                    host_id: host_id.into(),
                    key: key.into(),
                    kind: kind.into(),
                    severity: sev,
                    summary: line.message.clone(),
                    evidence: vec![Evidence {
                        ts: line.ts_ms,
                        source: "journald".into(),
                        detail: line.message.clone(),
                    }],
                    ..Default::default()
                });
            }
            if let Some(sig) = crate::sensors::security::classify(line) {
                let (kind, sev, key) = match sig {
                    crate::sensors::security::SecSignal::NewUser(_) => {
                        (EventKind::NewUser, Severity::Warning, "sec:user")
                    }
                    crate::sensors::security::SecSignal::PackageInstalled(_) => {
                        (EventKind::PackageInstalled, Severity::Info, "sec:pkg")
                    }
                };
                evs.push(AgentEvent {
                    id: format!("{}-{}", key, line.ts_ms),
                    ts: line.ts_ms,
                    host_id: host_id.into(),
                    key: key.into(),
                    kind: kind.into(),
                    severity: sev,
                    summary: line.message.clone(),
                    evidence: vec![Evidence {
                        ts: line.ts_ms,
                        source: "journald".into(),
                        detail: line.message.clone(),
                    }],
                    ..Default::default()
                });
            }
            if !state.error_regexes.is_empty() {
                for (pat, re) in &state.error_regexes {
                    if re.is_match(&line.message) {
                        state
                            .error_counts
                            .entry((line.ident.clone(), pat.clone()))
                            .or_default()
                            .push(line.ts_ms);
                    }
                }
            }
        }
    }

    // netflow sensor
    evs.extend(state.net.observe(
        procfs,
        ts,
        host_id,
        cfg.scan_threshold,
        cfg.scan_window_secs * 1000,
    ));

    // disk/inode sensor
    evs.extend(crate::sensors::disk::disk_events(
        procfs,
        cfg,
        ts,
        host_id,
        &mut state.mount_ro_baseline,
    ));

    // access-log sensor (config-gated)
    for path in &cfg.access_log_paths {
        let tail = state.access_tails.entry(path.clone()).or_default();
        let lines = tail.read_new(std::path::Path::new(path));
        let mut errors_5xx = 0usize;
        for l in &lines {
            if let Some(al) = crate::sensors::accesslog::parse_combined(l) {
                if (500..600).contains(&al.status) {
                    errors_5xx += 1;
                }
            }
        }
        if errors_5xx > 0 {
            evs.push(AgentEvent {
                id: format!("http5xx-{}-{}", path, ts),
                ts,
                host_id: host_id.into(),
                key: format!("http5xx:{}", path),
                kind: EventKind::ErrorRateSpike.into(),
                severity: Severity::Warning,
                summary: format!("{} 5xx responses from {}", errors_5xx, path),
                evidence: vec![Evidence {
                    ts,
                    source: "accesslog".into(),
                    detail: format!("Path={} FiveXx={}", path, errors_5xx),
                }],
                ..Default::default()
            });
        }
        state.request_counts.push_back((ts, lines.len() as u32));
    }
    // request-rate spike (counts within the window, episode semantics)
    let window_ms = cfg.request_rate_window_secs.max(10) * 1000;
    state.request_counts.retain(|(t, _)| *t + window_ms >= ts);
    let total: u32 = state.request_counts.iter().map(|(_, n)| *n).sum();
    if total >= cfg.request_rate_threshold {
        state.request_counts.clear();
        evs.push(AgentEvent {
            id: format!("reqrate-{}", ts),
            ts,
            host_id: host_id.into(),
            key: "http:reqrate".into(),
            kind: EventKind::RequestRateSpike.into(),
            severity: Severity::Warning,
            summary: format!(
                "request rate exceeded {} in {}s",
                cfg.request_rate_threshold, cfg.request_rate_window_secs
            ),
            evidence: vec![Evidence {
                ts,
                source: "accesslog".into(),
                detail: format!(
                    "Requests={} WindowSecs={}",
                    total, cfg.request_rate_window_secs
                ),
            }],
            ..Default::default()
        });
    }

    // docker sensor (fail-open: no docker binary / daemon → nothing)
    if cfg.docker_enabled {
        if let Ok(out) = runners
            .docker
            .run(&["ps", "-a", "--no-trunc", "--format", "{{json .}}"])
        {
            if let Ok(containers) = crate::sensors::docker::parse_docker_ps(&out) {
                state.docker.observe(&containers, ts, host_id, &mut evs);
            }
        }
    }

    // TLS cert sensor — gated by the scan interval (openssl spawn per cert)
    if ts - state.last_cert_scan >= cfg.cert_scan_interval_secs.max(60) * 1000 {
        state.last_cert_scan = ts;
        evs.extend(crate::sensors::certs::scan_certs(
            &state.cert_paths,
            cfg,
            ts / 1000, // unix seconds (the cert math domain)
            ts,
            host_id,
            runners.openssl.as_ref(),
        ));
    }

    // persistence change detection (cron + systemd units): the first scan
    // only seeds the baseline; later scans diff and emit on changes
    if ts - state.persistence_scan >= PERSISTENCE_SCAN_MS {
        state.persistence_scan = ts;
        let after = crate::sensors::security::snapshot_dir(Path::new("/etc/cron.d"));
        let mut after_sys =
            crate::sensors::security::snapshot_dir(Path::new("/etc/systemd/system"));
        for (k, v) in after {
            after_sys.insert(format!("systemd/{}", k), v);
        }
        let mut all_changed = Vec::new();
        if let Some(before) = &state.persistence_snapshot {
            all_changed = crate::sensors::security::diff_snapshots(before, &after_sys);
        }
        state.persistence_snapshot = Some(after_sys);
        for path in all_changed {
            evs.push(AgentEvent {
                id: format!("persist-{}-{}", path, ts),
                ts,
                host_id: host_id.into(),
                key: format!("persist:{}", path),
                kind: EventKind::PersistenceChanged.into(),
                severity: Severity::Warning,
                summary: format!("persistence change: {}", path),
                evidence: vec![Evidence {
                    ts,
                    source: "security".into(),
                    detail: format!("Path={}", path),
                }],
                ..Default::default()
            });
        }
    }

    // process snapshot: suspicious + unexpected exec (heuristic)
    if ts - state.last_proc_scan >= cfg.process_scan_interval_secs.max(10) * 1000 {
        state.last_proc_scan = ts;
        let procs = crate::sensors::process::scan_procs(Path::new("/proc"));
        for p in &procs {
            if let Some(reason) = crate::sensors::process::suspicious(p) {
                evs.push(AgentEvent {
                    id: format!("susp-{}-{}", p.pid, ts),
                    ts,
                    host_id: host_id.into(),
                    key: format!("suspicious:{}", p.pid),
                    kind: EventKind::SuspiciousExec.into(),
                    severity: Severity::Critical,
                    summary: format!("suspicious process {} ({}): {}", p.pid, p.exe, reason),
                    evidence: vec![Evidence {
                        ts,
                        source: "process".into(),
                        detail: format!(
                            "Pid={} Exe={} Cmdline={} Reason={}",
                            p.pid, p.exe, p.cmdline, reason
                        ),
                    }],
                    ..Default::default()
                });
            }
        }
        // unexpected executables: baseline learning
        let current: std::collections::HashSet<String> = procs
            .iter()
            .filter(|p| !p.exe.is_empty() && !crate::sensors::process::is_system_path(&p.exe))
            .map(|p| p.exe.clone())
            .collect();
        match &state.known_exes {
            None => {
                state.known_exes = Some(current); // baseline
            }
            Some(baseline) => {
                for exe in current.difference(baseline) {
                    evs.push(AgentEvent {
                        id: format!("unexe-{}-{}", exe, ts),
                        ts,
                        host_id: host_id.into(),
                        key: format!("unexpected:{}", exe),
                        kind: EventKind::UnexpectedExec.into(),
                        severity: Severity::Warning,
                        summary: format!("unexpected executable running: {}", exe),
                        evidence: vec![Evidence {
                            ts,
                            source: "process".into(),
                            detail: format!("Exe={}", exe),
                        }],
                        ..Default::default()
                    });
                }
                state.known_exes.as_mut().unwrap().extend(current);
            }
        }
    }

    // error-rate spikes: prune windows, emit episodes, reset counters
    if !state.error_regexes.is_empty() {
        let window_ms = cfg.error_window_secs.max(1) * 1000;
        let mut fired = Vec::new();
        for ((ident, pat), list) in state.error_counts.iter_mut() {
            list.retain(|t| *t + window_ms >= ts);
            if list.len() >= cfg.error_threshold as usize {
                let count = list.len();
                fired.push((ident.clone(), pat.clone(), count));
            }
        }
        for (ident, pat, count) in fired {
            state.error_counts.remove(&(ident.clone(), pat.clone()));
            evs.push(AgentEvent {
                id: format!("err-{}-{}-{}", ts, ident, pat),
                ts,
                host_id: host_id.into(),
                key: format!("errrate:{}:{}", ident, pat),
                kind: EventKind::ErrorRateSpike.into(),
                severity: Severity::Warning,
                summary: format!(
                    "{} error pattern \"{}\" hit {} times in {}s",
                    ident, pat, count, cfg.error_window_secs
                ),
                evidence: vec![Evidence {
                    ts,
                    source: "journald".into(),
                    detail: format!(
                        "Ident={} Pattern={} Count={} WindowSecs={}",
                        ident, pat, count, cfg.error_window_secs
                    ),
                }],
                ..Default::default()
            });
        }
    }

    // FIM channel drain
    if let Some(rx) = &state.fim_rx {
        while let Ok(fim) = rx.try_recv() {
            evs.push(change_event(&fim.path, &fim.action, ts, host_id));
        }
    }

    evs.retain(|e| deduper.should_emit(&e.kind, &e.key, e.ts));
    evs
}

#[cfg(test)]
mod tests {
    /// Default config minus the system state file (see AgentState::for_tests).
    fn test_config() -> Config {
        Config {
            state_file: String::new(),
            ..Config::default()
        }
    }

    use super::*;
    use picket_common::EventKind;

    #[test]
    fn spike_detector_flags_deviation_above_ratio() {
        let mut d = SpikeDetector::new(8, 2.0);
        for _ in 0..8 {
            d.push(100.0);
        }
        assert!(d.is_spike(300.0));
    }

    #[test]
    fn spike_detector_ignores_gradual_ramp() {
        let mut d = SpikeDetector::new(8, 2.0);
        let mut v = 100.0;
        for _ in 0..8 {
            d.push(v);
            v += 2.0;
        }
        assert!(!d.is_spike(v));
    }

    #[test]
    fn spike_detector_needs_baseline() {
        let mut d = SpikeDetector::new(8, 2.0);
        assert!(!d.is_spike(1000.0));
        d.push(1.0);
        assert!(!d.is_spike(1000.0));
    }

    #[test]
    fn deduper_suppresses_within_window() {
        let mut d = Deduper::new(300);
        assert!(d.should_emit(&EventKind::LoadHigh.into(), "load:1m", 1000));
        assert!(!d.should_emit(&EventKind::LoadHigh.into(), "load:1m", 1100));
        assert!(d.should_emit(&EventKind::LoadHigh.into(), "load:5m", 1100));
    }

    #[test]
    fn deduper_allows_after_window_expires() {
        let mut d = Deduper::new(300);
        assert!(d.should_emit(&EventKind::DiskHigh.into(), "mount:/", 1000));
        assert!(d.should_emit(&EventKind::DiskHigh.into(), "mount:/", 1301));
    }

    #[test]
    fn cpu_spike_state_machine_emits_event_after_sudden_rise() {
        let mut s = CpuState::new(8, 2.0, "h-1");
        let mut evs = Vec::new();
        for _ in 0..8 {
            evs.extend(s.observe(5.0, 1000));
        }
        assert!(evs.is_empty());
        let out = s.observe(90.0, 1000);
        assert_eq!(out[0].kind, EventKind::CpuSpike);
        assert_eq!(
            out[0].ts, 1000,
            "event must use the poll ts, not wall clock"
        );
        assert_eq!(out[0].id, "h-1-cpu-1000");
    }

    #[test]
    fn cpu_spike_ignores_gradual_increase() {
        let mut s = CpuState::new(8, 2.0, "h-1");
        let mut v = 5.0;
        let mut evs = Vec::new();
        for _ in 0..40 {
            v += 0.5;
            evs.extend(s.observe(v, 1000));
        }
        assert!(evs.is_empty());
    }

    fn fixture_procfs() -> crate::procfs::ProcFs {
        crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        )
    }

    /// Fake runners: sys/journal fakes serve their string on `--since`-less
    /// systemctl/journalctl calls, the docker fake serves `docker_out` on
    /// docker-shaped calls (args contain "ps"); openssl stays empty.
    fn runners_with(sys_out: &str, journal_out: &str, docker_out: &str) -> crate::cmd::Runners {
        crate::cmd::Runners::with_fakes(
            Box::new(FakeSys {
                journal_out: sys_out.to_string(),
                docker_out: String::new(),
            }),
            Box::new(FakeSys {
                journal_out: journal_out.to_string(),
                docker_out: String::new(),
            }),
            Box::new(FakeSys {
                journal_out: String::new(),
                docker_out: docker_out.to_string(),
            }),
            Box::new(FakeSys {
                journal_out: String::new(),
                docker_out: String::new(),
            }),
        )
    }

    #[test]
    fn run_once_wires_sensors_and_emits_events() {
        let cfg = test_config();
        let mut deduper = Deduper::new(300);
        let mut state = AgentState::for_tests();
        let p = fixture_procfs();
        let runners = runners_with("", "", "");
        let evs = run_once(&cfg, &mut deduper, "h-1", 1000, &p, &runners, &mut state);
        assert!(!evs.is_empty());
        assert!(evs.iter().any(|e| e.kind == EventKind::SwapHigh));
    }

    #[test]
    fn run_once_integrates_ssh_and_netflow_sensors() {
        let cfg = Config {
            ssh_brute_threshold: 2,
            ssh_brute_window_secs: 300,
            ..test_config()
        };
        let mut deduper = Deduper::new(300);
        let mut state = AgentState::new(&cfg, "h-1");
        state.net.seeded = true; // established host: its first scan is past
        let p = fixture_procfs();
        let journal_out = r#"{"__REALTIME_TIMESTAMP":"1758000000100000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 203.0.113.7 port 40000 ssh2"}
{"__REALTIME_TIMESTAMP":"1758000000200000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 203.0.113.7 port 40001 ssh2"}"#;
        let runners = runners_with("", journal_out, "");
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_002_000,
            &p,
            &runners,
            &mut state,
        );
        assert!(evs.iter().any(|e| e.kind == EventKind::SshBruteForce));
        assert!(evs.iter().any(|e| e.kind == EventKind::NewListeningPort));
        assert!(evs
            .iter()
            .any(|e| e.kind == EventKind::NewOutboundConnection));
        // brute ids must be unique per (host, user, ip, ts) — the server
        // INSERT OR IGNOREs on id, so a second episode for the same user+ip
        // (or a second host brute-forced from the same ip) must not collide.
        let brute = evs
            .iter()
            .find(|e| e.kind == EventKind::SshBruteForce)
            .unwrap();
        assert!(brute.id.contains("h-1-"));
        assert!(brute.id.contains(&brute.ts.to_string()));
    }

    #[test]
    fn run_once_journal_cursor_advances_beyond_max_line() {
        let mut state = AgentState::for_tests();
        let runners = runners_with(
            "",
            r#"{"__REALTIME_TIMESTAMP":"1758000000100000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for deploy from 198.51.100.24 port 51234 ssh2"}"#,
            "",
        );
        let cfg = test_config();
        let mut deduper = Deduper::new(300);
        let p = fixture_procfs();
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_002_000,
            &p,
            &runners,
            &mut state,
        );
        assert!(evs.iter().any(|e| e.kind == EventKind::SshLogin));
        assert_eq!(state.journal_since_ms, 1_758_000_000_100);
        // the fake returns the same line forever; the ms cursor must skip it —
        // no ssh events AND no new seen-ip state mutation on the 2nd poll
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_004_000,
            &p,
            &runners,
            &mut state,
        );
        assert!(!evs.iter().any(|e| e.kind == EventKind::SshLogin));
        assert_eq!(state.journal_since_ms, 1_758_000_000_100);
    }

    #[test]
    fn run_once_phantom_failures_do_not_feed_brute_tracker() {
        let cfg = Config {
            ssh_brute_threshold: 2,
            ssh_brute_window_secs: 300,
            ..test_config()
        };
        let mut deduper = Deduper::new(300);
        let mut state = AgentState::new(&cfg, "h-1");
        let p = fixture_procfs();
        let runners = runners_with(
            "",
            r#"{"__REALTIME_TIMESTAMP":"1758000000100000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 203.0.113.7 port 40000 ssh2"}"#,
            "",
        );
        // poll 1: 1 failure counted, no episode (threshold 2)
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_002_000,
            &p,
            &runners,
            &mut state,
        );
        assert!(!evs.iter().any(|e| e.kind == EventKind::SshBruteForce));
        // polls 2-3 re-read the same line: without the ms cursor each poll
        // feeds a phantom failure → episode fires on poll 2. With it: nothing.
        for _ in 0..2 {
            let evs = run_once(
                &cfg,
                &mut deduper,
                "h-1",
                1_758_000_004_000,
                &p,
                &runners,
                &mut state,
            );
            assert!(
                !evs.iter().any(|e| e.kind == EventKind::SshBruteForce),
                "phantom episode fired"
            );
        }
    }

    #[test]
    fn run_once_emits_sudo_and_root_login() {
        let mut state = AgentState::for_tests();
        let runners = runners_with(
            "",
            r#"{"__REALTIME_TIMESTAMP":"1758000000200000","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart nginx"}
{"__REALTIME_TIMESTAMP":"1758000000500000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for root from 198.51.100.24 port 51235 ssh2"}"#,
            "",
        );
        let cfg = test_config();
        let mut deduper = Deduper::new(300);
        let p = fixture_procfs();
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_002_000,
            &p,
            &runners,
            &mut state,
        );
        assert!(evs.iter().any(|e| e.kind == EventKind::SudoUsed));
        assert!(evs.iter().any(|e| e.kind == EventKind::RootLogin));
        // root login from a first-seen IP escalates to Critical
        let root = evs.iter().find(|e| e.kind == EventKind::RootLogin).unwrap();
        assert_eq!(root.severity, picket_common::Severity::Critical);
    }

    #[test]
    fn local_sudo_does_not_escalate_on_first_use() {
        let mut state = AgentState::for_tests();
        let runners = runners_with(
            "",
            r#"{"__REALTIME_TIMESTAMP":"1758000000200000","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart nginx"}"#,
            "",
        );
        let cfg = test_config();
        let mut deduper = Deduper::new(300);
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_002_000,
            &p,
            &runners,
            &mut state,
        );
        let sudo = evs.iter().find(|e| e.kind == EventKind::SudoUsed).unwrap();
        assert_eq!(sudo.severity, picket_common::Severity::Info);
    }

    #[test]
    fn run_once_emits_service_restarted() {
        let mut state = AgentState::for_tests();
        let runners = runners_with(
            "",
            r#"{"__REALTIME_TIMESTAMP":"1758000011000000","SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Started myapp.service."}"#,
            "",
        );
        let cfg = test_config();
        let mut deduper = Deduper::new(300);
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_011_000,
            &p,
            &runners,
            &mut state,
        );
        let ev = evs
            .iter()
            .find(|e| e.kind == EventKind::ServiceRestarted)
            .expect("restart event");
        assert_eq!(ev.severity, picket_common::Severity::Info);
        assert_eq!(ev.key, "svc:myapp.service");
    }

    #[test]
    fn boot_epoch_matches_clock_minus_uptime() {
        assert_eq!(boot_epoch(1_000_000_000_000, 3600.0), Some(999_996_400_000));
        assert_eq!(boot_epoch(1_000_000_000_000, 0.0), Some(1_000_000_000_000));
    }

    #[test]
    fn reboot_detector_fires_on_epoch_jump() {
        let mut d = RebootDetector::default();
        assert!(!d.observe(1_000_000_000, None, 0).0, "seed only");
        let (fired, _) = d.observe(999_996_400_000, None, 1000);
        assert!(fired);
        let (fired, _) = d.observe(999_996_400_010, None, 1010);
        assert!(!fired, "stable after jump");
    }

    #[test]
    fn reboot_detector_ignores_subthreshold_steps() {
        // clock steps move now and boot together → no false reboot
        let mut d = RebootDetector::default();
        d.observe(1_000_000_000, None, 0);
        assert!(!d.observe(1_000_000_100, None, 1000).0); // +0.1s step — sub-threshold, no fire
    }

    #[test]
    fn reboot_requires_both_epoch_jump_and_boot_id_change() {
        let mut d = RebootDetector::default();
        assert!(!d.observe(1_000_000_000, Some("id-1".to_string()), 0).0);
        assert!(
            !d.observe(999_996_400_000, Some("id-1".to_string()), 1000).0,
            "clock step must not fire"
        );
        assert!(
            d.observe(1_000_000_100, Some("id-2".to_string()), 2000).0,
            "real reboot: fresh epoch and new id"
        );
    }

    #[test]
    fn reboot_falls_back_to_epoch_only_without_boot_id() {
        let mut d = RebootDetector::default();
        assert!(!d.observe(1_000_000_000, None, 0).0);
        assert!(
            d.observe(999_996_400_000, None, 1000).0,
            "no boot id → epoch heuristic only"
        );
    }

    #[test]
    fn boot_id_change_alone_does_not_fire() {
        let mut d = RebootDetector::default();
        assert!(!d.observe(1_000_000_000, Some("id-1".into()), 0).0);
        assert!(
            !d.observe(1_000_000_100, Some("id-2".into()), 1000).0,
            "id changed but epoch stable"
        );
    }

    #[test]
    fn error_counts_window_and_emits_spike_at_threshold() {
        let cfg = Config {
            error_patterns: vec!["ERROR".to_string(), "Traceback".to_string()],
            error_threshold: 3,
            error_window_secs: 300,
            ..test_config()
        };
        let mut state = AgentState::new(&cfg, "h-1");
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let lines = [
            r#"{"__REALTIME_TIMESTAMP":"1758000010000000","SYSLOG_IDENTIFIER":"myapp","MESSAGE":"request failed with ERROR 500"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1758000011000000","SYSLOG_IDENTIFIER":"myapp","MESSAGE":"another ERROR occurred"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1758000012000000","SYSLOG_IDENTIFIER":"myapp","MESSAGE":"Traceback (most recent call last)"}"#,
        ];
        let runners = runners_with("", &lines.join("\n"), "");
        let mut deduper = Deduper::new(300);
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_013_000,
            &p,
            &runners,
            &mut state,
        );
        // per-pattern counts: ERROR=2, Traceback=1 — neither crosses 3
        assert!(evs.iter().all(|e| e.kind != EventKind::ErrorRateSpike));
        // flood one pattern past the threshold in a second poll
        let flood = (0..4)
            .map(|i| format!(r#"{{"__REALTIME_TIMESTAMP":"{}","SYSLOG_IDENTIFIER":"myapp","MESSAGE":"ERROR in request {}"}}"#, 1_758_000_020_000_000_i64 + (i as i64) * 100_000, i))
            .collect::<Vec<_>>()
            .join("\n");
        let runners = runners_with("", &flood, "");
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_021_000,
            &p,
            &runners,
            &mut state,
        );
        let spike = evs.iter().find(|e| e.kind == EventKind::ErrorRateSpike);
        assert!(
            spike.is_some(),
            "threshold crossed must emit, got {:?}",
            evs.iter().map(|e| e.kind.clone()).collect::<Vec<_>>()
        );
        assert_eq!(spike.unwrap().severity, picket_common::Severity::Warning);
        assert!(spike.unwrap().summary.contains("ERROR"));
    }

    #[test]
    fn run_once_integrates_docker_sensor() {
        let cfg = test_config();
        let mut state = AgentState::new(&cfg, "h-1");
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        // seed the tracker: web was running
        state.docker.observe(
            &[crate::sensors::docker::ContainerState {
                id: "1".into(),
                name: "web".into(),
                image: "x".into(),
                state: "running".into(),
                status: "Up 1 second".into(),
            }],
            1_000,
            "h-1",
            &mut Vec::new(),
        );
        let docker_out = r#"{"ID":"1","Image":"x","Command":"","CreatedAt":"","RunningFor":"","Ports":"","State":"exited","Status":"Exited (1)","Size":"","Names":"web","Labels":"","Mounts":""}"#;
        let runners = runners_with("", "", docker_out);
        let mut deduper = Deduper::new(300);
        let evs = run_once(&cfg, &mut deduper, "h-1", 2_000, &p, &runners, &mut state);
        assert!(
            evs.iter().any(|e| e.kind == EventKind::ContainerStopped),
            "running→exited must emit"
        );
    }

    #[test]
    fn run_once_error_spike_uses_runners_journal() {
        let cfg = Config {
            error_patterns: vec!["ERROR".to_string()],
            error_threshold: 2,
            error_window_secs: 300,
            ..test_config()
        };
        let mut state = AgentState::new(&cfg, "h-1");
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let lines = (0..3)
            .map(|i| format!(r#"{{"__REALTIME_TIMESTAMP":"{}","SYSLOG_IDENTIFIER":"app","MESSAGE":"ERROR boom {}"}}"#, 1_758_000_010_000_000_i64 + (i as i64) * 100_000, i))
            .collect::<Vec<_>>()
            .join("\n");
        let runners = runners_with("", &lines, "");
        let mut deduper = Deduper::new(300);
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_011_000,
            &p,
            &runners,
            &mut state,
        );
        assert!(
            evs.iter().any(|e| e.kind == EventKind::ErrorRateSpike),
            "3 errors ≥ threshold 2"
        );
    }

    #[test]
    fn run_once_emits_health_signals() {
        let cfg = test_config();
        let mut state = AgentState::new(&cfg, "h-1");
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let lines = [
            r#"{"__REALTIME_TIMESTAMP":"1758000020000000","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"Out of memory: Killed process 1 (init) total-vm:123"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1758000021000000","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"Kernel panic - not syncing"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1758000022000000","SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Time has been changed"}"#,
        ];
        let runners = runners_with("", &lines.join("\n"), "");
        let mut deduper = Deduper::new(300);
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_023_000,
            &p,
            &runners,
            &mut state,
        );
        assert!(evs.iter().any(
            |e| e.kind == EventKind::OomKill && e.severity == picket_common::Severity::Critical
        ));
        assert!(evs.iter().any(|e| e.kind == EventKind::KernelPanic));
        assert!(evs
            .iter()
            .any(|e| e.kind == EventKind::ClockChange
                && e.severity == picket_common::Severity::Warning));
    }

    #[test]
    fn run_once_emits_security_signals_and_seeds_persistence() {
        let cfg = test_config();
        let mut state = AgentState::new(&cfg, "h-1");
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let lines = [
            r#"{"__REALTIME_TIMESTAMP":"1758000020000000","SYSLOG_IDENTIFIER":"useradd","MESSAGE":"new user: name=alice"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1758000021000000","SYSLOG_IDENTIFIER":"dpkg","MESSAGE":"status installed nginx:amd64 1.18.0"}"#,
        ];
        let runners = runners_with("", &lines.join("\n"), "");
        let mut deduper = Deduper::new(300);
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_023_000,
            &p,
            &runners,
            &mut state,
        );
        assert!(evs.iter().any(
            |e| e.kind == EventKind::NewUser && e.severity == picket_common::Severity::Warning
        ));
        assert!(evs.iter().any(|e| e.kind == EventKind::PackageInstalled
            && e.severity == picket_common::Severity::Info));
        // first persistence scan only seeds the baseline — no events
        assert!(state.persistence_snapshot.is_some());
        assert!(!evs.iter().any(|e| e.kind == EventKind::PersistenceChanged));
        // second poll within the interval does not re-scan
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_024_000,
            &p,
            &runners,
            &mut state,
        );
        assert!(!evs.iter().any(|e| e.kind == EventKind::PersistenceChanged));
    }

    #[test]
    fn run_once_access_log_signals() {
        let log = std::env::temp_dir().join(format!("wt-access-{}", std::process::id()));
        let cfg = Config {
            access_log_paths: vec![log.to_string_lossy().into_owned()],
            request_rate_threshold: 3,
            request_rate_window_secs: 60,
            ..test_config()
        };
        let mut state = AgentState::new(&cfg, "h-1");
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let runners = runners_with("", "", "");
        let mut deduper = Deduper::new(300);
        // seed a healthy line first (the tail baseline), then 5xx lines
        std::fs::write(
            &log,
            r#"127.0.0.1 - - [07/Aug/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-""#
                .to_owned()
                + "\n",
        )
        .unwrap();
        let _ = run_once(&cfg, &mut deduper, "h-1", 1_000, &p, &runners, &mut state);
        let lines: Vec<String> = (0..4)
            .map(|i| {
                format!(
                    r#"127.0.0.1 - - [07/Aug/2026:10:00:0{} +0000] "GET / HTTP/1.1" 503 5 "-" "-""#,
                    i
                )
            })
            .collect();
        std::fs::write(&log, lines.join("\n") + "\n").unwrap();
        let evs = run_once(&cfg, &mut deduper, "h-1", 2_000, &p, &runners, &mut state);
        assert!(
            evs.iter().any(|e| e.kind == EventKind::ErrorRateSpike),
            "5xx must emit"
        );
        assert!(
            evs.iter().any(|e| e.kind == EventKind::RequestRateSpike),
            "4 requests >= threshold 3"
        );
        std::fs::remove_file(&log).ok();
    }

    #[test]
    fn journal_cursor_restores_from_state_file() {
        let state_file =
            std::env::temp_dir().join(format!("wt-state-engine-{}", std::process::id()));
        crate::state::save(
            &state_file,
            &crate::state::PersistedState {
                seen_ips: vec![],
                journal_cursor_ms: 1_758_000_000_100, // past the fake line's ts
                last_cert_scan: 0,
                known_exes: vec![],
                ..Default::default()
            },
        );
        let cfg = Config {
            state_file: state_file.to_string_lossy().into_owned(),
            ..test_config()
        };
        let mut state = AgentState::new(&cfg, "h-1");
        let p = crate::procfs::ProcFs::new(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let lines = r#"{"__REALTIME_TIMESTAMP":"1758000000100000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for deploy from 198.51.100.24 port 51234 ssh2"}"#;
        let runners = runners_with("", lines, "");
        let mut deduper = Deduper::new(300);
        let evs = run_once(
            &cfg,
            &mut deduper,
            "h-1",
            1_758_000_000_200,
            &p,
            &runners,
            &mut state,
        );
        assert!(
            !evs.iter().any(|e| e.kind == EventKind::SshLogin),
            "cursor past the line → skipped"
        );
        std::fs::remove_file(&state_file).ok();
    }

    struct FakeSys {
        journal_out: String,
        docker_out: String,
    }

    impl crate::cmd::CommandRunner for FakeSys {
        fn run(&self, args: &[&str]) -> Result<String, String> {
            if args.contains(&"--since") {
                return Ok(self.journal_out.clone());
            }
            if args.contains(&"ps") {
                return Ok(self.docker_out.clone());
            }
            Ok("".to_string())
        }
    }
}
