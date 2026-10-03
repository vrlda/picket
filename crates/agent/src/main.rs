mod audit;
mod cmd;
mod discover;
mod engine;
mod hostid;
mod journald;
mod logs;
mod procfs;
mod sensors;
mod state;
mod telemetry;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use picket_common::{Config, Heartbeat};

#[derive(Parser)]
#[command(name = "picket-agent", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Path to config file.
    #[arg(long, default_value = "/etc/picket/agent.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the agent continuously.
    Run,
    /// One-shot: collect and print events, then exit.
    Check,
    /// Print the auto-discovery checklist, then exit.
    Discover,
}

fn load_config(path: &PathBuf) -> Config {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            eprintln!("invalid config {}: {}; using defaults", path.display(), e);
            Config::default()
        }),
        Err(e) => {
            eprintln!("no config at {} ({}); using defaults", path.display(), e);
            Config::default()
        }
    }
}

fn resolve_host_id(cfg: &Config) -> String {
    if cfg.host_id_valid() {
        cfg.host_id.clone()
    } else {
        hostid::resolve()
    }
}

/// Agent bearer tokens must not traverse a remote connection in clear text.
/// Keep plain HTTP available only for local development and test control
/// planes, where traffic never leaves the host.
fn is_safe_server_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(authority) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = authority.split('/').next().unwrap_or_default();
    matches!(authority, "localhost" | "127.0.0.1" | "[::1]")
        || authority.starts_with("localhost:")
        || authority.starts_with("127.0.0.1:")
        || authority.starts_with("[::1]:")
}

fn main() {
    let cli = Cli::parse();
    let cfg = load_config(&cli.config);
    if !cfg.server_url.is_empty() && !is_safe_server_url(&cfg.server_url) {
        eprintln!("server_url must use https (http is allowed only for localhost)");
        std::process::exit(1);
    }
    let host_id = resolve_host_id(&cfg);
    let procfs = procfs::ProcFs::new(PathBuf::from("/proc"));
    let runners = cmd::Runners::real();
    let spool = telemetry::Spool::new(PathBuf::from(&cfg.spool_dir));

    match cli.cmd {
        Cmd::Check => {
            let mut state = engine::AgentState::new(&cfg, &host_id);
            // Seed the journal cursor to now (ms): a one-shot check reads the
            // journal from now forward — without the seed, the full-journal
            // read since epoch would blow the 10s timeout.
            state.journal_since_ms = now_ms();
            let evs = engine::run_once(
                &cfg,
                &mut engine::Deduper::new(cfg.dedup_secs),
                &host_id,
                now_ms(),
                &procfs,
                &runners,
                &mut state,
            );
            for ev in &evs {
                println!("{}", serde_json::to_string(ev).unwrap());
            }
            if evs.is_empty() {
                if procfs_is_broken(&procfs) {
                    eprintln!("all sensors failed — cannot confirm host health");
                    std::process::exit(1);
                }
                println!("no issues detected");
            }
        }
        Cmd::Discover => {
            let procfs = procfs::ProcFs::new(PathBuf::from("/proc"));
            for check in discover::run_all(&PathBuf::from("/"), &runners, &procfs) {
                let mark = if check.ok { "✓" } else { "✗" };
                println!("{} {} — {}", mark, check.label, check.detail);
            }
            println!("\nYour server is now monitored.");
        }
        Cmd::Run => {
            let mut deduper = engine::Deduper::new(cfg.dedup_secs);
            let mut state = engine::AgentState::new(&cfg, &host_id);
            // startup permission audit — fail loudly, then keep running
            // (sensors fail-open, but the operator saw the summary)
            for row in audit::audit(&runners, &PathBuf::from(&cfg.spool_dir)) {
                let mark = if row.ok { "ok" } else { "WARN" };
                eprintln!("[audit] {}: {} — {}", mark, row.name, row.detail);
            }
            // Seed the journal cursor to now only when persisted state did
            // not restore one: reading the whole journal since epoch on
            // first start would blow the 10s timeout.
            if state.journal_since_ms == 0 {
                state.journal_since_ms = now_ms();
            }
            #[cfg(target_os = "linux")]
            if !cfg.watch_paths.is_empty() || cfg.watch_authorized_keys {
                let mut watch_paths = cfg.watch_paths.clone();
                if cfg.watch_authorized_keys {
                    for pat in ["/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"] {
                        if let Ok(entries) = glob::glob(pat) {
                            for e in entries.flatten() {
                                let p = e.to_string_lossy().into_owned();
                                if !watch_paths.contains(&p) {
                                    watch_paths.push(p);
                                }
                            }
                        }
                    }
                }
                let (tx, rx) = std::sync::mpsc::channel();
                if crate::sensors::fim::spawn_watcher(
                    watch_paths
                        .iter()
                        .map(|p| crate::sensors::fim_types::WatchedFile::new(p))
                        .collect(),
                    tx,
                )
                .is_ok()
                {
                    state.fim_rx = Some(rx);
                } else {
                    eprintln!("fim watcher failed to start");
                }
            }
            let mut last_heartbeat = Instant::now() - Duration::from_secs(cfg.heartbeat_secs + 1);
            let mut last_state_save = 0i64;
            loop {
                let evs = engine::run_once(
                    &cfg,
                    &mut deduper,
                    &host_id,
                    now_ms(),
                    &procfs,
                    &runners,
                    &mut state,
                );
                if !evs.is_empty() && !cfg.server_url.is_empty() {
                    match telemetry::post_batch(&cfg.server_url, &cfg.token, &evs) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("post failed ({:?}); spooling {} events", e, evs.len());
                            if let Err(se) = spool.append(&evs) {
                                eprintln!("spool append failed: {}", se);
                            }
                        }
                    }
                }
                if last_heartbeat.elapsed() >= Duration::from_secs(cfg.heartbeat_secs)
                    && !cfg.server_url.is_empty()
                {
                    let stats = spool.drain(&cfg.server_url, &cfg.token);
                    if stats.delivered > 0 || stats.dropped > 0 {
                        eprintln!(
                            "drain: {} delivered, {} dropped, {} deferred",
                            stats.delivered, stats.dropped, stats.deferred
                        );
                    }
                    let hb = Heartbeat {
                        host_id: host_id.clone(),
                        ts: now_ms(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        queue_len: spool.count() as u64,
                    };
                    if let Err(e) = telemetry::post_heartbeat(&cfg.server_url, &cfg.token, &hb) {
                        eprintln!("heartbeat failed: {:?}", e);
                    }
                    last_heartbeat = Instant::now();
                }
                // persist agent state every ~60s (crash loses at most one interval)
                if now_ms() - last_state_save >= 60_000 {
                    last_state_save = now_ms();
                    state.sync_persisted();
                    if !cfg.state_file.is_empty() {
                        crate::state::save(&PathBuf::from(&cfg.state_file), &state.persisted);
                    }
                }
                std::thread::sleep(Duration::from_secs(cfg.poll_interval_secs));
            }
        }
    }
}

/// True when the core /proc sensors all failed — used by `check` to avoid
/// claiming "no issues" on a host we cannot read.
fn procfs_is_broken(procfs: &procfs::ProcFs) -> bool {
    procfs.meminfo().is_err() && procfs.load_one_min().is_err() && procfs.netdev_errors().is_err()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::is_safe_server_url;

    #[test]
    fn permits_https_and_loopback_http_only() {
        assert!(is_safe_server_url("https://control.example.com"));
        assert!(is_safe_server_url("http://127.0.0.1:8787"));
        assert!(is_safe_server_url("http://localhost:8787"));
        assert!(is_safe_server_url("http://[::1]:8787"));
        assert!(!is_safe_server_url("http://control.example.com"));
        assert!(!is_safe_server_url("ftp://control.example.com"));
    }
}
