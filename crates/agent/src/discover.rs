//! Auto-discovery for the install checklist (product spec §3).
//! Every detection is a pure fn over (root path, runner) — no global state.

use std::path::Path;

use crate::cmd::{CommandRunner, Runners};

/// One checklist item.
pub struct Check {
    pub label: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// Run every detection; returns the checklist in display order.
pub fn run_all(root: &Path, runners: &Runners, procfs: &crate::procfs::ProcFs) -> Vec<Check> {
    vec![
        Check {
            label: "Host registered",
            ok: true,
            detail: "agent heartbeats self-register".into(),
        },
        Check {
            label: "System metrics enabled",
            ok: true,
            detail: "procfs sensors active".into(),
        },
        Check {
            label: "Process monitoring enabled",
            ok: true,
            detail: "systemd + journald sensors".into(),
        },
        Check {
            label: "SSH monitoring enabled",
            ok: detect_ssh(root).is_some(),
            detail: detect_ssh(root).unwrap_or_else(|| "no sshd_config".into()),
        },
        Check {
            label: "Application logs discovered",
            ok: detect_logs(root).is_some(),
            detail: detect_logs(root).unwrap_or_else(|| "no /var/log app dirs".into()),
        },
        Check {
            label: "Reverse proxy detected",
            ok: detect_proxies(root).is_some(),
            detail: detect_proxies(root).unwrap_or_else(|| "none".into()),
        },
        Check {
            label: "Docker detected",
            ok: detect_docker(runners.docker.as_ref()).is_some(),
            detail: detect_docker(runners.docker.as_ref())
                .unwrap_or_else(|| "docker unavailable".into()),
        },
        Check {
            label: "Listening ports",
            ok: detect_ports(procfs).is_some(),
            detail: detect_ports(procfs).unwrap_or_else(|| "none readable".into()),
        },
        Check {
            label: "Databases detected",
            ok: detect_databases(procfs).is_some(),
            detail: detect_databases(procfs).unwrap_or_else(|| "none".into()),
        },
        Check {
            label: "Scheduled jobs",
            ok: detect_cron(root).is_some(),
            detail: detect_cron(root).unwrap_or_else(|| "none".into()),
        },
        Check {
            label: "Firewall",
            ok: detect_firewall(root).is_some(),
            detail: detect_firewall(root).unwrap_or_else(|| "none".into()),
        },
        Check {
            label: "Cloud environment",
            ok: detect_cloud(root).is_some(),
            detail: detect_cloud(root).unwrap_or_else(|| "bare metal/unknown".into()),
        },
    ]
}

#[allow(dead_code)]
pub fn detect_distro(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("etc/os-release"))
        .or_else(|_| std::fs::read_to_string(root.join("os-release")))
        .ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
}

#[allow(dead_code)]
pub fn detect_systemd(_root: &Path, runner: &dyn CommandRunner) -> Option<String> {
    runner
        .run(&["is-system-running"])
        .ok()
        .map(|s| format!("systemd {}", s.trim()))
}

pub fn detect_docker(runner: &dyn CommandRunner) -> Option<String> {
    runner
        .run(&["ps", "-q"])
        .ok()
        .map(|_| "docker available".into())
}

pub fn detect_proxies(root: &Path) -> Option<String> {
    let mut found = Vec::new();
    for (path, name) in [
        ("etc/nginx/nginx.conf", "nginx"),
        ("etc/apache2/apache2.conf", "apache2"),
        ("etc/caddy/Caddyfile", "caddy"),
    ] {
        if root.join(path).is_file() {
            found.push(name);
        }
    }
    if found.is_empty() {
        None
    } else {
        Some(found.join(", "))
    }
}

pub fn detect_ssh(root: &Path) -> Option<String> {
    if root.join("etc/ssh/sshd_config").is_file() {
        Some("sshd_config present".into())
    } else {
        None
    }
}

pub fn detect_logs(root: &Path) -> Option<String> {
    let mut found = Vec::new();
    for d in ["var/log/nginx", "var/log/apache2", "var/log/syslog"] {
        if root.join(d).exists() {
            found.push(d.to_string());
        }
    }
    if found.is_empty() {
        None
    } else {
        Some(found.join(", "))
    }
}

pub fn detect_cron(root: &Path) -> Option<String> {
    if root.join("etc/cron.d").is_dir() || root.join("etc/crontab").is_file() {
        Some("cron configured".into())
    } else {
        None
    }
}

pub fn detect_firewall(root: &Path) -> Option<String> {
    let mut found = Vec::new();
    for (p, name) in [
        ("usr/sbin/ufw", "ufw"),
        ("usr/sbin/iptables", "iptables"),
        ("usr/sbin/nft", "nftables"),
    ] {
        if root.join(p).is_file() {
            found.push(name);
        }
    }
    if found.is_empty() {
        None
    } else {
        Some(found.join(", "))
    }
}

pub fn detect_cloud(root: &Path) -> Option<String> {
    let dmi =
        std::fs::read_to_string(root.join("sys/class/dmi/id/product_name")).unwrap_or_default();
    for (needle, name) in [
        ("Amazon EC2", "aws"),
        ("Google Compute Engine", "gcp"),
        ("Microsoft Corporation", "azure"),
        ("DigitalOcean", "digitalocean"),
    ] {
        if dmi.contains(needle) {
            return Some(name.into());
        }
    }
    if root.join("etc/cloud").is_dir() {
        return Some("cloud-init".into());
    }
    None
}

pub fn detect_ports(procfs: &crate::procfs::ProcFs) -> Option<String> {
    let entries = procfs.tcp_entries().ok()?;
    let mut ports: Vec<u16> = entries
        .iter()
        .filter(|e| e.state == "LISTEN")
        .map(|e| e.local_port)
        .collect();
    if ports.is_empty() {
        return None;
    }
    ports.sort_unstable();
    ports.dedup();
    Some(format!(
        "{} listening ports (e.g. {})",
        ports.len(),
        ports[0]
    ))
}

pub fn detect_databases(procfs: &crate::procfs::ProcFs) -> Option<String> {
    let entries = procfs.tcp_entries().ok()?;
    let listen: Vec<u16> = entries
        .iter()
        .filter(|e| e.state == "LISTEN")
        .map(|e| e.local_port)
        .collect();
    let mut found = Vec::new();
    for (port, name) in [(5432u16, "postgres"), (3306, "mysql"), (6379, "redis")] {
        if listen.contains(&port) {
            found.push(name);
        }
    }
    if found.is_empty() {
        None
    } else {
        Some(found.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discover")
    }

    #[test]
    fn detects_distro() {
        assert!(detect_distro(&root())
            .unwrap_or_default()
            .contains("Debian"));
    }

    #[test]
    fn detects_distro_from_etc() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discover");
        assert!(detect_distro(&root).unwrap_or_default().contains("Debian"));
    }

    #[test]
    fn falls_back_to_top_level_os_release() {
        let dir = std::env::temp_dir().join(format!("discover-fallback-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("os-release"), "PRETTY_NAME=\"Fallback OS\"\n").unwrap();
        assert_eq!(detect_distro(&dir).unwrap(), "Fallback OS");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_proxy_and_ssh_and_cron() {
        assert!(detect_proxies(&root())
            .unwrap_or_default()
            .contains("nginx"));
        assert!(detect_ssh(&root())
            .unwrap_or_default()
            .contains("sshd_config"));
        assert!(detect_cron(&root()).unwrap_or_default().contains("cron"));
    }

    #[test]
    fn detects_nothing_on_empty_root() {
        let empty = std::env::temp_dir().join(format!("discover-empty-{}", std::process::id()));
        std::fs::create_dir_all(empty.join("etc")).unwrap();
        assert!(detect_distro(&empty).is_none());
        assert!(detect_proxies(&empty).is_none());
        assert!(detect_ssh(&empty).is_none());
        std::fs::remove_dir_all(&empty).ok();
    }

    #[test]
    fn systemd_running_via_runner() {
        let runner = crate::cmd::FakeCli("running".to_string());
        assert!(detect_systemd(&root(), &runner).is_some());
        let runner = crate::cmd::FakeCli(String::new());
        assert!(
            detect_systemd(&root(), &runner).is_none(),
            "systemctl failure → not running"
        );
    }

    #[test]
    fn ports_and_databases_from_procfs() {
        let p = crate::procfs::ProcFs::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        assert!(detect_ports(&p).is_some());
        assert!(detect_databases(&p).is_none(), "fixture has no db ports");
    }

    #[test]
    fn docker_check_uses_docker_runner() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discover");
        let procfs = crate::procfs::ProcFs::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        );
        let runners = crate::cmd::Runners::with_fakes(
            Box::new(crate::cmd::FakeCli(String::new())),
            Box::new(crate::cmd::FakeCli(String::new())),
            Box::new(crate::cmd::FakeCli("x".into())),
            Box::new(crate::cmd::FakeCli(String::new())),
        );
        let checks = run_all(&root, &runners, &procfs);
        let docker = checks
            .iter()
            .find(|c| c.label == "Docker detected")
            .unwrap();
        assert!(
            docker.ok,
            "docker check must use the docker runner: {}",
            docker.detail
        );
    }
}
