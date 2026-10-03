use std::collections::{HashMap, HashSet};

use crate::journald::JournalLine;
use picket_common::Severity;

#[derive(Debug, Clone, PartialEq)]
pub enum AuthKind {
    SshLogin,
    SshFailed,
    RootLogin,
    SudoUsed,
}

/// One classified auth-related journal line.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthEvent {
    pub kind: AuthKind,
    pub user: String,
    pub ip: String,
    pub detail: String,
}

/// Classify a journal line into an auth event, or None for unrelated lines.
/// Recognized message shapes (sshd, sudo, su) mirror the fixture set.
pub fn classify(line: &JournalLine) -> Option<AuthEvent> {
    let msg = line.message.as_str();
    match line.ident.as_str() {
        "sshd" => {
            // NOTE: "pam_unix(sshd:session): session opened for user X" lines
            // are intentionally NOT classified — they fire alongside every
            // successful login ("Accepted ...") and would double-count.
            if let Some(rest) = msg.strip_prefix("Accepted ") {
                let (user, ip) = parse_user_ip(rest)?;
                let kind = if user == "root" {
                    AuthKind::RootLogin
                } else {
                    AuthKind::SshLogin
                };
                Some(AuthEvent {
                    kind,
                    user: user.to_string(),
                    ip: ip.to_string(),
                    detail: msg.to_string(),
                })
            } else if let Some(rest) = msg.strip_prefix("Failed password") {
                let (user, ip) = parse_user_ip(rest)?;
                Some(AuthEvent {
                    kind: AuthKind::SshFailed,
                    user: user.to_string(),
                    ip: ip.to_string(),
                    detail: msg.to_string(),
                })
            } else if let Some(rest) = msg.strip_prefix("Failed keyboard-interactive") {
                let (user, ip) = parse_user_ip(rest)?;
                Some(AuthEvent {
                    kind: AuthKind::SshFailed,
                    user: user.to_string(),
                    ip: ip.to_string(),
                    detail: msg.to_string(),
                })
            } else if let Some(rest) =
                msg.strip_prefix("error: maximum authentication attempts exceeded")
            {
                let (user, ip) = parse_user_ip(rest)?;
                Some(AuthEvent {
                    kind: AuthKind::SshFailed,
                    user: user.to_string(),
                    ip: ip.to_string(),
                    detail: msg.to_string(),
                })
            } else {
                None
            }
        }
        "sudo" => {
            if let Some(idx) = msg.find(" : ") {
                let user = &msg[..idx];
                if let Some(cmd) = msg.split("COMMAND=").nth(1) {
                    if !user.is_empty() && !cmd.is_empty() {
                        return Some(AuthEvent {
                            kind: AuthKind::SudoUsed,
                            user: user.to_string(),
                            ip: String::new(),
                            detail: msg.to_string(),
                        });
                    }
                }
            }
            None
        }
        "su" => {
            if msg.contains("pam_unix(su:session): session opened for user root") {
                Some(AuthEvent {
                    kind: AuthKind::RootLogin,
                    user: "root".into(),
                    ip: String::new(),
                    detail: msg.to_string(),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// "<method> for <user> from <ip> port <port> ..." — returns (user, ip).
/// Handles both shapes: "<method> for <user> ..." (Accepted) and
/// "for <user> ..." (Failed — the method token was the stripped prefix).
/// Handles the "invalid user X" shape (bots): the "invalid user " prefix is
/// stripped so brute-force keying and first-seen tracking use the real name.
/// The strip is inert on Accepted lines — a nonexistent user can never log in
/// successfully.
fn parse_user_ip(rest: &str) -> Option<(&str, &str)> {
    let (user, tail) = if let Some(t) = rest.trim_start().strip_prefix("for ") {
        let (user, tail) = t.split_once(" from ")?;
        (user, tail)
    } else {
        let (_, after_for) = rest.split_once(" for ")?;
        let (user, tail) = after_for.split_once(" from ")?;
        (user, tail)
    };
    let ip = tail.split(" port ").next()?;
    let user = user.strip_prefix("invalid user ").unwrap_or(user);
    if user.is_empty() || ip.is_empty() {
        return None;
    }
    Some((user, ip))
}

/// First-seen source IP tracking. Seeded from persisted state at startup and
/// synced back periodically (see AgentState::sync_persisted).
#[derive(Default)]
pub struct SeenIps {
    ips: HashSet<String>,
}

impl SeenIps {
    pub fn is_first(&mut self, ip: &str) -> bool {
        self.ips.insert(ip.to_string())
    }

    /// Seed the set from persisted state (restored on startup).
    pub fn extend(&mut self, ips: impl IntoIterator<Item = String>) {
        self.ips.extend(ips);
    }

    /// Snapshot of the set for persistence (sorted for deterministic output).
    pub fn all(&self) -> Vec<String> {
        let mut v: Vec<String> = self.ips.iter().cloned().collect();
        v.sort();
        v
    }
}

/// Brute-force episode detection per (user, ip): failures within a window;
/// at threshold the episode fires and resets.
pub struct BruteForceTracker {
    threshold: u32,
    window_secs: u64,
    failures: HashMap<(String, String), Vec<i64>>,
}

impl BruteForceTracker {
    pub fn new(threshold: u32, window_secs: u64) -> Self {
        BruteForceTracker {
            threshold,
            window_secs,
            failures: HashMap::new(),
        }
    }

    /// Record a failure at ts_ms. Returns (episode_completed, count_in_window).
    pub fn observe_failure(&mut self, user: &str, ip: &str, ts_ms: i64) -> (bool, usize) {
        let key = (user.to_string(), ip.to_string());
        let list = self.failures.entry(key.clone()).or_default();
        list.push(ts_ms);
        list.retain(|t| *t + (self.window_secs as i64) * 1000 >= ts_ms);
        if list.len() >= self.threshold as usize {
            let count = list.len();
            self.failures.remove(&key);
            (true, count)
        } else {
            (false, list.len())
        }
    }
}

/// Severity helpers for auth events. Login severity is decided by the caller
/// at construction (SshLogin=Info, RootLogin=Warning); suggest_severity only
/// escalates when the source IP is new (Critical cap).
pub fn base_ssh_event(user: &str, ip: &str, sev: Severity) -> SshEventBuilder {
    SshEventBuilder {
        user: user.to_string(),
        ip: ip.to_string(),
        sev,
    }
}

pub struct SshEventBuilder {
    // stored for callers that want them; severity escalation is sev-only
    #[allow(dead_code)]
    pub user: String,
    #[allow(dead_code)]
    pub ip: String,
    pub sev: Severity,
}

impl SshEventBuilder {
    /// Pure — no mutation of any tracker. Escalate one level on a new
    /// source IP, capped at Critical.
    pub fn suggest_severity(&self, ip_is_new: bool) -> Severity {
        if !ip_is_new {
            return self.sev;
        }
        match self.sev {
            Severity::Info => Severity::Warning,
            Severity::Warning => Severity::Critical,
            Severity::Critical => Severity::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_common::Severity;

    fn line(ts_ms: i64, ident: &str, msg: &str) -> JournalLine {
        JournalLine {
            ts_ms,
            ident: ident.into(),
            pid: 0,
            message: msg.into(),
        }
    }

    #[test]
    fn classifies_accepted_login() {
        let l = line(
            1000,
            "sshd",
            "Accepted publickey for deploy from 198.51.100.24 port 51234 ssh2: RSA",
        );
        let ev = classify(&l).expect("classified");
        assert_eq!(ev.kind, AuthKind::SshLogin);
        assert_eq!(ev.user, "deploy");
        assert_eq!(ev.ip, "198.51.100.24");
    }

    #[test]
    fn classifies_failed_password() {
        let l = line(
            1000,
            "sshd",
            "Failed password for root from 203.0.113.7 port 40000 ssh2",
        );
        let ev = classify(&l).expect("classified");
        assert_eq!(ev.kind, AuthKind::SshFailed);
        assert_eq!(ev.user, "root");
        assert_eq!(ev.ip, "203.0.113.7");
    }

    #[test]
    fn classifies_invalid_user_failure() {
        let l = line(
            1000,
            "sshd",
            "Failed password for invalid user root from 203.0.113.7 port 40002 ssh2",
        );
        let ev = classify(&l).expect("classified");
        assert_eq!(ev.kind, AuthKind::SshFailed);
        assert_eq!(ev.user, "root"); // "invalid user " prefix stripped
        assert_eq!(ev.ip, "203.0.113.7");
    }

    #[test]
    fn classifies_max_attempts_as_failed() {
        let l = line(1000, "sshd", "error: maximum authentication attempts exceeded for root from 203.0.113.7 port 40001 ssh2");
        let ev = classify(&l).expect("classified");
        assert_eq!(ev.kind, AuthKind::SshFailed);
        assert_eq!(ev.user, "root");
        assert_eq!(ev.ip, "203.0.113.7");
    }

    #[test]
    fn classifies_keyboard_interactive_failure() {
        let l = line(
            1000,
            "sshd",
            "Failed keyboard-interactive for deploy from 198.51.100.24 port 51236 ssh2",
        );
        let ev = classify(&l).expect("classified");
        assert_eq!(ev.kind, AuthKind::SshFailed);
        assert_eq!(ev.user, "deploy");
        assert_eq!(ev.ip, "198.51.100.24");
    }

    #[test]
    fn classifies_root_login() {
        let l = line(
            1000,
            "sshd",
            "Accepted password for root from 198.51.100.24 port 51235 ssh2",
        );
        let ev = classify(&l).expect("classified");
        assert_eq!(ev.kind, AuthKind::RootLogin);
        assert_eq!(ev.user, "root");
    }

    #[test]
    fn classifies_sudo() {
        let l = line(1000, "sudo", "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart nginx");
        let ev = classify(&l).expect("classified");
        assert_eq!(ev.kind, AuthKind::SudoUsed);
        assert_eq!(ev.user, "deploy");
        assert!(ev.detail.contains("systemctl restart nginx"));
    }

    #[test]
    fn classifies_su_to_root() {
        let l = line(
            1000,
            "su",
            "pam_unix(su:session): session opened for user root by (uid=1000)",
        );
        let ev = classify(&l).expect("classified");
        assert_eq!(ev.kind, AuthKind::RootLogin);
        assert_eq!(ev.user, "root");
    }

    #[test]
    fn ignores_sshd_session_opened() {
        let l = line(
            1000,
            "sshd",
            "pam_unix(sshd:session): session opened for user deploy by (uid=1000)",
        );
        assert!(classify(&l).is_none());
    }

    #[test]
    fn ignores_unrelated_lines() {
        let l = line(1000, "cron", "(root) CMD ( /usr/lib/atop/atop.daily )");
        assert!(classify(&l).is_none());
        let l = line(
            1000,
            "sshd",
            "Received disconnect from 198.51.100.24 port 51234:11",
        );
        assert!(classify(&l).is_none());
    }

    #[test]
    fn first_seen_and_root_escalate_severity() {
        let login = base_ssh_event("deploy", "198.51.100.24", Severity::Info);
        assert_eq!(login.suggest_severity(true), Severity::Warning); // first-seen login
        assert_eq!(login.suggest_severity(false), Severity::Info); // known ip

        let root = base_ssh_event("root", "198.51.100.24", Severity::Warning);
        assert_eq!(root.suggest_severity(true), Severity::Critical);
        assert_eq!(root.suggest_severity(false), Severity::Warning);
        let crit = base_ssh_event("root", "198.51.100.24", Severity::Critical);
        assert_eq!(crit.suggest_severity(true), Severity::Critical);
    }

    #[test]
    fn seen_ips_tracks_uniqueness() {
        let mut seen = SeenIps::default();
        assert!(seen.is_first("198.51.100.24"));
        assert!(!seen.is_first("198.51.100.24"));
        assert!(seen.is_first("203.0.113.7"));
    }

    #[test]
    fn brute_force_triggers_episode_at_threshold() {
        let mut bf = BruteForceTracker::new(5, 300);
        assert!(!bf.observe_failure("root", "203.0.113.7", 1000).0);
        assert!(!bf.observe_failure("root", "203.0.113.7", 1010).0);
        assert!(!bf.observe_failure("root", "203.0.113.7", 1020).0);
        assert!(!bf.observe_failure("root", "203.0.113.7", 1030).0);
        let (triggered, count) = bf.observe_failure("root", "203.0.113.7", 1040);
        assert!(triggered);
        assert_eq!(count, 5);
        let (triggered, _) = bf.observe_failure("deploy", "203.0.113.7", 1050);
        assert!(!triggered);
    }

    #[test]
    fn brute_force_prunes_outside_window() {
        let mut bf = BruteForceTracker::new(2, 10);
        assert!(!bf.observe_failure("root", "1.1.1.1", 1000).0);
        assert!(!bf.observe_failure("root", "1.1.1.1", 12000).0); // 1000 pruned (1000+10000 < 12000)
        assert!(!bf.observe_failure("root", "1.1.1.1", 23000).0); // 12000 pruned (12000+10000 < 23000)
    }
}
