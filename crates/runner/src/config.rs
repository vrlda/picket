//! Runner configuration (runner.toml). Everything about HOW an agent runs
//! lives here, on the machine that runs it — the Watchtower server only
//! names a profile.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RunnerConfig {
    /// Watchtower control plane, e.g. https://watchtower.example.com
    pub server_url: String,
    /// Must match a `[runners.<id>]` entry on the server.
    pub runner_id: String,
    /// The runner token from that entry.
    pub token: String,
    /// Reported to the server (routing uses the server-side labels).
    pub labels: Vec<String>,
    /// Long-poll duration per request.
    pub poll_timeout_secs: u64,
    /// Worktrees and logs live here.
    pub work_dir: PathBuf,
    /// Production hosts by Watchtower host id: how the agent reaches them
    /// over SSH. A host without an entry is reached as `ssh <host_id>`
    /// (an alias in ~/.ssh/config works).
    pub hosts: HashMap<String, Host>,
    pub profiles: HashMap<String, Profile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Host {
    /// ssh destination, e.g. "root@203.0.113.10" or a ~/.ssh/config alias.
    pub ssh: String,
}

impl RunnerConfig {
    /// ssh destination for a Watchtower host id.
    pub fn ssh_dest<'a>(&'a self, host_id: &'a str) -> &'a str {
        self.hosts
            .get(host_id)
            .map(|h| h.ssh.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(host_id)
    }
}

impl Default for RunnerConfig {
    fn default() -> Self {
        RunnerConfig {
            server_url: String::new(),
            runner_id: String::new(),
            token: String::new(),
            labels: Vec::new(),
            poll_timeout_secs: 30,
            work_dir: PathBuf::from("watchtower-runner"),
            hosts: HashMap::new(),
            profiles: HashMap::new(),
        }
    }
}

/// What the agent may do. Enforced by tool permissions and post-run checks
/// on the runner, and stated in the prompt — not by the prompt alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Autonomy {
    /// Read-only: inspect code, Watchtower and diagnostics. No changes.
    #[default]
    Investigate,
    /// Modify code and run tests (isolated worktree, nothing committed).
    Patch,
    /// Patch, then commit on the task branch.
    Commit,
    /// Commit and deploy using the procedure the repository documents.
    Deploy,
}

impl Autonomy {
    pub fn modifies(self) -> bool {
        self != Autonomy::Investigate
    }
}

/// What the agent may do on the production hosts (over SSH). Independent
/// of `autonomy`, which governs the code repository.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Production {
    /// No host access.
    None,
    /// Read-only diagnostics on the hosts.
    Diagnose,
    /// Diagnose and fix operational problems on the hosts (restart
    /// services, free disk, revert a bad config change, ...).
    #[default]
    Remediate,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// A git worktree on branch `watchtower/<task>` per task (default).
    #[default]
    Worktree,
    /// Work directly in `workspace`.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    /// "claude-code" (preset) or "command".
    pub adapter: String,
    /// Repository the agent works on. Empty = no repository: the agent
    /// works on the hosts over SSH from a scratch directory.
    pub workspace: PathBuf,
    /// What the agent may do in the repository.
    pub autonomy: Autonomy,
    /// What the agent may do on the production hosts.
    pub production: Production,
    pub isolation: Isolation,
    pub timeout_secs: u64,
    /// Extra instructions appended to the built-in prompt.
    pub prompt_file: Option<PathBuf>,
    /// Globs (relative to the repo) the agent must not change; touching
    /// them turns the result into a human escalation.
    pub blocked_paths: Vec<String>,
    /// Globs whose changes need a human's approval before use.
    pub require_human_approval_paths: Vec<String>,
    /// command adapter: argv; the prompt arrives on stdin and in
    /// $WATCHTOWER_PROMPT_FILE.
    pub command: Vec<String>,
    /// claude-code adapter: executable (default "claude").
    pub claude_bin: String,
    /// claude-code adapter: --allowedTools override.
    pub allowed_tools: Vec<String>,
    /// claude-code adapter: --model.
    pub model: String,
    /// Extra arguments appended to the adapter command.
    pub extra_args: Vec<String>,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            adapter: "claude-code".into(),
            workspace: PathBuf::new(),
            autonomy: Autonomy::Investigate,
            production: Production::Remediate,
            isolation: Isolation::Worktree,
            timeout_secs: 1800,
            prompt_file: None,
            blocked_paths: Vec::new(),
            require_human_approval_paths: Vec::new(),
            command: Vec::new(),
            claude_bin: "claude".into(),
            allowed_tools: Vec::new(),
            model: String::new(),
            extra_args: Vec::new(),
        }
    }
}

impl RunnerConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let cfg: RunnerConfig =
            toml::from_str(&text).map_err(|e| format!("invalid {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.server_url.is_empty() || self.runner_id.is_empty() || self.token.is_empty() {
            return Err("server_url, runner_id and token are required".into());
        }
        let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"];
        if !self.server_url.starts_with("https://")
            && !local.iter().any(|p| self.server_url.starts_with(p))
        {
            return Err("server_url must use https (http only for localhost)".into());
        }
        if self.profiles.is_empty() {
            return Err("configure at least one [profiles.<name>]".into());
        }
        for (name, p) in &self.profiles {
            match p.adapter.as_str() {
                "claude-code" => {}
                "command" if !p.command.is_empty() => {}
                "command" => {
                    return Err(format!("profile {name}: command adapter needs `command`"))
                }
                other => return Err(format!("profile {name}: unknown adapter {other:?}")),
            }
            for g in p
                .blocked_paths
                .iter()
                .chain(&p.require_human_approval_paths)
            {
                glob::Pattern::new(g)
                    .map_err(|e| format!("profile {name}: bad glob {g:?}: {e}"))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let cfg: RunnerConfig = toml::from_str(
            r#"
            server_url = "https://watchtower.example.com"
            runner_id = "home-mac"
            token = "t"
            labels = ["payments"]
            [profiles.payment_api]
            workspace = "/Users/dan/code/payment-platform"
            autonomy = "patch"
            blocked_paths = ["src/ledger/**"]
            [profiles.custom]
            adapter = "command"
            command = ["my-agent", "--json"]
            workspace = "/srv/app"
            [profiles.ops]
            production = "diagnose"
            [hosts.web-1]
            ssh = "root@203.0.113.10"
            "#,
        )
        .unwrap();
        cfg.validate().unwrap();
        let p = &cfg.profiles["payment_api"];
        assert_eq!(p.adapter, "claude-code");
        assert_eq!(p.autonomy, Autonomy::Patch);
        assert_eq!(p.isolation, Isolation::Worktree);
        assert_eq!(p.timeout_secs, 1800);
        assert_eq!(
            p.production,
            Production::Remediate,
            "host access by default"
        );
        let ops = &cfg.profiles["ops"];
        assert!(ops.workspace.as_os_str().is_empty(), "no repository needed");
        assert_eq!(ops.production, Production::Diagnose);
        assert_eq!(cfg.ssh_dest("web-1"), "root@203.0.113.10");
        assert_eq!(
            cfg.ssh_dest("db-1"),
            "db-1",
            "unknown hosts use ssh aliases"
        );
    }

    #[test]
    fn rejects_plain_http_and_bad_profiles() {
        let mut cfg = RunnerConfig {
            server_url: "http://watchtower.example.com".into(),
            runner_id: "r".into(),
            token: "t".into(),
            ..Default::default()
        };
        cfg.profiles.insert(
            "p".into(),
            Profile {
                workspace: "/x".into(),
                ..Default::default()
            },
        );
        assert!(cfg.validate().unwrap_err().contains("https"));
        cfg.server_url = "http://127.0.0.1:8787".into();
        cfg.validate().unwrap();
        cfg.profiles.insert(
            "c".into(),
            Profile {
                adapter: "command".into(),
                workspace: "/x".into(),
                ..Default::default()
            },
        );
        assert!(cfg.validate().unwrap_err().contains("command"));
    }
}
