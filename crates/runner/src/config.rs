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
    pub profiles: HashMap<String, Profile>,
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
    /// Repository the agent works on.
    pub workspace: PathBuf,
    pub autonomy: Autonomy,
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
            if p.workspace.as_os_str().is_empty() {
                return Err(format!("profile {name}: workspace is required"));
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
            "#,
        )
        .unwrap();
        cfg.validate().unwrap();
        let p = &cfg.profiles["payment_api"];
        assert_eq!(p.adapter, "claude-code");
        assert_eq!(p.autonomy, Autonomy::Patch);
        assert_eq!(p.isolation, Isolation::Worktree);
        assert_eq!(p.timeout_secs, 1800);
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
