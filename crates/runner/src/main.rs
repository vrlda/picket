use std::path::PathBuf;

use clap::{Parser, Subcommand};
use picket_runner::config::RunnerConfig;

#[derive(Parser)]
#[command(
    name = "picket-runner",
    version,
    about = "Runs Picket agent tasks (outbound HTTPS only)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Path to the runner config.
    #[arg(long, default_value = "/etc/picket/runner.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect and run tasks forever.
    Run,
    /// Validate the config, the workspaces, the agent CLI and the server
    /// connection, then exit.
    Check,
}

fn main() {
    let cli = Cli::parse();
    let cfg = match RunnerConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    match cli.cmd {
        Cmd::Run => picket_runner::run_forever(&cfg),
        Cmd::Check => {
            let mut ok = true;
            let mark = |good: bool| if good { "✓" } else { "✗" };
            for (name, p) in &cfg.profiles {
                let bin = if p.adapter == "command" {
                    p.command[0].clone()
                } else {
                    p.claude_bin.clone()
                };
                let found = std::process::Command::new(&bin)
                    .arg("--version")
                    .output()
                    .is_ok();
                let (repo_ok, repo) = if p.workspace.as_os_str().is_empty() {
                    (true, "no repository".to_string())
                } else {
                    let git = std::process::Command::new("git")
                        .arg("-C")
                        .arg(&p.workspace)
                        .args(["rev-parse", "--is-inside-work-tree"])
                        .output()
                        .is_ok_and(|o| o.status.success());
                    (
                        p.workspace.is_dir(),
                        format!(
                            "workspace {} ({})",
                            p.workspace.display(),
                            if git { "git" } else { "not a git repo" }
                        ),
                    )
                };
                println!(
                    "{} profile {name}: {repo} · {bin} {} · autonomy {:?} · production {:?}",
                    mark(repo_ok && found),
                    if found { "found" } else { "NOT FOUND" },
                    p.autonomy,
                    p.production,
                );
                ok &= repo_ok && found;
            }
            let mut hosts: Vec<&String> = cfg.hosts.keys().collect();
            hosts.sort();
            for h in hosts {
                let dest = cfg.ssh_dest(h);
                let reached = std::process::Command::new("ssh")
                    .args([
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "ConnectTimeout=10",
                        "-o",
                        "StrictHostKeyChecking=accept-new",
                        dest,
                        "true",
                    ])
                    .output()
                    .is_ok_and(|o| o.status.success());
                println!(
                    "{} host {h}: ssh {dest} {}",
                    mark(reached),
                    if reached {
                        "ok"
                    } else {
                        "FAILED (key-based ssh must work non-interactively)"
                    }
                );
                ok &= reached;
            }
            let client = picket_runner::Client::new(&cfg);
            let caps: Vec<String> = cfg.profiles.keys().cloned().collect();
            match client.register(&cfg.labels, &caps) {
                Ok(()) => println!("✓ connected to {} as {}", cfg.server_url, cfg.runner_id),
                Err(e) => {
                    println!("✗ cannot register with {}: {e}", cfg.server_url);
                    ok = false;
                }
            }
            std::process::exit(if ok { 0 } else { 1 });
        }
    }
}
