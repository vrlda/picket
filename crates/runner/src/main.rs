use std::path::PathBuf;

use clap::{Parser, Subcommand};
use watchtower_runner::config::RunnerConfig;

#[derive(Parser)]
#[command(
    name = "watchtower-runner",
    version,
    about = "Runs Watchtower agent tasks (outbound HTTPS only)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Path to the runner config.
    #[arg(long, default_value = "/etc/watchtower/runner.toml")]
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
        Cmd::Run => watchtower_runner::run_forever(&cfg),
        Cmd::Check => {
            let mut ok = true;
            for (name, p) in &cfg.profiles {
                let git = std::process::Command::new("git")
                    .arg("-C")
                    .arg(&p.workspace)
                    .args(["rev-parse", "--is-inside-work-tree"])
                    .output()
                    .is_ok_and(|o| o.status.success());
                let bin = if p.adapter == "command" {
                    p.command[0].clone()
                } else {
                    p.claude_bin.clone()
                };
                let found = std::process::Command::new(&bin)
                    .arg("--version")
                    .output()
                    .is_ok();
                println!(
                    "{} profile {name}: workspace {} ({}) · {} {} · autonomy {:?}",
                    if p.workspace.is_dir() && found {
                        "✓"
                    } else {
                        "✗"
                    },
                    p.workspace.display(),
                    if git { "git" } else { "not a git repo" },
                    bin,
                    if found { "found" } else { "NOT FOUND" },
                    p.autonomy,
                );
                ok &= p.workspace.is_dir() && found;
            }
            let client = watchtower_runner::Client::new(&cfg);
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
