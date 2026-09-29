use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "watchtower-server", version)]
struct Cli {
    /// Path to config file.
    #[arg(long, default_value = "/etc/watchtower/server.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let cfg = watchtower_server::config::load(&cli.config);
    if cfg.auth_token.is_empty() {
        eprintln!("server config: auth_token is empty — refusing to run without auth");
        std::process::exit(1);
    }
    let pool = match watchtower_server::db::connect(&cfg).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("db connect failed: {e}");
            std::process::exit(1);
        }
    };
    let mut state = watchtower_server::app::AppState::new(pool, cfg.clone()).await;
    watchtower_server::probes::spawn_probe_tasks(state.clone(), cfg.probes.clone());
    watchtower_server::correlation::spawn_runner(state.clone());
    watchtower_server::watchdog::spawn_watchdog(state.clone());
    watchtower_server::notify::spawn_retry_loop(state.clone());
    tokio::spawn(watchtower_server::notify::start_telegram(state.clone()));
    if let Some(rx) = state.notify_rx.take() {
        watchtower_server::notifier::spawn_notifier(state.clone(), rx);
    }
    let app = watchtower_server::app::build_app(state).await;
    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("bind {} failed: {e}", cfg.listen);
            std::process::exit(1);
        });
    eprintln!(
        "watchtower-server {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        cfg.listen
    );
    axum::serve(listener, app).await.unwrap();
}
