use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "picket-server", version)]
struct Cli {
    /// Path to config file.
    #[arg(long, default_value = "/etc/picket/server.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let cfg = picket_server::config::load(&cli.config);
    if cfg.auth_token.is_empty() {
        eprintln!("server config: auth_token is empty — refusing to run without auth");
        std::process::exit(1);
    }
    let pool = match picket_server::db::connect(&cfg).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("db connect failed: {e}");
            std::process::exit(1);
        }
    };
    let state = picket_server::app::AppState::new(pool, cfg.clone()).await;
    picket_server::probes::spawn_probe_tasks(state.clone(), cfg.probes.clone());
    picket_server::correlation::spawn_runner(state.clone());
    picket_server::watchdog::spawn_watchdog(state.clone());
    picket_server::notify::spawn_retry_loop(state.clone());
    picket_server::agent_tasks::spawn_sweeper(state.clone());
    tokio::spawn(picket_server::notify::start_telegram(state.clone()));
    if let Some(rx) = state.take_notify_rx() {
        picket_server::notifier::spawn_notifier(state.clone(), rx);
    }
    let app = picket_server::app::build_app(state).await;
    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("bind {} failed: {e}", cfg.listen);
            std::process::exit(1);
        });
    eprintln!(
        "picket-server {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        cfg.listen
    );
    axum::serve(listener, app).await.unwrap();
}
