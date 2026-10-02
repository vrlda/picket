//! Postgres integration (CI only): schema init + ingest round-trip against a
//! real postgres. Runs via `cargo test -p watchtower-server --features ci-postgres -- --ignored`.

#![cfg(feature = "ci-postgres")]

use watchtower_server::config::ServerConfig;

#[tokio::test]
#[ignore]
async fn postgres_schema_and_round_trip() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL for the ci postgres service");
    let cfg = ServerConfig {
        db_url: url,
        auth_token: "test".into(),
        ..Default::default()
    };
    let pool = watchtower_server::db::connect(&cfg).await.expect("connect");
    watchtower_server::db::init_schema(&pool)
        .await
        .expect("schema");
    let ev = wt_common::AgentEvent {
        id: "pg-e1".into(),
        ts: 1_000,
        host_id: "h-pg".into(),
        key: "k".into(),
        kind: wt_common::EventKind::ServiceFailed,
        severity: wt_common::Severity::Critical,
        summary: "pg test".into(),
        evidence: vec![],
        ..Default::default()
    };
    watchtower_server::ingest::store_events(&pool, &[ev])
        .await
        .expect("store");
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM events WHERE id = 'pg-e1'")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1);
    // dedup: same id again → still 1
    let ev2 = wt_common::AgentEvent {
        id: "pg-e1".into(),
        ts: 1_000,
        host_id: "h-pg".into(),
        key: "k".into(),
        kind: wt_common::EventKind::ServiceFailed,
        severity: wt_common::Severity::Critical,
        summary: "pg test".into(),
        evidence: vec![],
        ..Default::default()
    };
    watchtower_server::ingest::store_events(&pool, &[ev2])
        .await
        .expect("store again");
    let (n2,): (i64,) = sqlx::query_as("SELECT count(*) FROM events WHERE id = 'pg-e1'")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n2, 1, "ON CONFLICT DO NOTHING dedups");
    // incidents round-trip too (link_events is the other OR IGNORE site)
    let inc = watchtower_server::incidents::create_incident(
        &pool,
        "pg-key",
        "h-pg",
        "Critical",
        "head",
        "cause",
        &[],
        &[],
    )
    .await
    .expect("incident");
    let ev3 = wt_common::AgentEvent {
        id: "pg-e2".into(),
        ts: 1_000,
        host_id: "h-pg".into(),
        key: "k2".into(),
        kind: wt_common::EventKind::CpuSpike,
        severity: wt_common::Severity::Warning,
        summary: "s".into(),
        evidence: vec![],
        ..Default::default()
    };
    watchtower_server::incidents::link_events(&pool, &inc.id, &[ev3])
        .await
        .expect("link");
    let got = watchtower_server::incidents::fetch_incident(&pool, &inc.id)
        .await
        .expect("fetch")
        .expect("incident");
    assert_eq!(got.timeline.len(), 1);
}
