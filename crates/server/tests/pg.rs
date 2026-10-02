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
        kind: wt_common::EventKind::ServiceFailed.into(),
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
        kind: wt_common::EventKind::ServiceFailed.into(),
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
        kind: wt_common::EventKind::CpuSpike.into(),
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

/// The custom-event + autonomy SQL on postgres: context columns, attribute
/// filters (jsonb), threshold scan, task dispatch (partial unique index),
/// claim/complete and the recovery pass.
#[tokio::test]
#[ignore]
async fn postgres_custom_events_and_agent_tasks() {
    use serde_json::json;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL for the ci postgres service");
    let rule: watchtower_server::correlation::Rule = toml::from_str(
        r#"
        id = "pg_merchant_failures"
        trigger = "pg.request_failed"
        count = 3
        window_secs = 600
        group_by = ["attributes.merchant_id"]
        severity = "Critical"
        headline = "failures for {attributes.merchant_id}"
        [recovery]
        window_secs = 1
        [[dispatch]]
        type = "agent"
        profile = "p"
        "#,
    )
    .unwrap();
    let mut cfg = ServerConfig {
        db_url: url,
        auth_token: "test".into(),
        rules: vec![rule],
        ..Default::default()
    };
    cfg.runners.insert(
        "r1".into(),
        watchtower_server::dispatch::RunnerConfig {
            token: "rt".into(),
            labels: vec![],
        },
    );
    cfg.agent_profiles.insert(
        "p".into(),
        watchtower_server::dispatch::AgentProfile {
            runner: "r1".into(),
            ..Default::default()
        },
    );
    let pool = watchtower_server::db::connect(&cfg).await.expect("connect");
    let state = watchtower_server::app::AppState::new(pool.clone(), cfg).await;
    let now = watchtower_server::ingest::now_ms();
    let run = uuid_like(now);
    let merchant = format!("mer_{run}");
    for i in 0..3 {
        let mut ev = wt_common::AgentEvent {
            id: format!("pg-{run}-{i}"),
            ts: now - 5_000 + i,
            host_id: "payment-api".into(),
            key: format!("merchant:{merchant}"),
            kind: wt_common::EventType::parse("pg.request_failed").unwrap(),
            severity: wt_common::Severity::Warning,
            summary: "failed".into(),
            source: "payment-api".into(),
            subject: format!("merchant:{merchant}"),
            ..Default::default()
        };
        ev.attributes.insert("merchant_id".into(), json!(merchant));
        ev.attributes.insert("status_code".into(), json!(502));
        ev.measurements.insert("latency_ms".into(), 812.0);
        watchtower_server::ingest::store_events(&pool, &[ev])
            .await
            .expect("store");
    }
    let mut params = std::collections::HashMap::new();
    params.insert(format!("attr.merchant_id"), merchant.clone());
    params.insert("attr.status_code".into(), "502".into());
    let q = watchtower_server::events::EventQuery::from_params(&params).unwrap();
    let found = watchtower_server::events::fetch_events(&pool, &q)
        .await
        .expect("attr query");
    assert_eq!(found.len(), 3, "jsonb attribute filters");
    assert_eq!(found[0]["measurements"]["latency_ms"], 812.0);

    let changed = watchtower_server::correlation::scan_and_absorb(&pool, &state.rules, now)
        .await
        .expect("scan");
    let inc = changed
        .into_iter()
        .find(|i| i.key.ends_with(&merchant))
        .expect("threshold incident");
    assert_eq!(inc.rule_id, "pg_merchant_failures");
    let first = watchtower_server::agent_tasks::dispatch_agent(&state, &inc, "p")
        .await
        .expect("dispatch");
    assert!(matches!(
        first,
        watchtower_server::agent_tasks::DispatchOutcome::Created(_)
    ));
    let again = watchtower_server::agent_tasks::dispatch_agent(&state, &inc, "p")
        .await
        .expect("dispatch 2");
    assert_eq!(
        again,
        watchtower_server::agent_tasks::DispatchOutcome::AlreadyActive
    );
    let claimed = watchtower_server::agent_tasks::claim_next(&state, "r1")
        .await
        .expect("claim")
        .expect("a task");
    watchtower_server::agent_tasks::mark_started(&state, &claimed.task_id, "r1", "test")
        .await
        .unwrap();
    let status = watchtower_server::agent_tasks::complete(
        &state,
        &claimed.task_id,
        "r1",
        watchtower_server::agent_tasks::AgentResult {
            outcome: "fixed".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(status, "awaiting_verification");
    watchtower_server::agent_tasks::sweep(&state, now + 10_000)
        .await
        .expect("sweep");
    let inc = watchtower_server::incidents::fetch_incident(&pool, &inc.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        inc.status,
        watchtower_server::incidents::IncidentStatus::Resolved
    );
    let task = watchtower_server::agent_tasks::get_task(&pool, &claimed.task_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.status, "succeeded");
}

/// Unique-per-run suffix (the CI database is shared across runs).
fn uuid_like(now: i64) -> String {
    format!("{now:x}{}", std::process::id())
}
