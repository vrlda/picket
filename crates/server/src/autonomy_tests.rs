//! End-to-end tests of the autonomous-response path: custom events →
//! threshold rules → incidents → agent tasks → runner protocol → results →
//! verified recovery. Uses the real router (tower oneshot) and the real
//! correlation scan with explicit clocks.

use axum::http::StatusCode;
use serde_json::{json, Value};

use crate::app::{build_app, AppState};
use crate::correlation::{merged_rules, scan_and_absorb, Rule};
use crate::dispatch::{AgentProfile, RunnerConfig};

const RULES: &str = r#"
[[rule]]
id = "merchant_failures"
trigger = "payment.request_failed"
count = 5
window_secs = 120
group_by = ["attributes.merchant_id"]
severity = "Critical"
headline = "Payment failures for merchant {attributes.merchant_id} ({count} in window)"
cause = "Repeated payment failures exceeded threshold."
recommended_actions = ["Inspect recent failed requests"]
[rule.recovery]
window_secs = 60
[[rule.dispatch]]
type = "agent"
profile = "payment_api"
[[rule.dispatch]]
type = "notify"
channel = "telegram"
policy = "on_agent_failure"

[[rule]]
id = "conversion_low"
trigger = "payment.conversion_sample"
group_by = ["attributes.merchant_id"]
severity = "Warning"
headline = "Conversion {measurements.conversion_rate} for {attributes.merchant_id}"
[[rule.where]]
field = "measurements.attempts"
op = ">="
value = 100
[[rule.where]]
field = "measurements.conversion_rate"
op = "<"
value = 0.70
"#;

#[derive(serde::Deserialize)]
struct RulesFile {
    rule: Vec<Rule>,
}

async fn state() -> AppState {
    let mut s = AppState::for_tests().await;
    let rules: RulesFile = toml::from_str(RULES).unwrap();
    s.cfg.rules = rules.rule;
    s.rules = merged_rules(&s.cfg.rules);
    s.cfg.runners.insert(
        "home-mac".into(),
        RunnerConfig {
            token: "runner-token".into(),
            labels: vec!["payments".into()],
        },
    );
    s.cfg.runners.insert(
        "other".into(),
        RunnerConfig {
            token: "other-token".into(),
            labels: vec!["marketing".into()],
        },
    );
    s.cfg.agent_profiles.insert(
        "payment_api".into(),
        AgentProfile {
            labels: vec!["payments".into()],
            max_attempts: 2,
            lease_secs: 60,
            ..Default::default()
        },
    );
    s
}

fn failure(id: &str, ts: i64, merchant: &str) -> wt_common::AgentEvent {
    crate::custom_events::build_event(
        serde_json::from_value(json!({
            "id": id,
            "ts": ts,
            "kind": "payment.request_failed",
            "source": "payment-api",
            "environment": "production",
            "subject": format!("merchant:{merchant}"),
            "summary": "Payment creation failed",
            "severity": "warning",
            "attributes": { "merchant_id": merchant, "authorization": "Bearer sk_live_secret" }
        }))
        .unwrap(),
        None,
        None,
        ts,
    )
    .unwrap()
}

async fn store(s: &AppState, evs: &[wt_common::AgentEvent]) {
    crate::ingest::store_events(&s.pool, evs).await.unwrap();
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let body = body.map(|b| b.to_string());
    crate::test_util::call(app, method, uri, Some(token), body.as_deref()).await
}

async fn task_count(s: &AppState) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM agent_tasks")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    n
}

/// Incidents from one scan, then their agent dispatch (what the scan loop does).
async fn scan(s: &AppState, now: i64) -> Vec<crate::incidents::Incident> {
    let changed = scan_and_absorb(&s.pool, &s.rules, now).await.unwrap();
    for inc in &changed {
        crate::agent_tasks::dispatch_for_incident(s, inc).await;
    }
    changed
}

/// Test clock origin: just behind real time, because task timestamps
/// (finished_at, created_at) use the real clock.
static T0: std::sync::LazyLock<i64> =
    std::sync::LazyLock::new(|| crate::ingest::now_ms() - 600_000);

#[tokio::test]
async fn threshold_groups_by_merchant_and_absorbs() {
    let s = state().await;
    // 10 failures for mer_a, 3 for mer_b (below count=5)
    let mut evs: Vec<_> = (0..10)
        .map(|i| failure(&format!("a{i}"), *T0 + i * 1000, "mer_a"))
        .collect();
    evs.extend((0..3).map(|i| failure(&format!("b{i}"), *T0 + i * 1000, "mer_b")));
    store(&s, &evs).await;
    let changed = scan(&s, *T0 + 20_000).await;
    assert_eq!(changed.len(), 1, "exactly one incident (mer_a)");
    let inc = &changed[0];
    assert_eq!(inc.key, "rule:merchant_failures:merchant_id=mer_a");
    assert_eq!(inc.rule_id, "merchant_failures");
    assert_eq!(
        inc.headline,
        "Payment failures for merchant mer_a (10 in window)"
    );
    assert_eq!(inc.severity, "Critical");
    assert_eq!(inc.affected, vec!["merchant:mer_a".to_string()]);
    assert_eq!(inc.timeline.len(), 10);
    // custom events never open fallback incidents (mer_b stays quiet)
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM incidents")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    // more mer_a failures absorb; mer_b crossing the threshold opens its own
    store(&s, &[failure("a10", *T0 + 30_000, "mer_a")]).await;
    store(
        &s,
        &(3..6)
            .map(|i| failure(&format!("b{i}"), *T0 + 30_000 + i, "mer_b"))
            .collect::<Vec<_>>(),
    )
    .await;
    let changed = scan(&s, *T0 + 40_000).await;
    assert_eq!(changed.len(), 2);
    let a = changed.iter().find(|i| i.key.ends_with("mer_a")).unwrap();
    assert_eq!(a.id, inc.id, "absorbed into the open incident");
    assert_eq!(a.timeline.len(), 11);
    let b = changed.iter().find(|i| i.key.ends_with("mer_b")).unwrap();
    assert_eq!(b.timeline.len(), 6);
    // an unrelated custom kind joins nothing
    let mut other = failure("x1", *T0 + 41_000, "mer_a");
    other.kind = wt_common::EventType::parse("checkout.completed").unwrap();
    store(&s, &[other]).await;
    assert!(scan(&s, *T0 + 42_000).await.is_empty());
}

#[tokio::test]
async fn measurement_conditions_open_business_incidents() {
    let s = state().await;
    let sample = |id: &str, attempts: f64, rate: f64| {
        crate::custom_events::build_event(
            serde_json::from_value(json!({
                "id": id, "ts": *T0, "kind": "payment.conversion_sample", "summary": "sample",
                "attributes": { "merchant_id": "mer_v" },
                "measurements": { "attempts": attempts, "conversion_rate": rate }
            }))
            .unwrap(),
            None,
            None,
            *T0,
        )
        .unwrap()
    };
    // healthy, and low-but-too-little-volume samples do not match
    store(&s, &[sample("s1", 183.0, 0.87), sample("s2", 40.0, 0.2)]).await;
    assert!(scan(&s, *T0 + 1000).await.is_empty());
    store(&s, &[sample("s3", 183.0, 0.639)]).await;
    let changed = scan(&s, *T0 + 2000).await;
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].headline, "Conversion 0.639 for mer_v");
    assert_eq!(changed[0].severity, "Warning");
    // no agent dispatch on this rule
    assert_eq!(task_count(&s).await, 0);
}

#[tokio::test]
async fn agent_lifecycle_end_to_end() {
    let s = state().await;
    let mut notifications = s.take_notify_rx().unwrap();
    let evs: Vec<_> = (0..6)
        .map(|i| failure(&format!("a{i}"), *T0 + i * 1000, "mer_a"))
        .collect();
    store(&s, &evs).await;
    let inc = scan(&s, *T0 + 10_000).await.remove(0);
    assert_eq!(
        task_count(&s).await,
        1,
        "matching incident → one durable task"
    );
    // absorbing more events never starts a second concurrent task
    store(&s, &[failure("a7", *T0 + 11_000, "mer_a")]).await;
    assert_eq!(scan(&s, *T0 + 12_000).await.len(), 1);
    assert_eq!(task_count(&s).await, 1);

    let app = build_app(s.clone()).await;
    // auth separation: shared token can't use runner routes, runner token
    // can't read the API
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/agent-tasks/next?timeout=0",
            "test-token",
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/v1/incidents", "runner-token", None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // a runner without the profile's labels gets nothing
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/agent-tasks/next?timeout=0",
            "other-token",
            None
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    // the eligible runner claims it
    let (st, body) = call(
        &app,
        "GET",
        "/v1/agent-tasks/next?timeout=0",
        "runner-token",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let task = &body["task"];
    let id = task["task_id"].as_str().unwrap().to_string();
    let ctx_token = task["context_token"].as_str().unwrap().to_string();
    assert_eq!(task["incident_id"], inc.id);
    assert_eq!(task["attempt"], 1);
    assert_eq!(task["payload"]["headline"], inc.headline);
    // the payload is a snapshot at dispatch; live context has everything
    assert_eq!(
        task["payload"]["event_summary"]["payment.request_failed"],
        6
    );
    // nothing left to claim
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/agent-tasks/next?timeout=0",
            "runner-token",
            None
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    // the wrong runner cannot act on it
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/agent-tasks/{id}/started"),
            "other-token",
            Some(json!({}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/agent-tasks/{id}/started"),
            "runner-token",
            Some(json!({"agent": "Claude Code"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/agent-tasks/{id}/heartbeat"),
            "runner-token",
            None
        )
        .await
        .0,
        StatusCode::OK
    );

    // the agent reads context with the task token — redacted
    let (st, ctx) = call(
        &app,
        "GET",
        &format!("/v1/agent-tasks/{id}/context"),
        &ctx_token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(ctx["incident"]["id"], inc.id);
    assert_eq!(ctx["incident"]["event_count"], 7);
    let tl0 = &ctx["incident"]["timeline"][0];
    assert_eq!(tl0["attributes"]["merchant_id"], "mer_a");
    assert_eq!(tl0["attributes"]["authorization"], crate::redact::MASK);
    let (st, evs) = call(
        &app,
        "GET",
        &format!("/v1/agent-tasks/{id}/events?attr.merchant_id=mer_a"),
        &ctx_token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(evs["events"].as_array().unwrap().len(), 7);
    // the task token is good for nothing else
    assert_eq!(
        call(&app, "GET", "/v1/incidents", &ctx_token, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/v1/agent-tasks/{id}/context"),
            "runner-token",
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );

    // agent reports a fix → awaiting verification; the incident stays open
    let (st, body) = call(
        &app,
        "POST",
        &format!("/v1/agent-tasks/{id}/complete"),
        "runner-token",
        Some(json!({
            "outcome": "fixed", "classification": "platform_bug",
            "summary": "Nullable metadata caused a serialization panic",
            "actions": ["Added nullable handling", "Added regression test"],
            "confidence": 0.9
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "awaiting_verification");
    // the context token died with the run
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/v1/agent-tasks/{id}/context"),
            &ctx_token,
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let inc_now = crate::incidents::fetch_incident(&s.pool, &inc.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        inc_now.status,
        crate::incidents::IncidentStatus::Open,
        "agent success alone resolves nothing"
    );

    // a recurring failure resets the recovery timer
    store(&s, &[failure("a8", *T0 + 50_000, "mer_a")]).await;
    scan(&s, *T0 + 51_000).await;
    crate::agent_tasks::sweep(&s, *T0 + 100_000).await.unwrap(); // only 50s quiet
    assert_eq!(
        crate::incidents::fetch_incident(&s.pool, &inc.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        crate::incidents::IncidentStatus::Open
    );
    // 60s without matching events → verified recovery
    crate::agent_tasks::sweep(&s, *T0 + 111_000).await.unwrap();
    let done = crate::incidents::fetch_incident(&s.pool, &inc.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.status, crate::incidents::IncidentStatus::Resolved);
    let t = crate::agent_tasks::get_task(&s.pool, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t.status, "succeeded");
    // the timeline tells the story
    let activity = crate::dispatch::fetch_activity(&s.pool, &inc.id)
        .await
        .unwrap();
    let text: Vec<&str> = activity
        .iter()
        .map(|a| a["summary"].as_str().unwrap())
        .collect();
    assert!(text.iter().any(|t| t.contains("queued")), "{text:?}");
    assert!(text.iter().any(|t| t.contains("claimed")), "{text:?}");
    assert!(
        text.iter().any(|t| t.contains("investigation started")),
        "{text:?}"
    );
    assert!(text.iter().any(|t| t.contains("reports a fix")), "{text:?}");
    assert!(
        text.iter().any(|t| t.contains("Recovery verified")),
        "{text:?}"
    );
    // notify policy on_agent_failure: the success path stayed quiet except
    // for the always-on verified-resolution notice? — no: explicit
    // policies decide, so nothing was sent.
    assert!(
        notifications.try_recv().is_err(),
        "on_agent_failure: no notifications on success"
    );
}

#[tokio::test]
async fn escalation_retry_and_lease_expiry() {
    let s = state().await;
    let mut notifications = s.take_notify_rx().unwrap();
    let app = build_app(s.clone()).await;
    let claim = |app: axum::Router| async move {
        let (st, body) = call(
            &app,
            "GET",
            "/v1/agent-tasks/next?timeout=0",
            "runner-token",
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        body["task"]["task_id"].as_str().unwrap().to_string()
    };

    // merchant 1: infrastructure failure retries, then fails for good
    store(
        &s,
        &(0..5)
            .map(|i| failure(&format!("a{i}"), *T0 + i, "mer_1"))
            .collect::<Vec<_>>(),
    )
    .await;
    let inc1 = scan(&s, *T0 + 1000).await.remove(0);
    let id = claim(app.clone()).await;
    let (_, b) = call(
        &app,
        "POST",
        &format!("/v1/agent-tasks/{id}/fail"),
        "runner-token",
        Some(json!({"error": "claude: quota exhausted", "retryable": true})),
    )
    .await;
    assert_eq!(
        b["status"], "queued",
        "retryable + attempts left → requeued"
    );
    assert_eq!(claim(app.clone()).await, id, "same task, second attempt");
    // the lease expires (runner vanished) on the last attempt → failed
    crate::agent_tasks::sweep(&s, crate::ingest::now_ms() + 61_000)
        .await
        .unwrap();
    let t = crate::agent_tasks::get_task(&s.pool, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t.status, "failed");
    assert!(t.error.contains("lease expired"), "{}", t.error);
    let n = notifications
        .try_recv()
        .expect("agent failure notifies (on_agent_failure)");
    assert_eq!(n["id"], inc1.id);
    assert!(n["_notice"]["text"].as_str().unwrap().contains("failed"));
    assert_eq!(n["_channels"], json!(["telegram"]));

    // merchant 2: the agent concludes a human is needed
    store(
        &s,
        &(0..5)
            .map(|i| failure(&format!("b{i}"), *T0 + i, "mer_2"))
            .collect::<Vec<_>>(),
    )
    .await;
    let inc2 = scan(&s, *T0 + 2000)
        .await
        .into_iter()
        .find(|i| i.key.ends_with("mer_2"))
        .unwrap();
    let id2 = claim(app.clone()).await;
    let (st, b) = call(
        &app,
        "POST",
        &format!("/v1/agent-tasks/{id2}/complete"),
        "runner-token",
        Some(json!({
            "outcome": "needs_human", "classification": "client_integration",
            "summary": "Merchant signs webhooks with the wrong secret",
            "needs_human_reason": "Ask mer_2 to rotate their webhook secret"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(b["status"], "needs_human");
    let n = notifications.try_recv().expect("escalation notifies");
    assert_eq!(n["id"], inc2.id);
    let text = n["_notice"]["text"].as_str().unwrap();
    assert!(
        text.contains("needs a human") && text.contains("rotate their webhook secret"),
        "{text}"
    );
    // more failures: no re-dispatch after the agent asked for a human
    store(&s, &[failure("b9", *T0 + 3000, "mer_2")]).await;
    scan(&s, *T0 + 4000).await;
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM agent_tasks WHERE incident_id = $1")
        .bind(&inc2.id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    // invalid outcome is rejected
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/agent-tasks/x/complete",
            "runner-token",
            Some(json!({"outcome": "maybe"}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn loop_guard_limits_tasks_per_incident() {
    let s = state().await;
    store(
        &s,
        &(0..5)
            .map(|i| failure(&format!("a{i}"), *T0 + i, "mer_l"))
            .collect::<Vec<_>>(),
    )
    .await;
    let inc = scan(&s, *T0 + 1000).await.remove(0);
    // two tasks run (default max_tasks_per_incident = 2), each "succeeds"
    // without fixing anything; the third dispatch is refused
    for round in 0..3 {
        let out = crate::agent_tasks::dispatch_agent(&s, &inc, "payment_api")
            .await
            .unwrap();
        if round < 2 {
            assert!(
                matches!(
                    out,
                    crate::agent_tasks::DispatchOutcome::Created(_)
                        | crate::agent_tasks::DispatchOutcome::AlreadyActive
                ),
                "{out:?}"
            );
            sqlx::query("UPDATE agent_tasks SET status = 'succeeded' WHERE incident_id = $1")
                .bind(&inc.id)
                .execute(&s.pool)
                .await
                .unwrap();
        } else {
            assert!(
                matches!(out, crate::agent_tasks::DispatchOutcome::Limited(_)),
                "{out:?}"
            );
        }
    }
    // a rule without an agent action never creates tasks
    let unknown = crate::agent_tasks::dispatch_agent(&s, &inc, "nope")
        .await
        .unwrap();
    assert_eq!(unknown, crate::agent_tasks::DispatchOutcome::UnknownProfile);
}

#[tokio::test]
async fn unclaimed_task_alerts_once() {
    let mut s = state().await;
    // profile that no runner matches
    s.cfg.agent_profiles.get_mut("payment_api").unwrap().labels = vec!["nobody".into()];
    let mut notifications = s.take_notify_rx().unwrap();
    store(
        &s,
        &(0..5)
            .map(|i| failure(&format!("a{i}"), *T0 + i, "mer_u"))
            .collect::<Vec<_>>(),
    )
    .await;
    scan(&s, *T0 + 1000).await;
    let later = crate::ingest::now_ms() + 10 * 60_000;
    crate::agent_tasks::sweep(&s, later).await.unwrap();
    crate::agent_tasks::sweep(&s, later + 10_000).await.unwrap();
    let n = notifications.try_recv().expect("stuck task alert");
    assert!(n["_notice"]["text"]
        .as_str()
        .unwrap()
        .contains("no configured runner"));
    assert!(notifications.try_recv().is_err(), "alerted once");
}

#[tokio::test]
async fn auto_agent_takes_built_in_incidents() {
    let mut s = state().await;
    s.cfg
        .agent_profiles
        .insert("ops".into(), AgentProfile::default());
    s.cfg.auto_agent = crate::dispatch::AutoAgent {
        profile: "ops".into(),
        ..Default::default()
    };
    let host_event = |id: &str, host: &str, sev: wt_common::Severity| wt_common::AgentEvent {
        id: id.into(),
        ts: *T0,
        host_id: host.into(),
        key: format!("svc:{id}"),
        kind: wt_common::EventKind::ServiceFailed.into(),
        severity: sev,
        summary: "nginx.service failed".into(),
        ..Default::default()
    };
    // below min_severity (Warning): no agent
    assert_eq!(s.cfg.auto_agent.profile_for("Info"), None);
    assert_eq!(s.cfg.auto_agent.profile_for("Warning"), Some("ops"));
    store(&s, &[host_event("i1", "web-2", wt_common::Severity::Info)]).await;
    scan(&s, *T0 + 1000).await;
    assert_eq!(task_count(&s).await, 0);
    // a critical service failure on a host goes to the auto profile
    store(
        &s,
        &[host_event("c1", "web-1", wt_common::Severity::Critical)],
    )
    .await;
    let changed = scan(&s, *T0 + 2000).await;
    assert_eq!(changed.len(), 1);
    let (profile, payload): (String, String) =
        sqlx::query_as("SELECT profile, payload_json FROM agent_tasks")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(profile, "ops");
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        payload["host_id"], "web-1",
        "the runner learns which host to reach"
    );
    // rules with their own agent dispatch keep it (merchant_failures → payment_api)
    store(
        &s,
        &(0..5)
            .map(|i| failure(&format!("m{i}"), *T0 + 3000 + i, "mer_z"))
            .collect::<Vec<_>>(),
    )
    .await;
    scan(&s, *T0 + 4000).await;
    let (n,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM agent_tasks WHERE profile = 'payment_api'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(n, 1);
}
