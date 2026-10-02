//! M4 acceptance: the product-spec §7 demo scenario produces exactly ONE
//! correlated incident with a full timeline, and the lifecycle works.
use watchtower_server::app::AppState;
use watchtower_server::correlation::{default_rules, scan_and_absorb};
use watchtower_server::incidents::{self, IncidentStatus};
use wt_common::{AgentEvent, EventKind, Severity};

fn ev(id: &str, ts: i64, kind: EventKind, sev: Severity, key: &str) -> AgentEvent {
    AgentEvent {
        id: id.into(),
        ts,
        host_id: "demo-host".into(),
        key: key.into(),
        kind: kind.into(),
        severity: sev,
        summary: format!("{} {:?}", id, kind),
        evidence: vec![],
        ..Default::default()
    }
}

fn fresh_sequence(base: i64) -> Vec<AgentEvent> {
    // a genuinely new occurrence after the cooldown: the config file changed
    // again and the service failed again
    vec![
        ev(
            "e2-fim",
            base,
            EventKind::FileChanged,
            Severity::Warning,
            "fim:/etc/myapp/config.yml",
        ),
        ev(
            "e2-fail",
            base + 50,
            EventKind::ServiceFailed,
            Severity::Critical,
            "svc:myapp.service",
        ),
    ]
}

fn demo_sequence() -> Vec<AgentEvent> {
    // product spec §7: ssh new ip → sudo → config modified → app restarted →
    // app errors (ServiceFailed proxy) → cpu rises → health check fails
    vec![
        ev(
            "e-ssh",
            999_999_750_000,
            EventKind::SshLogin,
            Severity::Warning,
            "ssh:login:deploy",
        ),
        ev(
            "e-sudo",
            999_999_780_000,
            EventKind::SudoUsed,
            Severity::Info,
            "sudo:deploy",
        ),
        ev(
            "e-fim",
            999_999_800_000,
            EventKind::FileChanged,
            Severity::Warning,
            "fim:/etc/myapp/config.yml",
        ),
        ev(
            "e-restart",
            999_999_830_000,
            EventKind::ServiceRestarted,
            Severity::Info,
            "svc:myapp.service",
        ),
        ev(
            "e-fail",
            999_999_860_000,
            EventKind::ServiceFailed,
            Severity::Critical,
            "svc:myapp.service",
        ),
        ev(
            "e-cpu",
            999_999_900_000,
            EventKind::CpuSpike,
            Severity::Warning,
            "cpu:usage",
        ),
        ev(
            "e-unreach",
            999_999_950_000,
            EventKind::HostUnreachable,
            Severity::Critical,
            "uptime:https://api.example.com",
        ),
    ]
}

#[tokio::test]
async fn demo_produces_one_incident_with_full_timeline() {
    let state = AppState::for_tests().await;
    watchtower_server::ingest::store_events(&state.pool, &demo_sequence())
        .await
        .unwrap();
    let rules = default_rules();
    let changed = scan_and_absorb(&state.pool, &rules, 1_000_000_000_000)
        .await
        .unwrap();
    assert_eq!(changed.len(), 1, "exactly ONE incident for the demo");
    let inc = &changed[0];
    assert_eq!(inc.key, "rule:config_change_outage:demo-host");
    assert_eq!(inc.severity, "Critical");
    assert_eq!(
        inc.headline,
        "myapp.service became unhealthy after a configuration change"
    );
    assert!(
        inc.timeline.len() >= 7,
        "all demo events in the timeline, got {}",
        inc.timeline.len()
    );
    let kinds: Vec<&str> = inc.timeline.iter().map(|e| e.kind.as_str()).collect();
    for want in [
        "SshLogin",
        "SudoUsed",
        "FileChanged",
        "ServiceRestarted",
        "ServiceFailed",
        "CpuSpike",
        "HostUnreachable",
    ] {
        assert!(kinds.contains(&want), "timeline missing {}", want);
    }
    assert_eq!(inc.timeline[0].id, "e-unreach", "timeline ordered ts desc");

    // the webhook payload carries the full anatomy
    let json = watchtower_server::api_incidents::incident_json(inc);
    assert!(json["cause"]
        .as_str()
        .unwrap()
        .contains("configuration change"));
    assert!(!json["actions"].as_array().unwrap().is_empty());
    assert!(json["affected"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "svc:myapp.service"));

    // lifecycle: ack → resolve → the API reports the status
    incidents::set_status(&state.pool, &inc.id, IncidentStatus::Acknowledged)
        .await
        .unwrap();
    let got = incidents::fetch_incident(&state.pool, &inc.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.status, IncidentStatus::Acknowledged);
    // resolve at the FAKE scan clock so the cooldown diff below is a real
    // +10ms of window arithmetic (now - resolved_at < 600_000)
    incidents::set_status_at(
        &state.pool,
        &inc.id,
        IncidentStatus::Resolved,
        1_000_000_000_010,
    )
    .await
    .unwrap();
    let got = incidents::fetch_incident(&state.pool, &inc.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.status, IncidentStatus::Resolved);
    assert!(got.resolved_at.is_some());

    // cooldown: re-scanning the same window 10ms after the resolve does not
    // re-open (10ms < 600s cooldown)
    let changed = scan_and_absorb(&state.pool, &rules, 1_000_000_000_020)
        .await
        .unwrap();
    assert!(changed.is_empty(), "cooldown suppresses re-open");

    // honest re-open: cooldown expired (600_001ms > 600_000ms) — a FRESH
    // batch re-triggers the rule and opens a NEW incident with the same key
    // (dedup is keyed on OPEN incidents only; the resolution is long gone)
    let batch_base = 1_000_000_599_000; // inside the 300s scan window at 600_011
    watchtower_server::ingest::store_events(&state.pool, &fresh_sequence(batch_base))
        .await
        .unwrap();
    let changed = scan_and_absorb(&state.pool, &rules, 1_000_000_600_011)
        .await
        .unwrap();
    assert_eq!(changed.len(), 1, "cooldown expired → the rule re-opens");
    let reopened = &changed[0];
    assert_eq!(
        reopened.key, inc.key,
        "same rule:host key after the cooldown"
    );
    assert_ne!(reopened.id, inc.id, "a NEW incident, not the resolved one");
}
