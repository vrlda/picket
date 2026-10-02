use serde::{Deserialize, Serialize};
use wt_common::{AgentEvent, EventKind, EventType, Severity};

/// One correlation rule.
///
/// Legacy rules (built-in kinds, no count/group_by/where) match a trigger
/// plus supporting kinds within a sliding window per host — unchanged.
///
/// Threshold rules (`count`, `group_by` or `where` set, or a custom-kind
/// trigger) count matching trigger events per group across all hosts: at
/// least `count` events satisfying every `where` condition within the
/// window open one incident per group key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub trigger: EventType,
    #[serde(default)]
    pub supporting: Vec<EventType>,
    #[serde(default = "default_min_supporting")]
    pub min_supporting: u32,
    #[serde(default = "default_window")]
    pub window_secs: i64,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: i64,
    pub severity: Severity,
    pub headline: String,
    #[serde(default)]
    pub cause: String,
    /// Human remediation suggestions shown with the incident (also accepted
    /// as `recommended_actions`). Not to be confused with `dispatch`.
    #[serde(default, alias = "recommended_actions")]
    pub actions: Vec<String>,
    /// Kinds that join the timeline when present but do NOT count toward
    /// min_supporting (evidence only — e.g. a probe failure riding along
    /// with a config-change outage must not trigger the config rule alone).
    #[serde(default)]
    pub absorb_only: Vec<EventType>,
    /// Threshold rules: matching trigger events needed per group within the
    /// window (0 = 1).
    #[serde(default)]
    pub count: u32,
    /// Threshold rules: event fields whose values split incidents, e.g.
    /// ["attributes.merchant_id"].
    #[serde(default)]
    pub group_by: Vec<String>,
    /// Threshold rules: every condition must hold for an event to count.
    #[serde(default, rename = "where")]
    pub conditions: Vec<crate::rules::Condition>,
    /// What to do with the incident: notify channels and/or dispatch an
    /// agent. Empty = the severity routing in [notify.routing].
    #[serde(default)]
    pub dispatch: Vec<crate::dispatch::DispatchAction>,
    /// Automatic resolution once the trigger condition has been clear for
    /// the recovery window.
    #[serde(default)]
    pub recovery: Option<Recovery>,
    /// The fallback rule matches no trigger; handled separately.
    #[serde(skip)]
    pub is_fallback: bool,
}

/// `[rule.recovery]`: the incident resolves itself (and an agent fix counts
/// as verified) once no matching event arrived for `window_secs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recovery {
    pub window_secs: i64,
}

impl Rule {
    /// Threshold semantics (see the type docs) instead of legacy matching.
    pub fn is_threshold(&self) -> bool {
        self.count > 0
            || !self.group_by.is_empty()
            || !self.conditions.is_empty()
            || self.trigger.is_custom()
    }
}

fn kinds(k: &[EventKind]) -> Vec<EventType> {
    k.iter().map(|k| (*k).into()).collect()
}

fn default_min_supporting() -> u32 {
    1
}
fn default_window() -> i64 {
    300
}
fn default_cooldown() -> i64 {
    600
}

/// A rule match: the events that constitute it.
#[derive(Debug)]
pub struct RuleMatch {
    pub events: Vec<AgentEvent>,
    /// The unit name from the trigger event's key ("svc:myapp.service").
    pub service: Option<String>,
}

/// Default rules shipped with the server. `[[rule]]` entries in server.toml
/// override by id or add new ones.
pub fn default_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "config_change_outage".into(),
            trigger: EventKind::ServiceFailed.into(),
            supporting: kinds(&[
                EventKind::FileChanged,
                EventKind::SshLogin,
                EventKind::SudoUsed,
                EventKind::ServiceRestarted,
                EventKind::CpuSpike, // absorbed INTO the incident so the demo yields one notification
                EventKind::ErrorRateSpike, // app errors join the outage narrative
            ]),
            // probe failure rides along as evidence; it alone must not
            // satisfy min_supporting and open a config-change incident
            absorb_only: kinds(&[EventKind::HostUnreachable]),
            min_supporting: 1,
            window_secs: 300,
            cooldown_secs: 600,
            severity: Severity::Critical,
            headline: "{service} became unhealthy after a configuration change".into(),
            cause:
                "A configuration change was followed by a service failure within {window} seconds."
                    .into(),
            actions: vec![
                "Review the change to the affected configuration file".into(),
                "Roll back the latest configuration".into(),
                "Verify the SSH session that preceded the change".into(),
            ],
            is_fallback: false,
            ..Default::default()
        },
        Rule {
            id: "ssh_bruteforce".into(),
            trigger: EventKind::SshBruteForce.into(),
            supporting: kinds(&[EventKind::SshFailed]),
            min_supporting: 1,
            window_secs: 300,
            cooldown_secs: 600,
            severity: Severity::Critical,
            headline: "Brute-force attack against {host}".into(),
            cause: "Repeated failed SSH logins exceeded the threshold.".into(),
            actions: vec![
                "Block the source IP at the firewall".into(),
                "Check for successful logins from the same source".into(),
            ],
            absorb_only: vec![],
            is_fallback: false,
            ..Default::default()
        },
        Rule {
            id: "root_login".into(),
            trigger: EventKind::RootLogin.into(),
            supporting: kinds(&[EventKind::SshLogin]),
            min_supporting: 0,
            window_secs: 300,
            cooldown_secs: 600,
            // Warning floor: the agent escalates to Critical on a first-seen
            // IP; the incident severity derives from the matched events.
            severity: Severity::Warning,
            headline: "Root access on {host}".into(),
            cause: "A login as root was recorded.".into(),
            actions: vec!["Verify the session was authorized".into()],
            absorb_only: vec![],
            is_fallback: false,
            ..Default::default()
        },
        Rule {
            id: "server_unreachable".into(),
            trigger: EventKind::HostUnreachable.into(),
            supporting: vec![],
            min_supporting: 0,
            window_secs: 300,
            cooldown_secs: 600,
            severity: Severity::Critical,
            headline: "{host} is unreachable".into(),
            cause: "External probes failed consecutively.".into(),
            actions: vec!["Check power and network".into()],
            absorb_only: vec![],
            is_fallback: false,
            ..Default::default()
        },
        // App exceptions need no supporting evidence; the exception level
        // propagates to the incident severity (the assemble special-case)
        // and cooldown is off so a new occurrence always re-opens the
        // fingerprint's incident.
        Rule {
            id: "app_exception".into(),
            trigger: EventKind::AppException.into(),
            supporting: vec![],
            min_supporting: 0,
            window_secs: 300,
            cooldown_secs: 0,
            severity: Severity::Critical,
            headline: "{summary}".into(),
            cause: "An application exception was reported.".into(),
            actions: vec!["Inspect the stack trace in the incident timeline".into()],
            absorb_only: vec![],
            is_fallback: false,
            ..Default::default()
        },
        Rule {
            id: "fallback".into(),
            trigger: EventKind::CpuSpike.into(), // placeholder — is_fallback handles semantics
            supporting: vec![],
            min_supporting: 0,
            window_secs: 300,
            cooldown_secs: 300,
            severity: Severity::Warning,
            headline: String::new(),
            cause: String::new(),
            actions: vec![],
            absorb_only: vec![],
            is_fallback: true,
            ..Default::default()
        },
    ]
}

/// Match a rule against a host's window events. Events already absorbed by
/// an earlier rule (in `exclude`) never match — this keeps one event in one
/// incident and lets the config-change rule claim the HostUnreachable event
/// before the server_unreachable rule can.
pub fn match_rule(
    rule: &Rule,
    events: &[AgentEvent],
    now: i64,
    _host: &str,
    exclude: &std::collections::HashSet<String>,
) -> Option<RuleMatch> {
    if rule.is_fallback {
        return None;
    }
    let window_start = now - rule.window_secs * 1000;
    let in_window: Vec<&AgentEvent> = events
        .iter()
        .filter(|e| {
            !exclude.contains(&e.id)
                && e.ts >= window_start
                && e.ts <= now
                && (e.kind == rule.trigger
                    || rule.supporting.contains(&e.kind)
                    || rule.absorb_only.contains(&e.kind))
        })
        .collect();
    let trigger = in_window.iter().find(|e| e.kind == rule.trigger)?;
    // app_exception: ONE match per fingerprint (event key), oldest first —
    // the caller loops `while let Some` so each fingerprint group becomes
    // its own incident (a bug is one incident, not N per occurrence).
    if rule.id == "app_exception" {
        let group_key = &trigger.key;
        let events: Vec<AgentEvent> = in_window
            .iter()
            .filter(|e| &e.key == group_key)
            .map(|e| (*e).clone())
            .collect();
        return Some(RuleMatch {
            events,
            service: None,
        });
    }
    let supporting_count = in_window
        .iter()
        .filter(|e| {
            e.kind != rule.trigger
                && rule.supporting.contains(&e.kind)
                && !rule.absorb_only.contains(&e.kind)
        })
        .count();
    if (supporting_count as u32) < rule.min_supporting {
        return None;
    }
    let service = trigger.key.strip_prefix("svc:").map(|s| s.to_string());
    Some(RuleMatch {
        events: in_window.into_iter().cloned().collect(),
        service,
    })
}

/// Fill {host} and {service} slots in a template.
pub fn fill_template(tpl: &str, host: &str, service: Option<&str>) -> String {
    tpl.replace("{host}", host)
        .replace("{service}", service.unwrap_or("a service"))
}

/// Incident severity: the rule severity is a floor; the worst matched event
/// raises it (e.g. root_login: the agent emits Warning on a known IP and
/// Critical on a first-seen IP — the incident must reflect that).
fn incident_severity(rule: &Rule, m: &RuleMatch) -> String {
    let mut sev = rule.severity;
    for e in &m.events {
        if e.severity > sev {
            sev = e.severity;
        }
    }
    crate::ingest::severity_wire(sev)
}

/// Assemble an incident draft from a rule match.
pub fn assemble(rule: &Rule, m: &RuleMatch, host: &str) -> IncidentDraft {
    let service = m.service.as_deref();
    let window = rule.window_secs;
    // app_exception: per-fingerprint key (cross-host grouping — the key
    // comes from the event, not the host), severity and headline from the
    // first (oldest) event so the exception level drives the incident.
    if rule.id == "app_exception" {
        let first = m
            .events
            .first()
            .expect("app_exception match always has a trigger event");
        return IncidentDraft {
            key: format!("rule:app_exception:{}", first.key),
            host_id: host.into(),
            severity: crate::ingest::severity_wire(first.severity),
            headline: first.summary.clone(),
            cause: fill_template(&rule.cause, host, service)
                .replace("{window}", &window.to_string()),
            actions: rule.actions.clone(),
            affected: {
                let mut v = vec![host.to_string()];
                for e in &m.events {
                    if !v.contains(&e.key) {
                        v.push(e.key.clone());
                    }
                }
                v
            },
            events: m.events.clone(),
        };
    }
    IncidentDraft {
        key: format!("rule:{}:{}", rule.id, host),
        host_id: host.into(),
        severity: incident_severity(rule, m),
        headline: fill_template(&rule.headline, host, service),
        cause: fill_template(&rule.cause, host, service).replace("{window}", &window.to_string()),
        actions: rule.actions.clone(),
        affected: {
            let mut v = vec![host.to_string()];
            for e in &m.events {
                if !v.contains(&e.key) {
                    v.push(e.key.clone());
                }
            }
            v
        },
        events: m.events.clone(),
    }
}

/// Multi-host match: HostUnreachable events from >= 2 DISTINCT hosts within
/// the shared window. Runs BEFORE the per-host rule pass so the events are
/// claimed here (one incident, not N+1).
pub fn multi_host_match(
    by_host: &std::collections::HashMap<String, Vec<AgentEvent>>,
    now: i64,
    exclude: &std::collections::HashSet<String>,
) -> Option<(Vec<AgentEvent>, usize)> {
    let window_start = now - 300_000; // shared 300s window
    let mut events = Vec::new();
    let mut hosts = std::collections::HashSet::new();
    for (host, host_events) in by_host {
        for e in host_events {
            if e.kind == EventKind::HostUnreachable
                && !exclude.contains(&e.id)
                && e.ts >= window_start
                && e.ts <= now
            {
                events.push(e.clone());
                hosts.insert(host.clone());
            }
        }
    }
    if hosts.len() >= 2 {
        Some((events, hosts.len()))
    } else {
        None
    }
}

/// Assemble the multi-host incident draft. Host-independent key (no template
/// filling — severity/cause/actions are fixed).
pub fn assemble_multi_host(events: Vec<AgentEvent>, host_count: usize) -> IncidentDraft {
    IncidentDraft {
        key: "rule:multi_host_outage:multi".into(),
        host_id: "multi".into(),
        severity: "Critical".into(),
        headline: format!("{} hosts unreachable", host_count),
        cause: "External probes failed for multiple hosts within the window.".into(),
        actions: vec!["Check the upstream network and provider status".into()],
        affected: {
            let mut v: Vec<String> = events.iter().map(|e| e.host_id.clone()).collect();
            v.sort_unstable();
            v.dedup();
            v
        },
        events,
    }
}

/// An incident about to be persisted.
#[derive(Debug)]
pub struct IncidentDraft {
    pub key: String,
    pub host_id: String,
    pub severity: String,
    pub headline: String,
    pub cause: String,
    pub actions: Vec<String>,
    pub affected: Vec<String>,
    pub events: Vec<AgentEvent>,
}

/// Fallback: unmatched Warning+ events become single-event incidents.
pub fn fallback_incidents(events: &[AgentEvent], _now: i64, host: &str) -> Vec<IncidentDraft> {
    let mut out = Vec::new();
    for e in events {
        // custom (application) kinds become incidents only through rules
        if e.severity == Severity::Info || e.kind.is_custom() {
            continue;
        }
        let kind = crate::ingest::kind_wire(&e.kind);
        out.push(IncidentDraft {
            key: format!("event:{}:{}:{}", kind, host, e.key),
            host_id: host.into(),
            severity: crate::ingest::severity_wire(e.severity),
            headline: format!("{}: {}", kind, e.key),
            cause: String::new(),
            actions: vec![],
            affected: vec![host.into(), e.key.clone()],
            events: vec![e.clone()],
        });
    }
    out
}

/// Merge configured rules over the built-in defaults (override by id).
pub fn merged_rules(cfg_rules: &[Rule]) -> Vec<Rule> {
    let mut rules = default_rules();
    for r in cfg_rules {
        if let Some(slot) = rules.iter_mut().find(|x| x.id == r.id) {
            *slot = r.clone();
        } else {
            rules.push(r.clone());
        }
    }
    rules
}

use crate::incidents::{self, Incident};

/// Scan recent events, run rules + fallback, absorb or create incidents.
/// Returns incidents that CHANGED (new or gained new events) — the notifier
/// trigger. Cooldown applies to BOTH the rule pass and the fallback pass.
pub async fn scan_and_absorb(
    pool: &sqlx::AnyPool,
    rules: &[Rule],
    now: i64,
) -> Result<Vec<Incident>, sqlx::Error> {
    let max_window = rules.iter().map(|r| r.window_secs).max().unwrap_or(300) * 1000;
    let since = now - max_window;
    let events = crate::events::fetch_events_simple(pool, since).await?;
    let all_events = events.clone();
    let mut by_host: std::collections::HashMap<String, Vec<AgentEvent>> = Default::default();
    for e in events {
        by_host.entry(e.host_id.clone()).or_default().push(e);
    }
    let mut changed = Vec::new();
    let mut seen: std::collections::HashSet<String> = Default::default();
    // shared across hosts: the multi-host pass claims events FIRST so the
    // per-host rule pass can't double-fire on the same unreachables
    // Events that belong to an already-RESOLVED incident are settled: they
    // must never match again (one event, one incident). Without this, a
    // resolved incident whose events are still inside the scan range
    // re-opens as soon as its cooldown lapses — immediately for
    // app_exception (cooldown 0) — and re-notifies about old news.
    let resolved = resolved_event_ids(pool, since).await?;
    let mut matched_event_ids = resolved.clone();
    let fallback_cooldown = rules
        .iter()
        .find(|r| r.is_fallback)
        .map(|r| r.cooldown_secs * 1000)
        .unwrap_or(300_000);

    // multi-host pass: >=2 hosts unreachable in the shared window → one
    // incident (not N+1); the per-host loop below skips claimed events
    if let Some((mh_events, host_count)) = multi_host_match(&by_host, now, &matched_event_ids) {
        let draft = assemble_multi_host(mh_events, host_count);
        // claim first: cooldown-suppressed events must not re-open as
        // per-host or fallback incidents (same convention as the rule pass)
        for e in &draft.events {
            matched_event_ids.insert(e.id.clone());
        }
        if !recently_resolved(pool, &draft.key, now, 600_000).await? {
            let inc = incidents::create_incident(
                pool,
                &draft.key,
                &draft.host_id,
                &draft.severity,
                &draft.headline,
                &draft.cause,
                &draft.actions,
                &draft.affected,
            )
            .await?;
            incidents::set_rule_id(pool, &inc.id, "multi_host_outage").await?;
            let new_links = incidents::link_events(pool, &inc.id, &draft.events).await?;
            if new_links > 0 {
                incidents::touch_incident(pool, &inc.id).await?;
                let inc = incidents::fetch_incident(pool, &inc.id).await?.unwrap();
                if seen.insert(inc.id.clone()) {
                    changed.push(inc);
                }
            }
        }
    }

    // threshold rules (custom events, count/group_by/where) run across
    // hosts. They only skip settled (resolved) events — two threshold rules
    // may count the same event — but claim what they match so the fallback
    // pass leaves it alone.
    for rule in rules.iter().filter(|r| !r.is_fallback && r.is_threshold()) {
        for inc in threshold_rule(
            pool,
            rule,
            &all_events,
            now,
            &resolved,
            &mut matched_event_ids,
        )
        .await?
        {
            if seen.insert(inc.id.clone()) {
                changed.push(inc);
            }
        }
    }

    for (host, host_events) in by_host {
        // rule pass (declared order; earlier rules claim events first)
        for rule in rules {
            if rule.is_fallback || rule.is_threshold() {
                continue;
            }
            // while-let: app_exception matches ONCE PER FINGERPRINT (the
            // events are claimed between iterations); every other rule
            // matches at most once per host, so this is a no-op for them.
            while let Some(m) = match_rule(rule, &host_events, now, &host, &matched_event_ids) {
                let draft = assemble(rule, &m, &host);
                // claim first: cooldown-suppressed events must NOT re-open as
                // fallback incidents (they belong to the suppressed key)
                for e in &m.events {
                    matched_event_ids.insert(e.id.clone());
                }
                // cooldown: a resolved incident with this key blocks re-open
                if recently_resolved(pool, &draft.key, now, rule.cooldown_secs * 1000).await? {
                    continue;
                }
                let inc = incidents::create_incident(
                    pool,
                    &draft.key,
                    &draft.host_id,
                    &draft.severity,
                    &draft.headline,
                    &draft.cause,
                    &draft.actions,
                    &draft.affected,
                )
                .await?;
                incidents::set_rule_id(pool, &inc.id, &rule.id).await?;
                let new_links = incidents::link_events(pool, &inc.id, &draft.events).await?;
                if new_links > 0 {
                    incidents::touch_incident(pool, &inc.id).await?;
                    // severity may have risen (e.g. first-seen root login
                    // absorbs a Critical event into a Warning incident)
                    let worst = draft
                        .events
                        .iter()
                        .map(|e| e.severity)
                        .max()
                        .unwrap_or(wt_common::Severity::Warning);
                    if worst > wt_common::Severity::Warning {
                        incidents::raise_severity(
                            pool,
                            &inc.id,
                            &crate::ingest::severity_wire(worst),
                        )
                        .await?;
                    }
                    let inc = incidents::fetch_incident(pool, &inc.id).await?.unwrap();
                    if seen.insert(inc.id.clone()) {
                        changed.push(inc);
                    }
                }
            }
        }
        // fallback pass: Warning+ events NOT matched by any rule
        let unmatched: Vec<AgentEvent> = host_events
            .iter()
            .filter(|e| !matched_event_ids.contains(&e.id))
            .cloned()
            .collect();
        for draft in fallback_incidents(&unmatched, now, &host) {
            if let Some(open) = incidents::find_open_by_key(pool, &draft.key).await? {
                let new_links = incidents::link_events(pool, &open.id, &draft.events).await?;
                if new_links > 0 {
                    incidents::touch_incident(pool, &open.id).await?;
                    // severity may have risen — the SQL guard in
                    // raise_severity keeps it raise-only
                    let worst = draft
                        .events
                        .iter()
                        .map(|e| e.severity)
                        .max()
                        .unwrap_or(wt_common::Severity::Warning);
                    if worst > wt_common::Severity::Warning {
                        incidents::raise_severity(
                            pool,
                            &open.id,
                            &crate::ingest::severity_wire(worst),
                        )
                        .await?;
                    }
                    let inc = incidents::fetch_incident(pool, &open.id).await?.unwrap();
                    if seen.insert(inc.id.clone()) {
                        changed.push(inc);
                    }
                }
            } else if !recently_resolved(pool, &draft.key, now, fallback_cooldown).await? {
                let inc = incidents::create_incident(
                    pool,
                    &draft.key,
                    &draft.host_id,
                    &draft.severity,
                    &draft.headline,
                    &draft.cause,
                    &draft.actions,
                    &draft.affected,
                )
                .await?;
                incidents::set_rule_id(pool, &inc.id, "fallback").await?;
                incidents::link_events(pool, &inc.id, &draft.events).await?;
                let inc = incidents::fetch_incident(pool, &inc.id).await?.unwrap();
                if seen.insert(inc.id.clone()) {
                    changed.push(inc);
                }
            }
        }
    }
    Ok(changed)
}

/// One threshold rule over all scanned events: matching trigger events in
/// the window, grouped by `group_by`; a group with at least `count` events
/// opens (or a group with an open incident absorbs into) the incident
/// `rule:<id>:<group>`. Returns incidents that gained events.
async fn threshold_rule(
    pool: &sqlx::AnyPool,
    rule: &Rule,
    events: &[AgentEvent],
    now: i64,
    resolved: &std::collections::HashSet<String>,
    matched: &mut std::collections::HashSet<String>,
) -> Result<Vec<Incident>, sqlx::Error> {
    let window_start = now - rule.window_secs * 1000;
    let mut groups: std::collections::BTreeMap<String, Vec<&AgentEvent>> = Default::default();
    for e in events {
        if e.kind != rule.trigger
            || e.ts < window_start
            || e.ts > now
            || resolved.contains(&e.id)
            || !rule.conditions.iter().all(|c| c.matches(e))
        {
            continue;
        }
        groups
            .entry(crate::rules::group_key(e, &rule.group_by))
            .or_default()
            .push(e);
    }
    let mut changed = Vec::new();
    for (group, evs) in groups {
        let key = if group.is_empty() {
            format!("rule:{}", rule.id)
        } else {
            format!("rule:{}:{}", rule.id, group)
        };
        let open = incidents::find_open_by_key(pool, &key).await?;
        if evs.len() < rule.count.max(1) as usize && open.is_none() {
            continue; // below threshold, nothing to absorb into
        }
        for e in &evs {
            matched.insert(e.id.clone());
        }
        if open.is_none() && recently_resolved(pool, &key, now, rule.cooldown_secs * 1000).await? {
            continue;
        }
        let latest = evs.last().expect("non-empty group");
        let worst = evs
            .iter()
            .map(|e| e.severity)
            .max()
            .unwrap_or(rule.severity);
        let severity = crate::ingest::severity_wire(worst.max(rule.severity));
        let fill = |tpl: &str| {
            crate::rules::fill(tpl, latest, evs.len())
                .replace("{window}", &rule.window_secs.to_string())
        };
        let mut affected: Vec<String> = Vec::new();
        for e in &evs {
            if !e.subject.is_empty() && !affected.contains(&e.subject) {
                affected.push(e.subject.clone());
            }
        }
        if affected.is_empty() && !group.is_empty() {
            affected = group.split(',').map(String::from).collect();
        }
        let host = &evs[0].host_id;
        let host_id = if evs.iter().all(|e| &e.host_id == host) {
            host.clone()
        } else {
            String::new()
        };
        let inc = incidents::create_incident(
            pool,
            &key,
            &host_id,
            &severity,
            &fill(&rule.headline),
            &fill(&rule.cause),
            &rule.actions,
            &affected,
        )
        .await?;
        incidents::set_rule_id(pool, &inc.id, &rule.id).await?;
        let owned: Vec<AgentEvent> = evs.iter().map(|e| (*e).clone()).collect();
        if incidents::link_events(pool, &inc.id, &owned).await? > 0 {
            incidents::touch_incident(pool, &inc.id).await?;
            incidents::raise_severity(pool, &inc.id, &severity).await?;
            if let Some(inc) = incidents::fetch_incident(pool, &inc.id).await? {
                changed.push(inc);
            }
        }
    }
    Ok(changed)
}

/// Ids of events at/after `since_ms` already linked to a resolved incident.
async fn resolved_event_ids(
    pool: &sqlx::AnyPool,
    since_ms: i64,
) -> Result<std::collections::HashSet<String>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String,)>(
        "SELECT ie.event_id
         FROM incident_events ie
         JOIN incidents i ON i.id = ie.incident_id
         JOIN events e ON e.id = ie.event_id
         WHERE i.status = 'resolved' AND e.ts >= $1",
    )
    .bind(since_ms)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// True when a resolved incident with this key was resolved less than
/// `cooldown_ms` ago.
pub async fn recently_resolved(
    pool: &sqlx::AnyPool,
    key: &str,
    now: i64,
    cooldown_ms: i64,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query_as::<_, (Option<i64>,)>(
        "SELECT resolved_at FROM incidents WHERE key = $1 AND status = 'resolved' ORDER BY resolved_at DESC LIMIT 1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((Some(resolved_at),)) => now - resolved_at < cooldown_ms,
        _ => false,
    })
}

/// Per-incident minimum interval between notifications (absorb re-notify
/// throttle). An incident that absorbs new events re-notifies at most once
/// per window — the M4-era "full payload per absorb" debt.
pub struct NotifyThrottle {
    window_ms: i64,
    last: std::collections::HashMap<String, i64>,
}

impl NotifyThrottle {
    pub fn new(window_secs: i64) -> Self {
        NotifyThrottle {
            window_ms: window_secs.max(0) * 1000,
            last: Default::default(),
        }
    }

    pub fn allow(&mut self, incident_id: &str, ts: i64) -> bool {
        // Entries older than the window would be allowed anyway — dropping
        // them is behavior-neutral and keeps the map from growing by one
        // entry per incident for the life of the process.
        if self.last.len() >= 1024 {
            let window = self.window_ms;
            self.last.retain(|_, t| ts.saturating_sub(*t) < window);
        }
        let last = self.last.entry(incident_id.to_string()).or_insert(i64::MIN);
        if ts.saturating_sub(*last) >= self.window_ms {
            *last = ts;
            true
        } else {
            false
        }
    }
}

/// Spawn the correlation loop: scan every interval, notify on changes.
pub fn spawn_runner(state: crate::app::AppState) {
    tokio::spawn(crate::supervise::spawn_supervised(
        "correlation",
        move || scan_loop(state.clone()),
    ));
}

async fn scan_loop(state: crate::app::AppState) {
    let interval = state.cfg.scan_interval_secs.max(5); // clamp: never scan faster than every 5s
    let mut throttle = NotifyThrottle::new(state.cfg.notify_min_interval_secs);
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval as u64));
    ticker.tick().await; // skip immediate
    loop {
        ticker.tick().await;
        let now = crate::ingest::now_ms();
        match scan_and_absorb(&state.pool, &state.rules, now).await {
            Ok(changed) => {
                if changed.is_empty() {
                    continue;
                }
                for inc in &changed {
                    // dispatch first so the notification can say an agent
                    // took it; new dispatch news bypasses the throttle
                    let dispatch = crate::agent_tasks::dispatch_for_incident(&state, inc).await;
                    let news = dispatch.as_ref().is_some_and(|(_, new)| *new);
                    if !throttle.allow(&inc.id, now) && !news {
                        continue;
                    }
                    eprintln!("incident {}: {} [{}]", inc.id, inc.headline, inc.severity);
                    let mut json = crate::api_incidents::incident_json(inc);
                    let actions = state
                        .rules
                        .iter()
                        .find(|r| r.id == inc.rule_id)
                        .map(|r| r.dispatch.clone())
                        .unwrap_or_default();
                    let channels = crate::dispatch::channels_for_moment(
                        &actions,
                        &crate::notify::channels_for(&state.notify, &inc.severity),
                        crate::dispatch::Moment::Incident,
                    );
                    if channels.is_empty() {
                        continue;
                    }
                    json["_channels"] = serde_json::json!(channels);
                    if let Some((text, _)) = dispatch {
                        json["_notice"] = serde_json::json!({ "moment": "incident", "text": text });
                    }
                    if let Err(e) = state.notify_tx.try_send(json) {
                        match e {
                            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                                eprintln!(
                                    "notify queue full — dropping notification for {}",
                                    inc.id
                                );
                            }
                            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                                eprintln!("notify channel closed (notifier task died) — dropping notification for {}", inc.id);
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("correlation scan failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use wt_common::{AgentEvent, EventKind, Severity};

    fn ev(id: &str, ts: i64, kind: EventKind, sev: Severity, key: &str) -> AgentEvent {
        ev_host("h-1", id, ts, kind, sev, key)
    }

    fn ev_host(
        host: &str,
        id: &str,
        ts: i64,
        kind: EventKind,
        sev: Severity,
        key: &str,
    ) -> AgentEvent {
        AgentEvent {
            id: id.into(),
            ts,
            host_id: host.into(),
            key: key.into(),
            kind: kind.into(),
            severity: sev,
            summary: format!("{} {:?}", id, kind),
            evidence: vec![],
            ..Default::default()
        }
    }

    const CFG_RULE: &str = r#"
id = "config_change_outage"
trigger = "ServiceFailed"
supporting = ["FileChanged", "SshLogin", "SudoUsed", "ServiceRestarted"]
min_supporting = 1
window_secs = 300
cooldown_secs = 600
severity = "Critical"
headline = "{service} became unhealthy after a configuration change"
cause = "A configuration change was followed by a service failure within {window} seconds."
actions = ["Review the change to the affected file", "Roll back the latest configuration"]
"#;

    fn no_exclude() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    #[test]
    fn parses_rule_from_toml() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        assert_eq!(rule.id, "config_change_outage");
        assert_eq!(rule.trigger, EventKind::ServiceFailed);
        assert_eq!(rule.supporting.len(), 4);
        assert_eq!(rule.cooldown_secs, 600);
        assert!(!rule.is_fallback);
    }

    #[test]
    fn matches_rule_when_trigger_and_supporting_in_window() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![
            ev(
                "e-1",
                999_999_700_000,
                EventKind::SshLogin,
                Severity::Info,
                "ssh:login:deploy",
            ),
            ev(
                "e-2",
                999_999_700_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:/etc/myapp/config.yml",
            ),
            ev(
                "e-3",
                999_999_750_000,
                EventKind::ServiceRestarted,
                Severity::Info,
                "svc:myapp.service",
            ),
            ev(
                "e-4",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:myapp.service",
            ),
        ];
        let m = match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude());
        let matched = m.expect("matched");
        assert_eq!(matched.events.len(), 4);
        assert!(matched
            .events
            .iter()
            .any(|e| e.kind == EventKind::ServiceFailed));
        assert_eq!(matched.service, Some("myapp.service".to_string()));
    }

    #[test]
    fn does_not_match_trigger_without_supporting() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![ev(
            "e-1",
            999_999_800_000,
            EventKind::ServiceFailed,
            Severity::Critical,
            "svc:myapp.service",
        )];
        assert!(match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).is_none());
    }

    #[test]
    fn does_not_match_events_outside_window() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![
            ev(
                "e-1",
                999_600_000_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:x",
            ),
            ev(
                "e-2",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:x",
            ),
        ];
        // e-1: now - e-1 = 400_000_000 ms > window 300_000 ms → outside
        assert!(match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).is_none());
    }

    #[test]
    fn excluded_events_do_not_match() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![
            ev(
                "e-2",
                999_999_700_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:x",
            ),
            ev(
                "e-4",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:x",
            ),
        ];
        let mut exclude = std::collections::HashSet::new();
        exclude.insert("e-4".to_string());
        assert!(
            match_rule(&rule, &events, 1_000_000_000_000, "h-1", &exclude).is_none(),
            "trigger already absorbed"
        );
    }

    #[test]
    fn headline_slots_are_filled() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![
            ev(
                "e-1",
                999_999_700_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:x",
            ),
            ev(
                "e-2",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:myapp.service",
            ),
        ];
        let m = match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).unwrap();
        let assembled = assemble(&rule, &m, "h-1");
        assert_eq!(
            assembled.headline,
            "myapp.service became unhealthy after a configuration change"
        );
        assert!(assembled.cause.contains("300"));
        assert_eq!(assembled.actions.len(), 2);
        assert!(assembled.affected.iter().any(|a| a == "h-1"));
        assert!(assembled.affected.iter().any(|a| a == "svc:myapp.service"));
    }

    #[test]
    fn fallback_covers_unmatched_warning_events() {
        let evs = vec![ev(
            "e-1",
            999_999_900_000,
            EventKind::CpuSpike,
            Severity::Warning,
            "cpu:usage",
        )];
        let incidents = fallback_incidents(&evs, 1_000_000_000_000, "h-1");
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].headline, "CpuSpike: cpu:usage");
        assert_eq!(incidents[0].severity, "Warning");
    }

    #[test]
    fn default_rules_include_config_change_and_fallback() {
        let rules = default_rules();
        assert!(rules.iter().any(|r| r.id == "config_change_outage"));
        assert!(rules.iter().any(|r| r.id == "fallback"));
        assert!(rules.iter().any(|r| r.id == "ssh_bruteforce"));
        let cfg = rules
            .iter()
            .find(|r| r.id == "config_change_outage")
            .unwrap();
        assert!(
            cfg.supporting.contains(&EventKind::CpuSpike.into()),
            "cpu spike absorbed so the demo yields ONE incident"
        );
    }

    #[test]
    fn severity_derives_from_matched_events() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap(); // Critical
        let events = vec![
            ev(
                "e-1",
                999_999_700_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:x",
            ),
            ev(
                "e-2",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:myapp.service",
            ),
        ];
        let m = match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).unwrap();
        let a = assemble(&rule, &m, "h-1");
        assert_eq!(a.severity, "Critical");
        // root_login: rule Warning, a Warning-only root login stays Warning
        let root_rule = default_rules()
            .into_iter()
            .find(|r| r.id == "root_login")
            .unwrap();
        let events = vec![
            ev(
                "e-1",
                999_999_700_000,
                EventKind::SshLogin,
                Severity::Info,
                "ssh:login:ops",
            ),
            ev(
                "e-2",
                999_999_800_000,
                EventKind::RootLogin,
                Severity::Warning,
                "ssh:login:root",
            ),
        ];
        let m = match_rule(&root_rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).unwrap();
        let a = assemble(&root_rule, &m, "h-1");
        assert_eq!(a.severity, "Warning", "known-IP root login stays Warning");
        // first-seen root login: the agent's Critical raises the incident
        let events = vec![
            ev(
                "e-1",
                999_999_700_000,
                EventKind::SshLogin,
                Severity::Info,
                "ssh:login:ops",
            ),
            ev(
                "e-2",
                999_999_800_000,
                EventKind::RootLogin,
                Severity::Critical,
                "ssh:login:root",
            ),
        ];
        let m = match_rule(&root_rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).unwrap();
        let a = assemble(&root_rule, &m, "h-1");
        assert_eq!(
            a.severity, "Critical",
            "first-seen root login escalates to Critical"
        );
    }

    #[test]
    fn absorb_only_does_not_satisfy_min_supporting() {
        let rule = default_rules()
            .into_iter()
            .find(|r| r.id == "config_change_outage")
            .unwrap();
        let events = vec![
            ev(
                "e-1",
                999_999_800_000,
                EventKind::HostUnreachable,
                Severity::Critical,
                "uptime:https://api",
            ),
            ev(
                "e-2",
                999_999_850_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:myapp.service",
            ),
        ];
        // HostUnreachable present but absorb-only → no supporting → no match
        assert!(match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).is_none());
        // with a FileChanged it matches AND absorbs the probe event
        let events = vec![
            ev(
                "e-1",
                999_999_700_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:x",
            ),
            ev(
                "e-2",
                999_999_800_000,
                EventKind::HostUnreachable,
                Severity::Critical,
                "uptime:https://api",
            ),
            ev(
                "e-3",
                999_999_850_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:myapp.service",
            ),
        ];
        let m = match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).unwrap();
        assert!(
            m.events
                .iter()
                .any(|e| e.kind == EventKind::HostUnreachable),
            "absorbed into the timeline"
        );
    }

    async fn pool() -> sqlx::AnyPool {
        crate::db::ensure_any_drivers();
        let p = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        crate::db::init_schema(&p).await.unwrap();
        p
    }

    #[tokio::test]
    async fn engine_scan_creates_one_incident_for_demo_sequence() {
        let p = pool().await;
        // demo scenario timeline (product spec §7), within one window
        let demo = [
            (
                "e-ssh",
                999_999_750_000i64,
                EventKind::SshLogin,
                Severity::Warning,
                "ssh:login:deploy",
            ),
            (
                "e-sudo",
                999_999_780_000,
                EventKind::SudoUsed,
                Severity::Info,
                "sudo:deploy",
            ),
            (
                "e-fim",
                999_999_800_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:/etc/myapp/config.yml",
            ),
            (
                "e-restart",
                999_999_830_000,
                EventKind::ServiceRestarted,
                Severity::Info,
                "svc:myapp.service",
            ),
            (
                "e-fail",
                999_999_860_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:myapp.service",
            ),
            (
                "e-cpu",
                999_999_900_000,
                EventKind::CpuSpike,
                Severity::Warning,
                "cpu:usage",
            ),
            (
                "e-unreach",
                999_999_950_000,
                EventKind::HostUnreachable,
                Severity::Critical,
                "uptime:https://api.example.com",
            ),
        ];
        let events: Vec<AgentEvent> = demo
            .iter()
            .map(|(id, ts, kind, sev, key)| AgentEvent {
                id: id.to_string(),
                ts: *ts,
                host_id: "h-1".into(),
                key: key.to_string(),
                kind: (*kind).into(),
                severity: *sev,
                summary: format!("{} {:?}", id, kind),
                evidence: vec![],
                ..Default::default()
            })
            .collect();
        crate::ingest::store_events(&p, &events).await.unwrap();
        let rules = default_rules();
        let incidents = scan_and_absorb(&p, &rules, 1_000_000_000_000)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "exactly ONE incident for the demo sequence"
        );
        assert_eq!(incidents[0].key, "rule:config_change_outage:h-1");
        assert_eq!(incidents[0].severity, "Critical");
        assert!(
            incidents[0].timeline.len() >= 5,
            "timeline has the correlated events"
        );
        // HostUnreachable absorbed as evidence; the cpu spike too; no fallback incidents
        assert!(incidents[0].timeline.iter().any(|e| e.kind == "CpuSpike"));
        assert!(incidents[0]
            .timeline
            .iter()
            .any(|e| e.kind == "HostUnreachable"));
    }

    #[tokio::test]
    async fn absorb_while_open_and_cooldown_after_resolve() {
        let p = pool().await;
        let rules = default_rules();
        let e1 = ev(
            "e-1",
            999_999_800_000,
            EventKind::ServiceFailed,
            Severity::Critical,
            "svc:myapp.service",
        );
        let e2 = ev(
            "e-2",
            999_999_750_000,
            EventKind::FileChanged,
            Severity::Warning,
            "fim:x",
        );
        crate::ingest::store_events(&p, &[e1.clone(), e2.clone()])
            .await
            .unwrap();
        let incs = scan_and_absorb(&p, &rules, 1_000_000_000_000)
            .await
            .unwrap();
        assert_eq!(incs.len(), 1);
        let id = incs[0].id.clone();
        // same events re-scanned → absorbed, no new incident, no churn
        let incs = scan_and_absorb(&p, &rules, 1_000_000_010_000)
            .await
            .unwrap();
        assert_eq!(incs.len(), 0, "absorb is a no-op — nothing new to report");
        // resolve at the FAKE scan clock, so the cooldown diff is a real
        // +10ms (the check is now - resolved_at < 600_000), then re-scan
        // within cooldown → nothing (BOTH passes check cooldown)
        crate::incidents::set_status_at(
            &p,
            &id,
            crate::incidents::IncidentStatus::Resolved,
            1_000_000_000_010,
        )
        .await
        .unwrap();
        let incs = scan_and_absorb(&p, &rules, 1_000_000_020_000)
            .await
            .unwrap();
        assert!(
            incs.is_empty(),
            "cooldown suppresses re-open (rule AND fallback passes)"
        );
    }

    #[tokio::test]
    async fn absorb_raises_severity_when_critical_event_joins() {
        let p = pool().await;
        let rules = default_rules();
        // scan 1: Warning RootLogin + Info SshLogin → root_login rule
        // (min_supporting 0) → incident at the Warning floor
        let e1 = ev(
            "e-1",
            999_999_800_000,
            EventKind::RootLogin,
            Severity::Warning,
            "ssh:login:root",
        );
        let e2 = ev(
            "e-2",
            999_999_750_000,
            EventKind::SshLogin,
            Severity::Info,
            "ssh:login:ops",
        );
        crate::ingest::store_events(&p, &[e1.clone(), e2.clone()])
            .await
            .unwrap();
        let incs = scan_and_absorb(&p, &rules, 1_000_000_000_000)
            .await
            .unwrap();
        assert_eq!(incs.len(), 1);
        assert_eq!(incs[0].severity, "Warning");
        let id = incs[0].id.clone();
        // scan 2: a NEW Critical RootLogin (first-seen) within the window
        // absorbs into the open incident → severity re-derived to Critical
        let e3 = ev(
            "e-3",
            999_999_900_000,
            EventKind::RootLogin,
            Severity::Critical,
            "ssh:login:root:first-seen",
        );
        crate::ingest::store_events(&p, std::slice::from_ref(&e3))
            .await
            .unwrap();
        let incs = scan_and_absorb(&p, &rules, 1_000_000_000_000)
            .await
            .unwrap();
        assert_eq!(incs.len(), 1, "absorb re-notifies the changed incident");
        let inc = crate::incidents::fetch_incident(&p, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            inc.severity, "Critical",
            "absorbing a Critical event raises the incident severity"
        );
    }

    #[tokio::test]
    async fn notifier_fires_for_changed_incidents() {
        // capture delivery: point the webhook at a local listener
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut buf = [0u8; 65536];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            let req = String::from_utf8_lossy(&buf).into_owned();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            req
        });
        let pool = pool().await;
        let events = vec![
            ev(
                "e-1",
                999_999_700_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:x",
            ),
            ev(
                "e-2",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:myapp.service",
            ),
        ];
        crate::ingest::store_events(&pool, &events).await.unwrap();
        let cfg = crate::config::ServerConfig {
            notify: crate::notify::NotifyConfig {
                webhook_url: format!("http://{}", addr),
                slack_url: String::new(),
                telegram_token: None,
                telegram_chat_id: None,
                telegram_password: None,
                routing: std::collections::HashMap::from([
                    ("Critical".into(), vec!["webhook".into()]),
                    ("Warning".into(), vec!["webhook".into()]),
                ]),
            },
            ..Default::default()
        };
        let rules = default_rules();
        let changed = scan_and_absorb(&pool, &rules, 1_000_000_000_000)
            .await
            .unwrap();
        assert_eq!(changed.len(), 1);
        let inc = crate::incidents::fetch_incident(&pool, &changed[0].id)
            .await
            .unwrap()
            .unwrap();
        let json = crate::api_incidents::incident_json(&inc);
        let failed = crate::notify::notify_incident(&cfg.notify, &json).await;
        assert!(failed.is_empty(), "delivery succeeded");
        let req = handle.join().unwrap();
        assert!(req.contains("watchtower.incident"));
        assert!(req.contains("myapp.service became unhealthy"));
    }

    #[test]
    fn notify_throttle_limits_absorbs() {
        let mut t = NotifyThrottle::new(300);
        assert!(t.allow("inc-1", 1_000), "first notify allowed");
        assert!(!t.allow("inc-1", 1_001), "second within window suppressed");
        assert!(!t.allow("inc-1", 300_000), "within the window suppressed");
        assert!(t.allow("inc-1", 301_001), "past the window allowed");
        assert!(t.allow("inc-2", 301_001), "different incident unaffected");
    }

    #[test]
    fn notify_throttle_prunes_expired_entries() {
        let mut t = NotifyThrottle::new(60);
        for i in 0..2000 {
            assert!(t.allow(&format!("inc-{i}"), i * 1_000));
        }
        assert!(t.last.len() <= 1024, "expired entries pruned");
        assert!(!t.allow("inc-1999", 1_999_000 + 1), "live entry kept");
    }

    #[test]
    fn m5_kinds_flow_to_incidents() {
        let rules = default_rules();
        let cfg_rule = rules
            .iter()
            .find(|r| r.id == "config_change_outage")
            .unwrap();
        // error spikes are supporting evidence for the outage rule
        assert!(cfg_rule
            .supporting
            .contains(&EventKind::ErrorRateSpike.into()));
        // container crash loops and cert expiry fall through the fallback
        for kind in [EventKind::ContainerCrashLoop, EventKind::CertExpiring] {
            let evs = vec![ev("e-1", 999_999_800_000, kind, Severity::Critical, "k:1")];
            let drafts = fallback_incidents(&evs, 1_000_000_000_000, "h-1");
            assert_eq!(drafts.len(), 1, "{:?} must incident via fallback", kind);
            assert_eq!(drafts[0].severity, "Critical");
        }
    }

    #[tokio::test]
    async fn multi_host_outage_one_incident_for_two_hosts() {
        let p = pool().await;
        let events = vec![
            ev_host(
                "mh-1",
                "mh-1",
                999_999_800_000,
                EventKind::HostUnreachable,
                Severity::Critical,
                "uptime:https://a",
            ),
            ev_host(
                "mh-2",
                "mh-2",
                999_999_820_000,
                EventKind::HostUnreachable,
                Severity::Critical,
                "uptime:https://b",
            ),
        ];
        crate::ingest::store_events(&p, &events).await.unwrap();
        let rules = default_rules();
        let changed = scan_and_absorb(&p, &rules, 1_000_000_000_000)
            .await
            .unwrap();
        assert_eq!(
            changed.len(),
            1,
            "one multi-host incident, no per-host incidents"
        );
        assert!(changed[0].key.starts_with("rule:multi_host_outage"));
        assert!(changed[0].headline.contains("2 hosts"));
        assert!(changed[0].timeline.len() >= 2);
    }

    #[tokio::test]
    async fn single_host_unreachable_uses_per_host_rule() {
        let p = pool().await;
        let events = vec![ev(
            "s-1",
            999_999_800_000,
            EventKind::HostUnreachable,
            Severity::Critical,
            "uptime:https://a",
        )];
        crate::ingest::store_events(&p, &events).await.unwrap();
        let rules = default_rules();
        let changed = scan_and_absorb(&p, &rules, 1_000_000_000_000)
            .await
            .unwrap();
        assert_eq!(changed.len(), 1);
        assert!(
            changed[0].key.starts_with("rule:server_unreachable"),
            "single host stays per-host"
        );
    }

    #[tokio::test]
    async fn app_exception_groups_by_fingerprint() {
        let p = pool().await;
        let fp = crate::errors::fingerprint("api", "ValueError", &[("app.py".into(), 42)]);
        let evs = vec![
            ev(
                "x-1",
                1_000,
                EventKind::AppException,
                Severity::Critical,
                &format!("ex:api:{}", fp),
            ),
            ev(
                "x-2",
                2_000,
                EventKind::AppException,
                Severity::Critical,
                &format!("ex:api:{}", fp),
            ),
        ];
        crate::ingest::store_events(&p, &evs).await.unwrap();
        let changed = scan_and_absorb(&p, &default_rules(), 10_000).await.unwrap();
        assert_eq!(changed.len(), 1, "one incident per fingerprint");
        assert_eq!(changed[0].key, format!("rule:app_exception:ex:api:{}", fp));
        assert_eq!(changed[0].severity, "Critical");
        assert_eq!(changed[0].timeline.len(), 2);
    }

    #[tokio::test]
    async fn resolved_incident_events_never_reopen_it() {
        // app_exception has cooldown 0: before the fix, the resolved
        // incident's own events (still inside the window) re-matched on the
        // next scan and re-opened (and re-notified) it within seconds.
        let p = pool().await;
        let fp = crate::errors::fingerprint("api", "ValueError", &[("app.py".into(), 42)]);
        let key = format!("ex:api:{}", fp);
        let x1 = ev(
            "x-1",
            1_000,
            EventKind::AppException,
            Severity::Critical,
            &key,
        );
        crate::ingest::store_events(&p, &[x1]).await.unwrap();
        let changed = scan_and_absorb(&p, &default_rules(), 10_000).await.unwrap();
        assert_eq!(changed.len(), 1);
        crate::incidents::set_status_at(
            &p,
            &changed[0].id,
            crate::incidents::IncidentStatus::Resolved,
            11_000,
        )
        .await
        .unwrap();
        let changed = scan_and_absorb(&p, &default_rules(), 20_000).await.unwrap();
        assert!(changed.is_empty(), "resolved events stay resolved");
        // a NEW occurrence of the same bug opens a fresh incident
        let x2 = ev(
            "x-2",
            21_000,
            EventKind::AppException,
            Severity::Critical,
            &key,
        );
        crate::ingest::store_events(&p, &[x2]).await.unwrap();
        let changed = scan_and_absorb(&p, &default_rules(), 30_000).await.unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].timeline.len(), 1, "only the new event");
        assert_eq!(changed[0].timeline[0].id, "x-2");
    }

    #[tokio::test]
    async fn resolved_fallback_events_do_not_reopen_after_cooldown() {
        let p = pool().await;
        // a custom rule with a long window widens the scan range past the
        // fallback cooldown (300s)
        let mut rules = default_rules();
        let mut long = rules[0].clone();
        long.id = "long_window".into();
        long.window_secs = 3600;
        rules.push(long);
        let e = ev(
            "d-1",
            1_000_000,
            EventKind::DiskHigh,
            Severity::Warning,
            "disk:/",
        );
        crate::ingest::store_events(&p, &[e]).await.unwrap();
        let changed = scan_and_absorb(&p, &rules, 1_010_000).await.unwrap();
        assert_eq!(changed.len(), 1);
        crate::incidents::set_status_at(
            &p,
            &changed[0].id,
            crate::incidents::IncidentStatus::Resolved,
            1_020_000,
        )
        .await
        .unwrap();
        // 20 minutes later: past the cooldown, event still inside the range
        let changed = scan_and_absorb(&p, &rules, 2_220_000).await.unwrap();
        assert!(changed.is_empty(), "old event must not open a new incident");
    }

    #[tokio::test]
    async fn app_exception_level_propagates_and_splits_fingerprints() {
        let p = pool().await;
        let fp_a = crate::errors::fingerprint("api", "ValueError", &[("app.py".into(), 42)]);
        let fp_b = crate::errors::fingerprint("api", "TypeError", &[("app.py".into(), 99)]);
        let evs = vec![
            ev(
                "x-1",
                1_000,
                EventKind::AppException,
                Severity::Warning,
                &format!("ex:api:{}", fp_a),
            ),
            ev(
                "x-2",
                1_000,
                EventKind::AppException,
                Severity::Critical,
                &format!("ex:api:{}", fp_b),
            ),
        ];
        crate::ingest::store_events(&p, &evs).await.unwrap();
        let changed = scan_and_absorb(&p, &default_rules(), 10_000).await.unwrap();
        assert_eq!(
            changed.len(),
            2,
            "different fingerprints → different incidents"
        );
        let warn = changed.iter().find(|i| i.severity == "Warning").unwrap();
        assert_eq!(warn.key, format!("rule:app_exception:ex:api:{}", fp_a));
        let crit = changed.iter().find(|i| i.severity == "Critical").unwrap();
        assert_eq!(crit.key, format!("rule:app_exception:ex:api:{}", fp_b));
    }
}
