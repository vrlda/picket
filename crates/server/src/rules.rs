//! Field access, predicates, grouping and templating for threshold rules
//! (rules over custom application/business events). Deliberately small:
//! dotted field paths and a handful of comparison operators — no DSL.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wt_common::AgentEvent;

/// Comparison operator of a `[[rule.where]]` condition. Accepts both the
/// names (`gte`) and the symbols (`>=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    #[serde(alias = "==", alias = "=")]
    Eq,
    #[serde(alias = "!=")]
    Neq,
    #[serde(alias = ">")]
    Gt,
    #[serde(alias = ">=")]
    Gte,
    #[serde(alias = "<")]
    Lt,
    #[serde(alias = "<=")]
    Lte,
    Exists,
}

/// One predicate: `field op value`, e.g. `measurements.attempts >= 100`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub op: Op,
    #[serde(default)]
    pub value: Option<Value>,
}

/// Value of a dotted field path on an event. Supported paths: `kind`,
/// `severity`, `host_id`, `key`, `summary`, `source` (alias `service`),
/// `environment`, `subject`, `attributes.<name>`, `measurements.<name>`.
/// Missing or empty → None.
pub fn field_value(ev: &AgentEvent, path: &str) -> Option<Value> {
    let text = |s: &str| (!s.is_empty()).then(|| Value::String(s.to_string()));
    if let Some(name) = path.strip_prefix("attributes.") {
        return ev.attributes.get(name).cloned().filter(|v| !v.is_null());
    }
    if let Some(name) = path.strip_prefix("measurements.") {
        return ev.measurements.get(name).map(|n| serde_json::json!(n));
    }
    match path {
        "kind" => Some(Value::String(ev.kind.to_string())),
        "severity" => Some(Value::String(crate::ingest::severity_wire(ev.severity))),
        "host_id" | "host" => text(&ev.host_id),
        "key" => text(&ev.key),
        "summary" => text(&ev.summary),
        "source" | "service" => text(&ev.source),
        "environment" => text(&ev.environment),
        "subject" => text(&ev.subject),
        _ => None,
    }
}

/// Plain-text rendering of a value (strings unquoted).
pub fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn as_number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

impl Condition {
    /// True when the event satisfies the condition. Ordering operators need
    /// both sides numeric; eq/neq compare numerically when both sides are
    /// numbers, else as text. A missing field fails every operator but
    /// `neq`.
    pub fn matches(&self, ev: &AgentEvent) -> bool {
        let actual = field_value(ev, &self.field);
        if self.op == Op::Exists {
            return actual.is_some();
        }
        let (Some(actual), Some(expected)) = (actual, self.value.as_ref()) else {
            return self.op == Op::Neq && self.value.is_some();
        };
        let numbers = as_number(&actual).zip(as_number(expected));
        match self.op {
            Op::Eq | Op::Neq => {
                let equal = match (&actual, expected, numbers) {
                    (Value::Number(_), _, Some((a, b))) | (_, Value::Number(_), Some((a, b))) => {
                        a == b
                    }
                    _ => value_text(&actual) == value_text(expected),
                };
                equal == (self.op == Op::Eq)
            }
            Op::Gt => numbers.is_some_and(|(a, b)| a > b),
            Op::Gte => numbers.is_some_and(|(a, b)| a >= b),
            Op::Lt => numbers.is_some_and(|(a, b)| a < b),
            Op::Lte => numbers.is_some_and(|(a, b)| a <= b),
            Op::Exists => unreachable!(),
        }
    }
}

/// Last path segment: `attributes.merchant_id` → `merchant_id`.
fn short_name(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

/// Grouping key of an event for `group_by` fields, e.g.
/// `merchant_id=mer_123,provider=a`. Empty when there are no group fields.
/// Missing fields group under an empty value (`merchant_id=`).
pub fn group_key(ev: &AgentEvent, group_by: &[String]) -> String {
    group_by
        .iter()
        .map(|f| {
            let v = field_value(ev, f)
                .map(|v| value_text(&v))
                .unwrap_or_default();
            format!("{}={}", short_name(f), v)
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Fill `{field.path}` slots in a template from an event: any path
/// `field_value` understands (`{attributes.merchant_id}`, `{subject}`,
/// `{measurements.conversion_rate}`, ...), plus `{count}` and the legacy
/// `{host}` / `{service}`. Unknown slots are left as-is.
pub fn fill(tpl: &str, ev: &AgentEvent, count: usize) -> String {
    let mut out = String::with_capacity(tpl.len());
    let mut rest = tpl;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = &after[..end];
        let value = match name {
            "count" => Some(count.to_string()),
            "host" => Some(ev.host_id.clone()),
            _ => field_value(ev, name).map(|v| value_text(&v)),
        };
        match value {
            Some(v) => out.push_str(&v),
            None => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev() -> AgentEvent {
        let mut e = AgentEvent {
            kind: wt_common::EventType::parse("payment.request_failed").unwrap(),
            source: "payment-api".into(),
            subject: "merchant:mer_1".into(),
            ..Default::default()
        };
        e.attributes.insert("merchant_id".into(), json!("mer_1"));
        e.attributes.insert("status_code".into(), json!(502));
        e.measurements.insert("conversion_rate".into(), 0.63);
        e
    }

    fn cond(field: &str, op: Op, value: Value) -> Condition {
        Condition {
            field: field.into(),
            op,
            value: Some(value),
        }
    }

    #[test]
    fn conditions_compare_numbers_and_text() {
        let e = ev();
        assert!(cond("attributes.status_code", Op::Gte, json!(500)).matches(&e));
        assert!(!cond("attributes.status_code", Op::Lt, json!(500)).matches(&e));
        assert!(cond("attributes.status_code", Op::Eq, json!("502")).matches(&e));
        assert!(cond("measurements.conversion_rate", Op::Lt, json!(0.7)).matches(&e));
        assert!(cond("attributes.merchant_id", Op::Eq, json!("mer_1")).matches(&e));
        assert!(cond("attributes.merchant_id", Op::Neq, json!("mer_2")).matches(&e));
        assert!(cond("service", Op::Eq, json!("payment-api")).matches(&e));
        // missing field: only neq holds; ordering never does
        assert!(!cond("attributes.nope", Op::Gt, json!(1)).matches(&e));
        assert!(cond("attributes.nope", Op::Neq, json!(1)).matches(&e));
        let exists = Condition {
            field: "attributes.merchant_id".into(),
            op: Op::Exists,
            value: None,
        };
        assert!(exists.matches(&e));
        // text is never ordered
        assert!(!cond("attributes.merchant_id", Op::Gt, json!(1)).matches(&e));
    }

    #[test]
    fn op_accepts_names_and_symbols() {
        #[derive(Deserialize)]
        struct W {
            op: Op,
        }
        for (s, op) in [
            ("gte", Op::Gte),
            (">=", Op::Gte),
            ("==", Op::Eq),
            ("<", Op::Lt),
        ] {
            let w: W = toml::from_str(&format!("op = {s:?}")).unwrap();
            assert_eq!(w.op, op);
        }
    }

    #[test]
    fn group_key_is_deterministic() {
        let e = ev();
        assert_eq!(
            group_key(&e, &["attributes.merchant_id".into(), "source".into()]),
            "merchant_id=mer_1,source=payment-api"
        );
        assert_eq!(group_key(&e, &["attributes.nope".into()]), "nope=");
        assert_eq!(group_key(&e, &[]), "");
    }

    #[test]
    fn templates_fill_event_fields() {
        let e = ev();
        assert_eq!(
            fill(
                "{count} failures for {attributes.merchant_id} ({subject}, {unknown})",
                &e,
                12
            ),
            "12 failures for mer_1 (merchant:mer_1, {unknown})"
        );
        assert_eq!(
            fill("rate {measurements.conversion_rate}", &e, 1),
            "rate 0.63"
        );
        assert_eq!(fill("no slots", &e, 1), "no slots");
        assert_eq!(fill("unclosed {x", &e, 1), "unclosed {x");
    }
}
