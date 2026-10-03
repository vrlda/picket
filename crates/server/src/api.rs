use picket_common::AgentEvent;
use serde::Deserialize;

/// POST /v1/telemetry body.
#[derive(Debug, Deserialize)]
pub struct TelemetryPayload {
    pub batch: Vec<AgentEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_common::{EventKind, Heartbeat};

    #[test]
    fn telemetry_batch_payload_deserializes() {
        let body = r#"{"batch":[{"id":"e-1","ts":1000,"host_id":"h-1","key":"svc:nginx","kind":"ServiceFailed","severity":"Critical","summary":"nginx failed","evidence":[]}]}"#;
        let p: TelemetryPayload = serde_json::from_str(body).unwrap();
        assert_eq!(p.batch.len(), 1);
        assert_eq!(p.batch[0].kind, EventKind::ServiceFailed);
    }

    #[test]
    fn telemetry_payload_rejects_unknown_kind() {
        let body = r#"{"batch":[{"id":"e-1","ts":1000,"host_id":"h-1","key":"k","kind":"Bogus","severity":"Critical","summary":"x","evidence":[]}]}"#;
        assert!(serde_json::from_str::<TelemetryPayload>(body).is_err());
    }

    #[test]
    fn telemetry_payload_accepts_empty_batch() {
        let body = r#"{"batch":[]}"#;
        let p = serde_json::from_str::<TelemetryPayload>(body).unwrap();
        assert!(p.batch.is_empty());
    }

    #[test]
    fn heartbeat_payload_deserializes() {
        let body = r#"{"host_id":"h-1","ts":9,"version":"0.1.0","queue_len":3}"#;
        let h: Heartbeat = serde_json::from_str(body).unwrap();
        assert_eq!(h.queue_len, 3);
    }
}
