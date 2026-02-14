use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ActorIdentity {
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub actor_label: String,
    pub request_id: Option<String>,
}

impl ActorIdentity {
    pub(crate) fn new(
        actor_type: impl Into<String>,
        actor_id: Option<String>,
        actor_label: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self {
            actor_type: actor_type.into(),
            actor_id,
            actor_label: actor_label.into(),
            request_id,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminAuditEvent {
    pub action: String,
    pub timestamp: String,
    pub request_id: Option<String>,
    pub actor: AdminAuditActor,
    pub details: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminAuditActor {
    pub kind: String,
    pub id: Option<String>,
    pub label: String,
}

impl AdminAuditEvent {
    pub(crate) fn from_parts(action: &str, actor: &ActorIdentity, details: Value) -> Self {
        Self {
            action: action.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: actor.request_id.clone(),
            actor: AdminAuditActor {
                kind: actor.actor_type.clone(),
                id: actor.actor_id.clone(),
                label: actor.actor_label.clone(),
            },
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_parts_builds_expected_audit_event() {
        let actor = ActorIdentity::new(
            "user_token",
            Some("token-123".to_string()),
            "user_token:alice:token-123",
            Some("req-789".to_string()),
        );
        let details = json!({
            "before": { "request_timeout": 60 },
            "after": { "request_timeout": 120 }
        });

        let event = AdminAuditEvent::from_parts("update_proxy_request_timeout", &actor, details);

        assert_eq!(event.action, "update_proxy_request_timeout");
        assert_eq!(event.request_id.as_deref(), Some("req-789"));
        assert_eq!(event.actor.kind, "user_token");
        assert_eq!(event.actor.id.as_deref(), Some("token-123"));
        assert_eq!(event.actor.label, "user_token:alice:token-123");
        assert_eq!(event.details["before"]["request_timeout"], json!(60));
        assert_eq!(event.details["after"]["request_timeout"], json!(120));
        assert!(
            !event.timestamp.is_empty(),
            "timestamp should be populated for audit event"
        );
    }
}