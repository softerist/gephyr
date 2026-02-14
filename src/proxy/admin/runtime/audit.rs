use axum::http::{header, HeaderMap};
use serde_json::{json, Value};

use super::audit_event::{ActorIdentity, AdminAuditEvent};
use crate::proxy::config::ProxyConfig;
use crate::proxy::state::AdminState;

fn extract_auth_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").or(Some(s)))
        .or_else(|| headers.get("x-api-key").and_then(|h| h.to_str().ok()))
        .or_else(|| headers.get("x-goog-api-key").and_then(|h| h.to_str().ok()))
}

fn extract_request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            headers
                .get("x-correlation-id")
                .and_then(|h| h.to_str().ok())
        })
        .or_else(|| headers.get("x-trace-id").and_then(|h| h.to_str().ok()))
        .map(|s| s.to_string())
}

pub(crate) async fn resolve_admin_actor(state: &AdminState, headers: &HeaderMap) -> ActorIdentity {
    let request_id = extract_request_id(headers);
    let Some(token) = extract_auth_token(headers) else {
        return ActorIdentity::new("unknown", None, "unknown", request_id);
    };

    if let Ok(Some(user_token)) =
        crate::modules::persistence::user_token_db::get_token_by_value(token)
    {
        return ActorIdentity::new(
            "user_token",
            Some(user_token.id.clone()),
            format!("user_token:{}:{}", user_token.username, user_token.id),
            request_id,
        );
    }

    let security = state.config.security.read().await.clone();
    if let Some(admin_password) = security.admin_password.as_deref() {
        if !admin_password.is_empty() && token == admin_password {
            return ActorIdentity::new("admin_password", None, "admin_password", request_id);
        }
    }
    if token == security.api_key {
        return ActorIdentity::new("api_key", None, "api_key", request_id);
    }

    ActorIdentity::new("unknown", None, "unknown", request_id)
}

pub(crate) fn summarize_proxy_config(proxy: &ProxyConfig) -> Value {
    json!({
        "enabled": proxy.enabled,
        "allow_lan_access": proxy.allow_lan_access,
        "auth_mode": proxy.auth_mode,
        "port": proxy.port,
        "auto_start": proxy.auto_start,
        "request_timeout": proxy.request_timeout,
        "persist_session_bindings": proxy.persist_session_bindings,
        "scheduling": proxy.scheduling,
        "preferred_account_id": proxy.preferred_account_id,
        "compliance": proxy.compliance,
        "custom_mapping_entries": proxy.custom_mapping.len(),
        "api_key_set": !proxy.api_key.trim().is_empty(),
        "admin_password_set": proxy
            .admin_password
            .as_deref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false),
        "upstream_proxy_enabled": proxy.upstream_proxy.enabled,
        "upstream_proxy_url_set": !proxy.upstream_proxy.url.trim().is_empty(),
        "zai_enabled": proxy.zai.enabled,
        "zai_dispatch_mode": proxy.zai.dispatch_mode,
        "user_agent_override_set": proxy.user_agent_override.is_some(),
        "saved_user_agent_set": proxy.saved_user_agent.is_some(),
    })
}

pub(crate) fn log_admin_audit(action: &str, actor: &ActorIdentity, details: Value) {
    let event = AdminAuditEvent::from_parts(action, actor, details.clone());
    match serde_json::to_string(&event) {
        Ok(payload) => {
            crate::modules::system::logger::log_info(&format!("[ADMIN_AUDIT] {}", payload))
        }
        Err(_) => crate::modules::system::logger::log_info(&format!(
            "[ADMIN_AUDIT] action={} actor={} details={}",
            action, actor.actor_label, details
        )),
    }
}