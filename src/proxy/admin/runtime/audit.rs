use axum::http::{header, HeaderMap};
use serde_json::{json, Value};

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

pub(crate) async fn resolve_admin_actor(state: &AdminState, headers: &HeaderMap) -> String {
    let Some(token) = extract_auth_token(headers) else {
        return "unknown".to_string();
    };

    if let Ok(Some(user_token)) =
        crate::modules::persistence::user_token_db::get_token_by_value(token)
    {
        return format!("user_token:{}:{}", user_token.username, user_token.id);
    }

    let security = state.config.security.read().await.clone();
    if let Some(admin_password) = security.admin_password.as_deref() {
        if !admin_password.is_empty() && token == admin_password {
            return "admin_password".to_string();
        }
    }
    if token == security.api_key {
        return "api_key".to_string();
    }

    "unknown".to_string()
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

pub(crate) fn log_admin_audit(action: &str, actor: &str, details: Value) {
    crate::modules::system::logger::log_info(&format!(
        "[ADMIN_AUDIT] action={} actor={} details={}",
        action, actor, details
    ));
}
