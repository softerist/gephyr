use super::audit;
use crate::modules::system::logger;
use crate::proxy::admin::ErrorResponse;
use crate::proxy::state::AdminState;
use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::Ordering;
pub(crate) async fn admin_get_proxy_status(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let active_accounts = state.core.token_manager.len();

    let is_running = { *state.runtime.is_running.read().await };
    Ok(Json(serde_json::json!({
        "running": is_running,
        "port": state.runtime.port,
        "base_url": format!("http://127.0.0.1:{}", state.runtime.port),
        "active_accounts": active_accounts,
    })))
}

pub(crate) async fn admin_get_version_routes() -> impl IntoResponse {
    let routes = crate::proxy::routes::admin_version_route_capabilities();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "routes": routes
    }))
}

pub(crate) async fn admin_start_proxy_service(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    if let Ok(mut config) = crate::modules::system::config::load_app_config() {
        config.proxy.auto_start = true;
        let _ = crate::modules::system::config::save_app_config(&config);
    }
    if let Err(e) = state.core.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to enable service and load accounts: {}",
            e
        ));
    }

    let mut running = state.runtime.is_running.write().await;
    *running = true;
    logger::log_info("[API] Proxy service enabled (Persistence synced)");
    StatusCode::OK
}

pub(crate) async fn admin_stop_proxy_service(State(state): State<AdminState>) -> impl IntoResponse {
    if let Ok(mut config) = crate::modules::system::config::load_app_config() {
        config.proxy.auto_start = false;
        let _ = crate::modules::system::config::save_app_config(&config);
    }

    let mut running = state.runtime.is_running.write().await;
    *running = false;
    logger::log_info("[API] Proxy service disabled (Axum mode / Persistence synced)");
    StatusCode::OK
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateMappingWrapper {
    config: crate::proxy::config::ProxyConfig,
}

fn model_mapping_change_details(
    before: &HashMap<String, String>,
    after: &HashMap<String, String>,
) -> serde_json::Value {
    let before_keys: BTreeSet<String> = before.keys().cloned().collect();
    let after_keys: BTreeSet<String> = after.keys().cloned().collect();

    let mut added: Vec<String> = after_keys.difference(&before_keys).cloned().collect();
    let mut removed: Vec<String> = before_keys.difference(&after_keys).cloned().collect();
    let mut updated: Vec<String> = after_keys
        .intersection(&before_keys)
        .filter_map(|key| {
            let before_value = before.get(key)?;
            let after_value = after.get(key)?;
            if before_value != after_value {
                Some(key.clone())
            } else {
                None
            }
        })
        .collect();

    added.sort();
    removed.sort();
    updated.sort();

    serde_json::json!({
        "before_entries": before.len(),
        "after_entries": after.len(),
        "delta": {
            "added_count": added.len(),
            "removed_count": removed.len(),
            "updated_count": updated.len(),
            "added_models": added,
            "removed_models": removed,
            "updated_models": updated
        }
    })
}

pub(crate) async fn admin_update_model_mapping(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateMappingWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let actor = audit::resolve_admin_actor(&state, &headers).await;
    let config = payload.config;
    {
        let mut mapping = state.config.custom_mapping.write().await;
        *mapping = config.custom_mapping.clone();
    }
    let mut app_config = crate::modules::system::config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let before_mapping = app_config.proxy.custom_mapping.clone();
    app_config.proxy.custom_mapping = config.custom_mapping;

    crate::modules::system::config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    logger::log_info("[API] Model mapping hot-reloaded via API and saved");
    audit::log_admin_audit(
        "update_model_mapping",
        &actor,
        model_mapping_change_details(&before_mapping, &app_config.proxy.custom_mapping),
    );
    Ok(StatusCode::OK)
}

pub(crate) async fn admin_generate_api_key() -> impl IntoResponse {
    let new_key = format!("sk-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
    Json(new_key)
}

pub(crate) async fn admin_clear_proxy_session_bindings(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    state.core.token_manager.clear_all_sessions();
    logger::log_info("[API] All session bindings cleared");
    StatusCode::OK
}

pub(crate) async fn admin_get_proxy_session_bindings(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    Json(state.core.token_manager.get_sticky_debug_snapshot())
}

pub(crate) async fn admin_get_proxy_sticky_config(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let sticky = state.core.token_manager.get_sticky_debug_snapshot();
    let preferred_account_id = state.core.token_manager.get_preferred_account().await;
    Json(serde_json::json!({
        "persist_session_bindings": sticky.persist_session_bindings,
        "scheduling": sticky.scheduling,
        "preferred_account_id": preferred_account_id
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct UpdateStickyConfigRequest {
    #[serde(default, alias = "persistSessionBindings")]
    persist_session_bindings: Option<bool>,
    #[serde(default)]
    scheduling: Option<crate::proxy::sticky_config::StickySessionConfig>,
}

pub(crate) async fn admin_update_proxy_sticky_config(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateStickyConfigRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let actor = audit::resolve_admin_actor(&state, &headers).await;
    if payload.persist_session_bindings.is_none() && payload.scheduling.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "At least one of persist_session_bindings or scheduling must be provided"
                    .to_string(),
            }),
        ));
    }

    let mut app_config = crate::modules::system::config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let before_persist = app_config.proxy.persist_session_bindings;
    let before_scheduling = app_config.proxy.scheduling.clone();

    if let Some(enabled) = payload.persist_session_bindings {
        app_config.proxy.persist_session_bindings = enabled;
    }
    if let Some(scheduling) = payload.scheduling.clone() {
        app_config.proxy.scheduling = scheduling;
    }

    if let Err(errors) = crate::modules::system::validation::validate_app_config(&app_config) {
        let message = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: message }),
        ));
    }

    crate::modules::system::config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    if let Some(enabled) = payload.persist_session_bindings {
        state
            .core
            .token_manager
            .update_session_binding_persistence(enabled);
    }
    if let Some(scheduling) = payload.scheduling {
        state
            .core
            .token_manager
            .update_sticky_config(scheduling)
            .await;
    }

    let sticky = state.core.token_manager.get_sticky_debug_snapshot();
    logger::log_info("[API] Sticky config updated via API and saved");
    audit::log_admin_audit(
        "update_proxy_sticky",
        &actor,
        serde_json::json!({
            "before": {
                "persist_session_bindings": before_persist,
                "scheduling": before_scheduling
            },
            "after": {
                "persist_session_bindings": sticky.persist_session_bindings,
                "scheduling": sticky.scheduling
            }
        }),
    );
    Ok(Json(serde_json::json!({
        "ok": true,
        "saved": true,
        "message": "Sticky config updated",
        "sticky": {
            "persist_session_bindings": sticky.persist_session_bindings,
            "scheduling": sticky.scheduling
        }
    })))
}

pub(crate) async fn admin_get_proxy_request_timeout(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let timeout = state.config.request_timeout_secs();
    Json(serde_json::json!({
        "request_timeout": timeout,
        "effective_request_timeout": timeout.max(5)
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct UpdateRequestTimeoutRequest {
    #[serde(default, alias = "requestTimeout", alias = "requestTimeoutSeconds")]
    request_timeout: Option<u64>,
    #[serde(default, alias = "request_timeout_seconds")]
    request_timeout_seconds: Option<u64>,
}

pub(crate) async fn admin_update_proxy_request_timeout(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateRequestTimeoutRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let actor = audit::resolve_admin_actor(&state, &headers).await;
    let request_timeout = payload
        .request_timeout
        .or(payload.request_timeout_seconds)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "request_timeout is required".to_string(),
                }),
            )
        })?;

    let mut app_config = crate::modules::system::config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let before_request_timeout = app_config.proxy.request_timeout;
    app_config.proxy.request_timeout = request_timeout;
    if let Err(errors) = crate::modules::system::validation::validate_app_config(&app_config) {
        let message = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: message }),
        ));
    }
    crate::modules::system::config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    state
        .config
        .request_timeout
        .store(request_timeout, Ordering::Relaxed);
    logger::log_info("[API] Request timeout updated via API and saved");
    audit::log_admin_audit(
        "update_proxy_request_timeout",
        &actor,
        serde_json::json!({
            "before": {
                "request_timeout": before_request_timeout,
                "effective_request_timeout": before_request_timeout.max(5)
            },
            "after": {
                "request_timeout": request_timeout,
                "effective_request_timeout": request_timeout.max(5)
            }
        }),
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "saved": true,
        "message": "Request timeout updated",
        "request_timeout": request_timeout,
        "effective_request_timeout": request_timeout.max(5)
    })))
}

pub(crate) async fn admin_get_proxy_compliance_debug(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    Json(
        state
            .core
            .token_manager
            .get_compliance_debug_snapshot()
            .await,
    )
}

pub(crate) async fn admin_update_proxy_compliance(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(compliance): Json<crate::proxy::config::ComplianceConfig>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let actor = audit::resolve_admin_actor(&state, &headers).await;
    let mut app_config = crate::modules::system::config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let before_compliance = app_config.proxy.compliance.clone();
    app_config.proxy.compliance = compliance.clone();
    if let Err(errors) = crate::modules::system::validation::validate_app_config(&app_config) {
        let message = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: message }),
        ));
    }
    crate::modules::system::config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    state
        .core
        .token_manager
        .update_compliance_config(compliance)
        .await;
    logger::log_info("[API] Compliance config updated via API and saved");
    audit::log_admin_audit(
        "update_proxy_compliance",
        &actor,
        serde_json::json!({
            "before": before_compliance,
            "after": app_config.proxy.compliance
        }),
    );
    Ok(Json(serde_json::json!({
        "ok": true,
        "saved": true,
        "message": "Compliance config updated",
        "compliance": app_config.proxy.compliance
    })))
}

pub(crate) async fn admin_clear_all_rate_limits(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    state.core.token_manager.clear_all_rate_limits();
    logger::log_info("[API] All rate limit records cleared");
    StatusCode::OK
}

pub(crate) async fn admin_clear_rate_limit(
    State(state): State<AdminState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    let cleared = state.core.token_manager.clear_rate_limit(&account_id);
    if cleared {
        logger::log_info(&format!(
            "[API] Rate limit record for account {} cleared",
            account_id
        ));
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

pub(crate) async fn admin_get_preferred_account(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let pref = state.core.token_manager.get_preferred_account().await;
    Json(pref)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetPreferredAccountRequest {
    account_id: Option<String>,
}

pub(crate) async fn admin_set_preferred_account(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<SetPreferredAccountRequest>,
) -> impl IntoResponse {
    let actor = audit::resolve_admin_actor(&state, &headers).await;
    let before = state.core.token_manager.get_preferred_account().await;
    state
        .core
        .token_manager
        .set_preferred_account(payload.account_id.clone())
        .await;
    let after = state.core.token_manager.get_preferred_account().await;
    audit::log_admin_audit(
        "set_preferred_account",
        &actor,
        serde_json::json!({
            "before": { "preferred_account_id": before },
            "after": { "preferred_account_id": after }
        }),
    );
    StatusCode::OK
}

pub(crate) async fn admin_fetch_zai_models(
    Json(payload): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let zai_config = payload.get("zai").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing zai config".to_string(),
            }),
        )
    })?;

    let api_key = zai_config
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let base_url = zai_config
        .get("base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("https://api.z.ai");
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/v1/models", base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    let data: serde_json::Value = resp.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let models = data
        .get("data")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    m.get("id")
                        .and_then(|id| id.as_str().map(|s| s.to_string()))
                })
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    Ok(Json(models))
}

pub(crate) async fn admin_set_proxy_monitor_enabled(
    State(state): State<AdminState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let enabled = payload
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if state.core.monitor.is_enabled() != enabled {
        state.core.monitor.set_enabled(enabled);
        logger::log_info(&format!("[API] Monitor status set to: {}", enabled));
    }

    StatusCode::OK
}
