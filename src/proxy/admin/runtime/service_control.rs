use crate::modules::system::logger;
use crate::proxy::admin::ErrorResponse;
use crate::proxy::state::AdminState;
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
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

pub(crate) async fn admin_update_model_mapping(
    State(state): State<AdminState>,
    Json(payload): Json<UpdateMappingWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
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

    app_config.proxy.custom_mapping = config.custom_mapping;

    crate::modules::system::config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    logger::log_info("[API] Model mapping hot-reloaded via API and saved");
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
    Json(payload): Json<SetPreferredAccountRequest>,
) -> impl IntoResponse {
    state
        .core
        .token_manager
        .set_preferred_account(payload.account_id)
        .await;
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
