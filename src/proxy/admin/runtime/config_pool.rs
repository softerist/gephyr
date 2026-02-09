use crate::models::AppConfig;
use crate::modules::system::config;
use crate::proxy::admin::ErrorResponse;
use crate::proxy::state::AdminState;
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
pub(crate) async fn admin_get_config(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let cfg = config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(cfg))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SaveConfigWrapper {
    config: AppConfig,
}

pub(crate) async fn admin_save_config(
    State(state): State<AdminState>,
    Json(payload): Json<SaveConfigWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut new_config = payload.config;
    let existing_config = config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let mut warnings: Vec<&'static str> = Vec::new();
    if new_config.proxy.api_key.trim().is_empty() {
        new_config.proxy.api_key = existing_config.proxy.api_key.clone();
        warnings.push("proxy.api_key_preserved_from_existing");
    }
    if let Err(errors) = crate::modules::system::validation::validate_app_config(&new_config) {
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

    config::save_app_config(&new_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    state.config.apply_proxy_config(&new_config.proxy).await;
    state
        .core
        .token_manager
        .update_sticky_config(new_config.proxy.scheduling.clone())
        .await;
    state
        .core
        .token_manager
        .update_session_binding_persistence(new_config.proxy.persist_session_bindings);
    state
        .core
        .token_manager
        .update_compliance_config(new_config.proxy.compliance.clone())
        .await;
    if let Some(account_id) = new_config.proxy.preferred_account_id.clone() {
        state
            .core
            .token_manager
            .set_preferred_account(Some(account_id))
            .await;
    } else {
        state.core.token_manager.set_preferred_account(None).await;
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "saved": true,
        "message": "Config updated",
        "warnings": warnings
    })))
}
pub(crate) async fn admin_get_proxy_pool_config(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = state.runtime.proxy_pool_state.read().await;
    Ok(Json(config.clone()))
}
pub(crate) async fn admin_get_all_account_bindings(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let bindings = state.runtime.proxy_pool_manager.get_all_bindings_snapshot();
    Ok(Json(bindings))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BindAccountProxyRequest {
    account_id: String,
    proxy_id: String,
}

pub(crate) async fn admin_bind_account_proxy(
    State(state): State<AdminState>,
    Json(payload): Json<BindAccountProxyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .runtime
        .proxy_pool_manager
        .bind_account_to_proxy(payload.account_id, payload.proxy_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(StatusCode::OK)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnbindAccountProxyRequest {
    account_id: String,
}

pub(crate) async fn admin_unbind_account_proxy(
    State(state): State<AdminState>,
    Json(payload): Json<UnbindAccountProxyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .runtime
        .proxy_pool_manager
        .unbind_account_proxy(payload.account_id)
        .await;
    Ok(StatusCode::OK)
}
pub(crate) async fn admin_get_account_proxy_binding(
    State(state): State<AdminState>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let binding = state
        .runtime
        .proxy_pool_manager
        .get_account_binding(&account_id);
    Ok(Json(binding))
}
pub(crate) async fn admin_trigger_proxy_health_check(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .runtime
        .proxy_pool_manager
        .health_check()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    let config = state.runtime.proxy_pool_state.read().await;
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Health check completed",
        "proxies": config.proxies,
    })))
}
