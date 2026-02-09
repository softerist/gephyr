use super::audit;
use crate::models::AppConfig;
use crate::modules::system::config;
use crate::proxy::admin::ErrorResponse;
use crate::proxy::state::AdminState;
use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
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
    headers: HeaderMap,
    Json(payload): Json<SaveConfigWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let actor = audit::resolve_admin_actor(&state, &headers).await;
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
    audit::log_admin_audit(
        "save_config",
        &actor,
        serde_json::json!({
            "before": audit::summarize_proxy_config(&existing_config.proxy),
            "after": audit::summarize_proxy_config(&new_config.proxy),
            "warnings": warnings,
        }),
    );

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

fn proxy_pool_runtime_snapshot(
    config: &crate::proxy::config::ProxyPoolConfig,
) -> serde_json::Value {
    let total = config.proxies.len();
    let enabled = config.proxies.iter().filter(|p| p.enabled).count();
    serde_json::json!({
        "strategy": config.strategy,
        "enabled": config.enabled,
        "auto_failover": config.auto_failover,
        "health_check_interval": config.health_check_interval,
        "proxies_total": total,
        "proxies_enabled": enabled
    })
}

pub(crate) async fn admin_get_proxy_pool_strategy(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = state.runtime.proxy_pool_state.read().await;
    Ok(Json(proxy_pool_runtime_snapshot(&config)))
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct UpdateProxyPoolStrategyRequest {
    #[serde(
        default,
        alias = "proxySelectionStrategy",
        alias = "proxy_selection_strategy"
    )]
    strategy: Option<crate::proxy::config::ProxySelectionStrategy>,
}

pub(crate) async fn admin_update_proxy_pool_strategy(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateProxyPoolStrategyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let actor = audit::resolve_admin_actor(&state, &headers).await;
    let strategy = payload.strategy.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "strategy is required".to_string(),
            }),
        )
    })?;

    let mut app_config = config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let before_strategy = app_config.proxy.proxy_pool.strategy.clone();
    app_config.proxy.proxy_pool.strategy = strategy.clone();

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

    config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    {
        let mut runtime_cfg = state.runtime.proxy_pool_state.write().await;
        runtime_cfg.strategy = strategy.clone();
    }
    let runtime_cfg = state.runtime.proxy_pool_state.read().await;
    let total = runtime_cfg.proxies.len();
    let enabled = runtime_cfg.proxies.iter().filter(|p| p.enabled).count();

    audit::log_admin_audit(
        "update_proxy_pool_strategy",
        &actor,
        serde_json::json!({
            "before": {
                "strategy": before_strategy
            },
            "after": {
                "strategy": runtime_cfg.strategy
            }
        }),
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "saved": true,
        "message": "Proxy pool strategy updated",
        "proxy_pool": {
            "strategy": runtime_cfg.strategy,
            "enabled": runtime_cfg.enabled,
            "auto_failover": runtime_cfg.auto_failover,
            "health_check_interval": runtime_cfg.health_check_interval,
            "proxies_total": total,
            "proxies_enabled": enabled
        }
    })))
}

pub(crate) async fn admin_get_proxy_pool_runtime(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = state.runtime.proxy_pool_state.read().await;
    Ok(Json(proxy_pool_runtime_snapshot(&config)))
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct UpdateProxyPoolRuntimeRequest {
    #[serde(default, alias = "poolEnabled", alias = "pool_enabled")]
    enabled: Option<bool>,
    #[serde(default, alias = "autoFailover")]
    auto_failover: Option<bool>,
    #[serde(
        default,
        alias = "healthCheckInterval",
        alias = "healthCheckIntervalSeconds"
    )]
    health_check_interval: Option<u64>,
}

pub(crate) async fn admin_update_proxy_pool_runtime(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateProxyPoolRuntimeRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let actor = audit::resolve_admin_actor(&state, &headers).await;
    if payload.enabled.is_none()
        && payload.auto_failover.is_none()
        && payload.health_check_interval.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error:
                    "At least one of enabled, auto_failover, health_check_interval must be provided"
                        .to_string(),
            }),
        ));
    }

    let mut app_config = config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let before_runtime = proxy_pool_runtime_snapshot(&app_config.proxy.proxy_pool);

    if let Some(enabled) = payload.enabled {
        app_config.proxy.proxy_pool.enabled = enabled;
    }
    if let Some(auto_failover) = payload.auto_failover {
        app_config.proxy.proxy_pool.auto_failover = auto_failover;
    }
    if let Some(health_check_interval) = payload.health_check_interval {
        app_config.proxy.proxy_pool.health_check_interval = health_check_interval;
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

    config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let after_runtime;
    {
        let mut runtime_cfg = state.runtime.proxy_pool_state.write().await;
        if let Some(enabled) = payload.enabled {
            runtime_cfg.enabled = enabled;
        }
        if let Some(auto_failover) = payload.auto_failover {
            runtime_cfg.auto_failover = auto_failover;
        }
        if let Some(health_check_interval) = payload.health_check_interval {
            runtime_cfg.health_check_interval = health_check_interval;
        }
        after_runtime = proxy_pool_runtime_snapshot(&runtime_cfg);
    }

    audit::log_admin_audit(
        "update_proxy_pool_runtime",
        &actor,
        serde_json::json!({
            "before": before_runtime,
            "after": after_runtime
        }),
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "saved": true,
        "message": "Proxy pool runtime config updated",
        "proxy_pool": after_runtime
    })))
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
