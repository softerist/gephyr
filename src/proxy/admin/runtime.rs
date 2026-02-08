use super::*;

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogsCountRequest {
    #[serde(default)]
    filter: String,
    #[serde(default)]
    errors_only: bool,
}

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
    let new_config = payload.config;
    config::save_app_config(&new_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    state.config.apply_proxy_config(&new_config.proxy).await;

    Ok(StatusCode::OK)
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

pub(crate) async fn admin_start_proxy_service(State(state): State<AdminState>) -> impl IntoResponse {
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
    Path(_id): Path<String>,
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

pub(crate) async fn admin_get_proxy_logs_count_filtered(
    Query(params): Query<LogsCountRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(move || {
        proxy_db::get_logs_count_filtered(&params.filter, params.errors_only)
    })
    .await;

    match res {
        Ok(Ok(count)) => Ok(Json(count)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

pub(crate) async fn admin_clear_proxy_logs() -> impl IntoResponse {
    let _ = tokio::task::spawn_blocking(|| {
        if let Err(e) = proxy_db::clear_logs() {
            logger::log_error(&format!("[API] Failed to clear proxy logs: {}", e));
        }
    })
    .await;
    logger::log_info("[API] All proxy logs cleared");
    StatusCode::OK
}

pub(crate) async fn admin_get_proxy_log_detail(
    Path(log_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res =
        tokio::task::spawn_blocking(move || crate::modules::persistence::proxy_db::get_log_detail(&log_id))
            .await;

    match res {
        Ok(Ok(log)) => Ok(Json(log)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogsFilterQuery {
    #[serde(default)]
    filter: String,
    #[serde(default)]
    errors_only: bool,
    #[serde(default)]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

pub(crate) async fn admin_get_proxy_logs_filtered(
    Query(params): Query<LogsFilterQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(move || {
        crate::modules::persistence::proxy_db::get_logs_filtered(
            &params.filter,
            params.errors_only,
            params.limit,
            params.offset,
        )
    })
    .await;

    match res {
        Ok(Ok(logs)) => Ok(Json(logs)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

pub(crate) async fn admin_get_proxy_stats(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let stats = state.core.monitor.get_stats().await;
    Ok(Json(stats))
}

pub(crate) async fn admin_get_data_dir_path() -> impl IntoResponse {
    match crate::modules::auth::account::get_data_dir() {
        Ok(p) => Json(p.to_string_lossy().to_string()),
        Err(e) => Json(format!("Error: {}", e)),
    }
}

pub(crate) async fn admin_list_user_tokens(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let tokens = crate::commands::user_token::list_user_tokens()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(tokens))
}

pub(crate) async fn admin_get_user_token_summary(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let summary = crate::commands::user_token::get_user_token_summary()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(summary))
}

pub(crate) async fn admin_create_user_token(
    Json(payload): Json<crate::commands::user_token::CreateTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let token = crate::commands::user_token::create_user_token(payload)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(token))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RenewTokenRequest {
    expires_type: String,
}

pub(crate) async fn admin_renew_user_token(
    Path(id): Path<String>,
    Json(payload): Json<RenewTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::user_token::renew_user_token(id, payload.expires_type)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(StatusCode::OK)
}

pub(crate) async fn admin_delete_user_token(
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::user_token::delete_user_token(id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn admin_update_user_token(
    Path(id): Path<String>,
    Json(payload): Json<crate::commands::user_token::UpdateTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::user_token::update_user_token(id, payload)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(StatusCode::OK)
}

pub(crate) async fn admin_should_check_updates(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let settings = crate::modules::system::update_checker::load_update_settings().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let should = crate::modules::system::update_checker::should_check_for_updates(&settings);
    Ok(Json(should))
}

pub(crate) async fn admin_get_antigravity_path(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let path = crate::commands::get_antigravity_path(Some(true))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(path))
}

pub(crate) async fn admin_get_antigravity_args(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let args = crate::commands::get_antigravity_args().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(args))
}

pub(crate) async fn admin_clear_antigravity_cache(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = crate::commands::clear_antigravity_cache()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(res))
}

pub(crate) async fn admin_get_antigravity_cache_paths(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = crate::commands::get_antigravity_cache_paths()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(res))
}

pub(crate) async fn admin_clear_log_cache(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::clear_log_cache().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}


