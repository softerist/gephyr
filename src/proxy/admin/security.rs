#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IpAccessLogQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_page_size")]
    page_size: usize,
    search: Option<String>,
    #[serde(default)]
    blocked_only: bool,
}

fn default_page() -> usize {
    1
}
fn default_page_size() -> usize {
    50
}

#[derive(Serialize)]
pub(crate) struct IpAccessLogResponse {
    logs: Vec<crate::modules::persistence::security_db::IpAccessLog>,
    total: usize,
}

pub(crate) async fn admin_get_ip_access_logs(
    Query(q): Query<IpAccessLogQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let offset = (q.page.max(1) - 1) * q.page_size;
    let logs =
        security_db::get_ip_access_logs(q.page_size, offset, q.search.as_deref(), q.blocked_only)
            .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    let total = logs.len();

    Ok(Json(IpAccessLogResponse { logs, total }))
}

pub(crate) async fn admin_clear_ip_access_logs(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    security_db::clear_ip_access_logs().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

#[derive(Serialize)]
pub(crate) struct IpStatsResponse {
    total_requests: usize,
    unique_ips: usize,
    blocked_requests: usize,
    top_ips: Vec<crate::modules::persistence::security_db::IpRanking>,
}

pub(crate) async fn admin_get_ip_stats(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let stats = security_db::get_ip_stats().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let top_ips = security_db::get_top_ips(10, 24).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let response = IpStatsResponse {
        total_requests: stats.total_requests as usize,
        unique_ips: stats.unique_ips as usize,
        blocked_requests: stats.blocked_count as usize,
        top_ips,
    };
    Ok(Json(response))
}

#[derive(Deserialize)]
pub(crate) struct IpTokenStatsQuery {
    limit: Option<usize>,
    hours: Option<i64>,
}

pub(crate) async fn admin_get_ip_token_stats(
    Query(q): Query<IpTokenStatsQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let stats = proxy_db::get_token_usage_by_ip(q.limit.unwrap_or(100), q.hours.unwrap_or(720))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(stats))
}

pub(crate) async fn admin_get_ip_blacklist(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let list = security_db::get_blacklist().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(list))
}

#[derive(Deserialize)]
pub(crate) struct AddBlacklistRequest {
    ip_pattern: String,
    reason: Option<String>,
    expires_at: Option<i64>,
}

pub(crate) async fn admin_add_ip_to_blacklist(
    Json(req): Json<AddBlacklistRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    security_db::add_to_blacklist(
        &req.ip_pattern,
        req.reason.as_deref(),
        req.expires_at,
        "manual",
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoveIpRequest {
    ip_pattern: String,
}

pub(crate) async fn admin_remove_ip_from_blacklist(
    Query(q): Query<RemoveIpRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_blacklist().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    if let Some(entry) = entries.iter().find(|e| e.ip_pattern == q.ip_pattern) {
        security_db::remove_from_blacklist(&entry.id).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    } else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("IP pattern {} not found", q.ip_pattern),
            }),
        ));
    }

    Ok(StatusCode::OK)
}

pub(crate) async fn admin_clear_ip_blacklist(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_blacklist().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    for entry in entries {
        security_db::remove_from_blacklist(&entry.ip_pattern).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckIpQuery {
    ip: String,
}

pub(crate) async fn admin_check_ip_in_blacklist(
    Query(q): Query<CheckIpQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let result = security_db::is_ip_in_blacklist(&q.ip).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(serde_json::json!({ "result": result })))
}

pub(crate) async fn admin_get_ip_whitelist(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let list = security_db::get_whitelist().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(list))
}

#[derive(Deserialize)]
pub(crate) struct AddWhitelistRequest {
    ip_pattern: String,
    description: Option<String>,
}

pub(crate) async fn admin_add_ip_to_whitelist(
    Json(req): Json<AddWhitelistRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    security_db::add_to_whitelist(&req.ip_pattern, req.description.as_deref()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::CREATED)
}

pub(crate) async fn admin_remove_ip_from_whitelist(
    Query(q): Query<RemoveIpRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_whitelist().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    if let Some(entry) = entries.iter().find(|e| e.ip_pattern == q.ip_pattern) {
        security_db::remove_from_whitelist(&entry.id).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    } else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("IP pattern {} not found", q.ip_pattern),
            }),
        ));
    }
    Ok(StatusCode::OK)
}

pub(crate) async fn admin_clear_ip_whitelist(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_whitelist().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    for entry in entries {
        security_db::remove_from_whitelist(&entry.ip_pattern).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    }
    Ok(StatusCode::OK)
}

pub(crate) async fn admin_check_ip_in_whitelist(
    Query(q): Query<CheckIpQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let result = security_db::is_ip_in_whitelist(&q.ip).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(serde_json::json!({ "result": result })))
}

pub(crate) async fn admin_get_security_config(
    State(_state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let app_config = crate::modules::system::config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(app_config.proxy.security_monitor))
}

#[derive(Deserialize)]
pub(crate) struct UpdateSecurityConfigWrapper {
    config: crate::proxy::config::SecurityMonitorConfig,
}

pub(crate) async fn admin_update_security_config(
    State(state): State<AdminState>,
    Json(payload): Json<UpdateSecurityConfigWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = payload.config;
    let mut app_config = crate::modules::system::config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    app_config.proxy.security_monitor = config.clone();

    crate::modules::system::config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    {
        let mut sec = state.config.security.write().await;
        *sec = crate::proxy::ProxySecurityConfig::from_proxy_config(&app_config.proxy);
        tracing::info!("[Security] Runtime security config hot-reloaded via Web API");
    }

    Ok(StatusCode::OK)
}

