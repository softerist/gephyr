pub(crate) async fn admin_enable_debug_console() -> impl IntoResponse {
    crate::modules::system::log_bridge::enable_log_bridge();
    StatusCode::OK
}

pub(crate) async fn admin_disable_debug_console() -> impl IntoResponse {
    crate::modules::system::log_bridge::disable_log_bridge();
    StatusCode::OK
}

pub(crate) async fn admin_is_debug_console_enabled() -> impl IntoResponse {
    Json(crate::modules::system::log_bridge::is_log_bridge_enabled())
}

pub(crate) async fn admin_get_debug_console_logs() -> impl IntoResponse {
    let logs = crate::modules::system::log_bridge::get_buffered_logs();
    Json(logs)
}

pub(crate) async fn admin_clear_debug_console_logs() -> impl IntoResponse {
    crate::modules::system::log_bridge::clear_log_buffer();
    StatusCode::OK
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpencodeSyncStatusRequest {
    proxy_url: String,
}

pub(crate) async fn admin_get_opencode_sync_status(
    Json(payload): Json<OpencodeSyncStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::opencode_sync::get_opencode_sync_status(payload.proxy_url)
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpencodeSyncRequest {
    proxy_url: String,
    api_key: String,
    #[serde(default)]
    sync_accounts: bool,
}

pub(crate) async fn admin_execute_opencode_sync(
    Json(payload): Json<OpencodeSyncRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::opencode_sync::execute_opencode_sync(
        payload.proxy_url,
        payload.api_key,
        Some(payload.sync_accounts),
    )
    .await
    .map(|_| StatusCode::OK)
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })
}

pub(crate) async fn admin_execute_opencode_restore(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::opencode_sync::execute_opencode_restore()
        .await
        .map(|_| StatusCode::OK)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetOpencodeConfigRequest {
    file_name: Option<String>,
}

pub(crate) async fn admin_get_opencode_config_content(
    Json(payload): Json<GetOpencodeConfigRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let file_name = payload.file_name;
    tokio::task::spawn_blocking(move || {
        crate::proxy::opencode_sync::read_opencode_config_content(file_name)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?
    .map(Json)
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })
}

