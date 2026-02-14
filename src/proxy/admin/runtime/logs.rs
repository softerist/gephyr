use crate::modules::{persistence::proxy_db, system::logger};
use crate::proxy::admin::ErrorResponse;
use crate::proxy::state::AdminState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Deserialize;
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogsCountRequest {
    #[serde(default)]
    filter: String,
    #[serde(default)]
    errors_only: bool,
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
    let res = tokio::task::spawn_blocking(move || {
        crate::modules::persistence::proxy_db::get_log_detail(&log_id)
    })
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