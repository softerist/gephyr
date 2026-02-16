use crate::proxy::admin::ErrorResponse;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
};
pub(crate) async fn admin_get_data_dir_path() -> impl IntoResponse {
    match crate::modules::auth::account::get_data_dir() {
        Ok(p) => Json(p.to_string_lossy().to_string()),
        Err(e) => Json(format!("Error: {}", e)),
    }
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
