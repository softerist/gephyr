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
