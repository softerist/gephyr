use crate::proxy::admin::ErrorResponse;
use axum::{
    extract::{Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
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

