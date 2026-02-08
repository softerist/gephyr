use axum::response::{IntoResponse, Json, Response};

pub async fn health_check_handler() -> Response {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
    .into_response()
}
