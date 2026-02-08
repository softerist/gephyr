mod admin;

use axum::{
    routing::{get, post},
    Router,
};

use crate::proxy::handlers;
use crate::proxy::middleware::{auth_middleware, ip_filter_middleware, monitor_middleware};
use crate::proxy::state::AppState;

pub use admin::build_admin_routes;

pub fn build_proxy_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/health", get(crate::proxy::health::health_check_handler))
        .route("/healthz", get(crate::proxy::health::health_check_handler))
        .route("/v1/models", get(handlers::openai::handle_list_models))
        .route(
            "/v1/chat/completions",
            post(handlers::openai::handle_chat_completions),
        )
        .route(
            "/v1/completions",
            post(handlers::openai::handle_completions),
        )
        .route("/v1/responses", post(handlers::openai::handle_completions))
        .route("/v1/messages", post(handlers::claude::handle_messages))
        .route(
            "/v1/messages/count_tokens",
            post(handlers::claude::handle_count_tokens),
        )
        .route(
            "/v1/models/claude",
            get(handlers::claude::handle_list_models),
        )
        .route("/v1beta/models", get(handlers::gemini::handle_list_models))
        .route(
            "/v1beta/models/:model",
            get(handlers::gemini::handle_get_model).post(handlers::gemini::handle_generate),
        )
        .route(
            "/v1beta/models/:model/countTokens",
            post(handlers::gemini::handle_count_tokens),
        )
        .route(
            "/v1/models/detect",
            post(handlers::common::handle_detect_model),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            monitor_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ip_filter_middleware,
        ))
}
