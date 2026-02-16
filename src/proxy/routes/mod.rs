mod admin;
mod admin_groups;

use axum::{
    routing::{get, post},
    Router,
};
use tracing::warn;

use crate::proxy::handlers;
use crate::proxy::health;
use crate::proxy::middleware::{
    auth_middleware, ip_filter_middleware, monitor_middleware, request_context_middleware,
};
use crate::proxy::state::AppState;

pub use admin::admin_version_route_capabilities;
pub use admin::build_admin_routes;

const DISABLE_PROMPT_ROUTES_ENV: &str = "GEPHYR_DISABLE_PROMPT_ROUTES";

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub fn build_proxy_routes(state: AppState) -> Router<AppState> {
    let disable_prompt_routes = env_truthy(DISABLE_PROMPT_ROUTES_ENV);
    if disable_prompt_routes {
        warn!(
            "[W-PROMPT-ROUTES-DISABLED] {} is enabled; generation routes are disabled for this run",
            DISABLE_PROMPT_ROUTES_ENV
        );
    }

    let gemini_model_route = if disable_prompt_routes {
        get(handlers::gemini::handle_get_model)
    } else {
        get(handlers::gemini::handle_get_model).post(handlers::gemini::handle_generate)
    };

    let mut router = Router::new()
        .route("/health", get(health::health_check_handler))
        .route("/internal/health", get(health::health_check_handler))
        .route(
            "/internal/status",
            get(handlers::common::handle_internal_status),
        )
        .route("/v1/models", get(handlers::openai::handle_list_models))
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
        .route("/v1beta/models/:model", gemini_model_route)
        .route(
            "/v1beta/models/:model/countTokens",
            post(handlers::gemini::handle_count_tokens),
        )
        .route(
            "/v1/models/detect",
            post(handlers::common::handle_detect_model),
        );

    if !disable_prompt_routes {
        router = router
            .route(
                "/v1/chat/completions",
                post(handlers::openai::handle_chat_completions),
            )
            .route(
                "/v1/completions",
                post(handlers::openai::handle_completions),
            )
            .route("/v1/responses", post(handlers::openai::handle_completions));
    }

    router
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
        .layer(axum::middleware::from_fn(request_context_middleware))
}
