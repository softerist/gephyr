use axum::{routing::get, Router};

use crate::proxy::routes::admin_groups;
use crate::proxy::state::AppState;
use crate::proxy::{admin, health};

const ADMIN_PATH_HEALTH: &str = "/health";
const ADMIN_PATH_VERSION_ROUTES: &str = "/version/routes";
const ADMIN_PATH_AUTH_STATUS: &str = "/auth/status";
const ADMIN_PATH_CONFIG: &str = "/config";
const ADMIN_PATH_PROXY_STATUS: &str = "/proxy/status";
const ADMIN_PATH_PROXY_REQUEST_TIMEOUT: &str = "/proxy/request-timeout";
const ADMIN_PATH_PROXY_POOL_RUNTIME: &str = "/proxy/pool/runtime";
const ADMIN_PATH_PROXY_POOL_STRATEGY: &str = "/proxy/pool/strategy";
const ADMIN_PATH_PROXY_SESSION_BINDINGS_CLEAR: &str = "/proxy/session-bindings/clear";
const ADMIN_PATH_PROXY_SESSION_BINDINGS: &str = "/proxy/session-bindings";
const ADMIN_PATH_PROXY_STICKY: &str = "/proxy/sticky";
const ADMIN_PATH_PROXY_COMPLIANCE: &str = "/proxy/compliance";
const ADMIN_PATH_PROXY_TLS_CANARY: &str = "/proxy/tls-canary";
const ADMIN_PATH_PROXY_TLS_CANARY_RUN: &str = "/proxy/tls-canary/run";
const ADMIN_PATH_PROXY_OPERATOR_STATUS: &str = "/proxy/operator-status";
const ADMIN_PATH_PROXY_METRICS: &str = "/proxy/metrics";

const VERSION_ROUTE_CAPABILITIES: &[(&str, &str)] = &[
    ("GET", ADMIN_PATH_HEALTH),
    ("GET", ADMIN_PATH_AUTH_STATUS),
    ("GET", ADMIN_PATH_CONFIG),
    ("POST", ADMIN_PATH_CONFIG),
    ("GET", ADMIN_PATH_PROXY_REQUEST_TIMEOUT),
    ("POST", ADMIN_PATH_PROXY_REQUEST_TIMEOUT),
    ("GET", ADMIN_PATH_PROXY_POOL_RUNTIME),
    ("POST", ADMIN_PATH_PROXY_POOL_RUNTIME),
    ("GET", ADMIN_PATH_PROXY_POOL_STRATEGY),
    ("POST", ADMIN_PATH_PROXY_POOL_STRATEGY),
    ("GET", ADMIN_PATH_PROXY_STICKY),
    ("POST", ADMIN_PATH_PROXY_STICKY),
    ("GET", ADMIN_PATH_PROXY_SESSION_BINDINGS),
    ("POST", ADMIN_PATH_PROXY_SESSION_BINDINGS_CLEAR),
    ("GET", ADMIN_PATH_PROXY_COMPLIANCE),
    ("POST", ADMIN_PATH_PROXY_COMPLIANCE),
    ("GET", ADMIN_PATH_PROXY_TLS_CANARY),
    ("POST", ADMIN_PATH_PROXY_TLS_CANARY_RUN),
    ("GET", ADMIN_PATH_PROXY_OPERATOR_STATUS),
    ("GET", ADMIN_PATH_PROXY_METRICS),
    ("GET", ADMIN_PATH_PROXY_STATUS),
    ("GET", ADMIN_PATH_VERSION_ROUTES),
];

pub fn admin_version_route_capabilities() -> serde_json::Map<String, serde_json::Value> {
    VERSION_ROUTE_CAPABILITIES
        .iter()
        .map(|(method, path)| {
            (
                format!("{} /api{}", method, path),
                serde_json::Value::Bool(true),
            )
        })
        .collect()
}

pub fn build_admin_routes(state: AppState) -> Router<AppState> {
    let router = Router::new()
        .route(ADMIN_PATH_HEALTH, get(health::health_check_handler))
        .route(
            ADMIN_PATH_VERSION_ROUTES,
            get(admin::admin_get_version_routes),
        );
    let router = admin_groups::add_account_routes(router);
    let router = admin_groups::add_proxy_routes(router);
    let router = admin_groups::add_logs_stats_debug_routes(router);
    let router = admin_groups::add_system_routes(router);
    let router = admin_groups::add_security_routes(router);
    let router = admin_groups::add_user_token_routes(router);
    add_legacy_stats_alias_routes(router)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::proxy::middleware::admin_auth_middleware,
        ))
        .layer(axum::middleware::from_fn(
            crate::proxy::middleware::request_context_middleware,
        ))
}

fn add_legacy_stats_alias_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/stats/summary", get(admin::admin_get_token_stats_summary))
        .route("/stats/hourly", get(admin::admin_get_token_stats_hourly))
        .route("/stats/daily", get(admin::admin_get_token_stats_daily))
        .route("/stats/weekly", get(admin::admin_get_token_stats_weekly))
        .route(
            "/stats/accounts",
            get(admin::admin_get_token_stats_by_account),
        )
        .route("/stats/models", get(admin::admin_get_token_stats_by_model))
}
