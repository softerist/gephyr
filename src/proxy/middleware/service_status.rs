use crate::proxy::state::RuntimeState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

pub async fn service_status_middleware(
    State(state): State<RuntimeState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path.starts_with("/api/")
        || path == "/auth/callback"
        || path == "/health"
        || path == "/healthz"
    {
        return next.run(request).await;
    }

    let running = {
        let r = state.is_running.read().await;
        *r
    };

    if !running {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Proxy service is currently disabled".to_string(),
        )
            .into_response();
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::service_status_middleware;
    use crate::proxy::config::ProxyPoolConfig;
    use crate::proxy::proxy_pool::ProxyPoolManager;
    use crate::proxy::state::RuntimeState;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use std::sync::{
        atomic::AtomicUsize,
        Arc,
    };
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    fn test_runtime_state(running: bool) -> RuntimeState {
        let proxy_pool_state = Arc::new(RwLock::new(ProxyPoolConfig::default()));
        let proxy_pool_manager = Arc::new(ProxyPoolManager::new(proxy_pool_state.clone()));
        RuntimeState {
            provider_rr: Arc::new(AtomicUsize::new(0)),
            switching: Arc::new(RwLock::new(false)),
            is_running: Arc::new(RwLock::new(running)),
            port: 8045,
            proxy_pool_state,
            proxy_pool_manager,
        }
    }

    #[tokio::test]
    async fn service_status_middleware_allows_health_routes_when_disabled() {
        let state = test_runtime_state(false);
        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .route("/healthz", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                service_status_middleware,
            ))
            .with_state(state);

        let health = app
            .clone()
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .expect("health request should succeed");
        assert_eq!(health.status(), StatusCode::OK);

        let healthz = app
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .expect("healthz request should succeed");
        assert_eq!(healthz.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn service_status_middleware_blocks_non_exempt_routes_when_disabled() {
        let state = test_runtime_state(false);
        let app = Router::new()
            .route("/v1/messages", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                service_status_middleware,
            ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/messages")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request should be handled");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn service_status_middleware_allows_admin_exempt_routes_when_disabled() {
        let state = test_runtime_state(false);
        let app = Router::new()
            .route("/auth/callback", get(|| async { StatusCode::OK }))
            .route("/api/test", get(|| async { StatusCode::OK }))
            .route("/v1/messages", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                service_status_middleware,
            ));

        let auth_callback = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/callback")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("auth callback request should be handled");
        assert_eq!(auth_callback.status(), StatusCode::OK);

        let api = app
            .oneshot(Request::builder().uri("/api/test").body(Body::empty()).unwrap())
            .await
            .expect("api request should be handled");
        assert_eq!(api.status(), StatusCode::OK);
    }
}
