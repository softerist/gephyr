use axum::http::{header, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use crate::proxy::config::{CorsConfig, CorsMode};

pub fn cors_layer(config: &CorsConfig) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
            Method::PATCH,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-api-key"),
            header::HeaderName::from_static("x-goog-api-key"),
        ])
        .allow_credentials(false)
        .max_age(std::time::Duration::from_secs(3600));

    if matches!(config.mode, CorsMode::Permissive) {
        return base.allow_origin(Any).allow_headers(Any);
    }

    let allowed_origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .filter_map(|origin| {
            let trimmed = origin.trim();
            match HeaderValue::from_str(trimmed) {
                Ok(value) => Some(value),
                Err(e) => {
                    tracing::warn!("Ignoring invalid CORS origin {:?}: {}", origin, e);
                    None
                }
            }
        })
        .collect();

    if allowed_origins.is_empty() {
        base
    } else {
        base.allow_origin(AllowOrigin::list(allowed_origins))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    fn cors_test_router(config: CorsConfig) -> Router {
        Router::new()
            .route("/ping", get(|| async { "ok" }))
            .layer(cors_layer(&config))
    }

    #[test]
    fn test_cors_layer_creation() {
        let _layer = cors_layer(&CorsConfig::default());
    }

    #[tokio::test]
    async fn strict_mode_allows_configured_origin() {
        let app = cors_test_router(CorsConfig {
            mode: CorsMode::Strict,
            allowed_origins: vec!["http://localhost:3000".to_string()],
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/ping")
                    .header("origin", "http://localhost:3000")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("access-control-allow-origin"),
            Some(&HeaderValue::from_static("http://localhost:3000"))
        );
    }

    #[tokio::test]
    async fn strict_mode_blocks_unlisted_origin() {
        let app = cors_test_router(CorsConfig {
            mode: CorsMode::Strict,
            allowed_origins: vec!["http://localhost:3000".to_string()],
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/ping")
                    .header("origin", "http://evil.example")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    #[tokio::test]
    async fn strict_mode_with_empty_allowlist_blocks_all_cross_origin_requests() {
        let app = cors_test_router(CorsConfig {
            mode: CorsMode::Strict,
            allowed_origins: vec![],
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/ping")
                    .header("origin", "http://any.example")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    #[tokio::test]
    async fn permissive_mode_allows_any_origin() {
        let app = cors_test_router(CorsConfig {
            mode: CorsMode::Permissive,
            allowed_origins: vec![],
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/ping")
                    .header("origin", "http://any.example")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("access-control-allow-origin"),
            Some(&HeaderValue::from_static("*"))
        );
    }
}
