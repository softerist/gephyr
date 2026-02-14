#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        extract::{Query, State},
        http::{Request, StatusCode},
        Router,
    };
    use once_cell::sync::Lazy;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::sync::{Arc, Mutex};
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use crate::modules::auth::account_service::AccountService;
    use crate::modules::system::config as system_config;
    use crate::modules::system::integration::SystemManager;
    use crate::proxy::config::{
        DebugLoggingConfig, ExperimentalConfig, ProxyAuthMode, ProxyPoolConfig,
        UpstreamProxyConfig, ZaiConfig,
    };
    use crate::proxy::monitor::ProxyMonitor;
    use crate::proxy::proxy_pool::ProxyPoolManager;
    use crate::proxy::routes::build_admin_routes;
    use crate::proxy::state::{AppState, ConfigState, CoreServices, RuntimeState};
    use crate::proxy::{ProxySecurityConfig, TokenManager};
    use crate::test_utils::ScopedEnvVar;

    static ADMIN_ENDPOINT_TEST_LOCK: Lazy<&'static Mutex<()>> =
        Lazy::new(|| &crate::proxy::tests::SECURITY_TEST_LOCK);

    fn seed_runtime_config_api_key(api_key: &str) {
        let mut cfg = system_config::load_app_config().unwrap_or_default();
        cfg.proxy.api_key = api_key.to_string();
        system_config::save_app_config(&cfg).expect("save app config for test");
    }

    fn build_test_state(api_key: &str) -> AppState {
        let data_dir = std::env::temp_dir().join(format!(
            ".gephyr-admin-endpoint-test-{}",
            uuid::Uuid::new_v4()
        ));
        let token_manager = Arc::new(TokenManager::new(data_dir));
        let monitor = Arc::new(ProxyMonitor::new(64));
        let integration = SystemManager::Headless;
        let account_service = Arc::new(AccountService::new(integration.clone()));
        let proxy_pool_state = Arc::new(RwLock::new(ProxyPoolConfig::default()));
        let proxy_pool_manager = Arc::new(ProxyPoolManager::new(proxy_pool_state.clone()));
        let core = Arc::new(CoreServices {
            token_manager,
            upstream: Arc::new(crate::proxy::upstream::client::UpstreamClient::new(
                None, None,
            )),
            monitor,
            integration: integration.clone(),
            account_service,
        });
        let config = Arc::new(ConfigState {
            custom_mapping: Arc::new(RwLock::new(HashMap::new())),
            upstream_proxy: Arc::new(RwLock::new(UpstreamProxyConfig::default())),
            zai: Arc::new(RwLock::new(ZaiConfig::default())),
            experimental: Arc::new(RwLock::new(ExperimentalConfig::default())),
            debug_logging: Arc::new(RwLock::new(DebugLoggingConfig::default())),
            security: Arc::new(RwLock::new(ProxySecurityConfig {
                auth_mode: ProxyAuthMode::Strict,
                api_key: api_key.to_string(),
                admin_password: None,
                allow_lan_access: false,
                port: 8045,
                security_monitor: crate::proxy::config::SecurityMonitorConfig::default(),
            })),
            request_timeout: Arc::new(AtomicU64::new(120)),
            update_lock: Arc::new(tokio::sync::Mutex::new(())),
        });
        let runtime = Arc::new(RuntimeState {
            provider_rr: Arc::new(AtomicUsize::new(0)),
            switching: Arc::new(RwLock::new(false)),
            is_running: Arc::new(RwLock::new(true)),
            port: 8045,
            proxy_pool_state,
            proxy_pool_manager,
        });

        AppState {
            core,
            config,
            runtime,
        }
    }

    fn build_test_state_from_persisted_config() -> AppState {
        let persisted = system_config::load_app_config().unwrap_or_default();
        let proxy_cfg = persisted.proxy;

        let data_dir = std::env::temp_dir().join(format!(
            ".gephyr-admin-endpoint-test-reinit-{}",
            uuid::Uuid::new_v4()
        ));
        let token_manager = Arc::new(TokenManager::new(data_dir));
        let monitor = Arc::new(ProxyMonitor::new(64));
        let integration = SystemManager::Headless;
        let account_service = Arc::new(AccountService::new(integration.clone()));
        let proxy_pool_state = Arc::new(RwLock::new(proxy_cfg.proxy_pool.clone()));
        let proxy_pool_manager = Arc::new(ProxyPoolManager::new(proxy_pool_state.clone()));
        let core = Arc::new(CoreServices {
            token_manager,
            upstream: Arc::new(crate::proxy::upstream::client::UpstreamClient::new(
                Some(proxy_cfg.upstream_proxy.clone()),
                None,
            )),
            monitor,
            integration: integration.clone(),
            account_service,
        });
        let config = Arc::new(ConfigState {
            custom_mapping: Arc::new(RwLock::new(proxy_cfg.custom_mapping.clone())),
            upstream_proxy: Arc::new(RwLock::new(proxy_cfg.upstream_proxy.clone())),
            zai: Arc::new(RwLock::new(proxy_cfg.zai.clone())),
            experimental: Arc::new(RwLock::new(proxy_cfg.experimental.clone())),
            debug_logging: Arc::new(RwLock::new(proxy_cfg.debug_logging.clone())),
            security: Arc::new(RwLock::new(ProxySecurityConfig::from_proxy_config(
                &proxy_cfg,
            ))),
            request_timeout: Arc::new(AtomicU64::new(proxy_cfg.request_timeout.max(5))),
            update_lock: Arc::new(tokio::sync::Mutex::new(())),
        });
        let runtime = Arc::new(RuntimeState {
            provider_rr: Arc::new(AtomicUsize::new(0)),
            switching: Arc::new(RwLock::new(false)),
            is_running: Arc::new(RwLock::new(true)),
            port: 8045,
            proxy_pool_state,
            proxy_pool_manager,
        });

        AppState {
            core,
            config,
            runtime,
        }
    }

    fn build_test_router(api_key: &str) -> Router {
        seed_runtime_config_api_key(api_key);
        let state = build_test_state(api_key);
        build_admin_routes(state.clone()).with_state(state)
    }

    fn build_test_router_from_persisted_config(api_key: &str) -> Router {
        seed_runtime_config_api_key(api_key);
        let state = build_test_state_from_persisted_config();
        build_admin_routes(state.clone()).with_state(state)
    }

    async fn send(router: &Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("route should handle request");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        let body = if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_| json!({}))
        };
        (status, body)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_health_echoes_request_id_headers_even_when_missing() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let request = Request::builder()
            .uri("/health")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");

        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("route should handle request");

        assert_eq!(response.status(), StatusCode::OK);

        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let correlation_id = response
            .headers()
            .get("x-correlation-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        assert!(
            !request_id.trim().is_empty(),
            "expected x-request-id to be present"
        );
        assert!(
            !correlation_id.trim().is_empty(),
            "expected x-correlation-id to be present"
        );
        assert_eq!(
            request_id, correlation_id,
            "when the client provides no correlation id, we mirror request id"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_version_routes_advertise_compliance_endpoints() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let request = Request::builder()
            .uri("/version/routes")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");

        let (status, body) = send(&router, request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["routes"]["GET /api/auth/status"], true);
        assert_eq!(body["routes"]["GET /api/proxy/request-timeout"], true);
        assert_eq!(body["routes"]["POST /api/proxy/request-timeout"], true);
        assert_eq!(body["routes"]["GET /api/proxy/pool/runtime"], true);
        assert_eq!(body["routes"]["POST /api/proxy/pool/runtime"], true);
        assert_eq!(body["routes"]["GET /api/proxy/pool/strategy"], true);
        assert_eq!(body["routes"]["POST /api/proxy/pool/strategy"], true);
        assert_eq!(body["routes"]["GET /api/proxy/sticky"], true);
        assert_eq!(body["routes"]["POST /api/proxy/sticky"], true);
        assert_eq!(body["routes"]["GET /api/proxy/compliance"], true);
        assert_eq!(body["routes"]["POST /api/proxy/compliance"], true);
        assert_eq!(body["routes"]["GET /api/proxy/google/outbound-policy"], true);
        assert_eq!(body["routes"]["GET /api/proxy/tls-canary"], true);
        assert_eq!(body["routes"]["POST /api/proxy/tls-canary/run"], true);
        assert_eq!(body["routes"]["GET /api/proxy/operator-status"], true);
        assert_eq!(body["routes"]["GET /api/proxy/metrics"], true);
        assert_eq!(body["routes"]["GET /api/version/routes"], true);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_routes_from_each_group_are_registered() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let probes = [
            "/accounts",
            "/auth/status",
            "/proxy/status",
            "/proxy/google/outbound-policy",
            "/proxy/operator-status",
            "/logs",
            "/system/data-dir",
            "/security/stats",
            "/user-tokens/summary",
            "/stats/token/summary",
        ];

        for path in probes {
            let request = Request::builder()
                .uri(path)
                .header("Authorization", format!("Bearer {}", api_key))
                .body(Body::empty())
                .expect("request");
            let (status, _) = send(&router, request).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "route {path} is unexpectedly missing"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_routes_require_auth_even_when_auth_mode_off() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";

        seed_runtime_config_api_key(api_key);
        let state = build_test_state(api_key);
        // Simulate proxy auth mode off. Admin routes should still require auth.
        {
            let mut security = state.config.security.write().await;
            security.auth_mode = ProxyAuthMode::Off;
        }
        let router = build_admin_routes(state.clone()).with_state(state);

        let request = Request::builder()
            .uri("/version/routes")
            .body(Body::empty())
            .expect("request");

        let (status, _) = send(&router, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn logout_all_route_exists_and_requires_auth() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";

        seed_runtime_config_api_key(api_key);
        let state = build_test_state(api_key);
        let router = build_admin_routes(state.clone()).with_state(state);

        let request = Request::builder()
            .method("POST")
            .uri("/accounts/logout-all")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"revokeRemote":true,"deleteLocal":false}"#))
            .expect("request");

        let (status, _body) = send(&router, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_oauth_status_returns_shape() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        crate::modules::auth::oauth_server::reset_oauth_observability_for_tests();
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let request = Request::builder()
            .uri("/auth/status")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");

        let (status, body) = send(&router, request).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["phase"].is_string());
        assert!(body["updated_at_unix"].is_number());
        assert!(body["detail"].is_null() || body["detail"].is_string());
        assert!(body["account_email"].is_null() || body["account_email"].is_string());
        assert!(body["recent_events"].is_array());
        assert!(body["counters"].is_object());
        assert!(body["counters"]["prepared_total"].is_number());
        assert!(body["counters"]["callback_received_total"].is_number());
        assert!(body["counters"]["exchanging_token_total"].is_number());
        assert!(body["counters"]["linked_total"].is_number());
        assert!(body["counters"]["rejected_total"].is_number());
        assert!(body["counters"]["cancelled_total"].is_number());
        assert!(body["counters"]["failed_total"].is_number());
        assert!(body["counters"]["failed_by_code"].is_object());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_oauth_status_recent_events_include_callback_marker() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        crate::modules::auth::oauth_server::reset_oauth_observability_for_tests();
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let marker = format!("test_callback_marker_{}", uuid::Uuid::new_v4());
        crate::modules::auth::oauth_server::mark_oauth_flow_status(
            crate::modules::auth::oauth_server::OAuthFlowPhase::Prepared,
            Some("test_prepared".to_string()),
            None,
        );
        crate::modules::auth::oauth_server::mark_oauth_flow_status(
            crate::modules::auth::oauth_server::OAuthFlowPhase::CallbackReceived,
            Some(marker.clone()),
            None,
        );
        crate::modules::auth::oauth_server::mark_oauth_flow_status(
            crate::modules::auth::oauth_server::OAuthFlowPhase::ExchangingToken,
            Some("test_exchange".to_string()),
            None,
        );

        let request = Request::builder()
            .uri("/auth/status")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");

        let (status, body) = send(&router, request).await;
        assert_eq!(status, StatusCode::OK);
        let recent_events = body["recent_events"]
            .as_array()
            .expect("recent_events should be an array");

        let marker_present = recent_events.iter().any(|event| {
            event["phase"] == Value::from("callback_received")
                && event["detail"] == Value::from(marker.clone())
        });
        assert!(
            marker_present,
            "recent_events should retain callback_received marker"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oauth_callback_access_denied_sets_rejected_phase() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        crate::modules::auth::oauth_server::reset_oauth_observability_for_tests();
        let api_key = "admin-test-key";
        seed_runtime_config_api_key(api_key);
        let state = build_test_state(api_key);
        let admin_router = build_admin_routes(state.clone()).with_state(state.clone());
        let oauth_state = "test-deny-state".to_string();

        let callback_result = crate::proxy::admin::handle_oauth_callback(
            Query(crate::proxy::admin::OAuthParams {
                code: None,
                _scope: None,
                state: Some(oauth_state),
                error: Some("access_denied".to_string()),
                error_description: Some("user denied".to_string()),
            }),
            axum::http::HeaderMap::new(),
            State(crate::proxy::state::AdminState {
                core: state.core.clone(),
                config: state.config.clone(),
                runtime: state.runtime.clone(),
            }),
        )
        .await;
        assert!(callback_result.is_ok(), "callback handler should succeed");

        let status_request = Request::builder()
            .uri("/auth/status")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (status, body) = send(&admin_router, status_request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["phase"], Value::from("rejected"));
        assert_eq!(body["detail"], Value::from("oauth_access_denied"));
        assert_eq!(body["counters"]["rejected_total"], Value::from(1));
        assert_eq!(body["counters"]["failed_total"], Value::from(0));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_oauth_status_failure_counters_track_by_code() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        crate::modules::auth::oauth_server::reset_oauth_observability_for_tests();
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        crate::modules::auth::oauth_server::mark_oauth_flow_status(
            crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
            Some("oauth_exchange_failed: mocked".to_string()),
            None,
        );
        crate::modules::auth::oauth_server::mark_oauth_flow_status(
            crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
            Some("oauth_refresh_token_missing".to_string()),
            None,
        );
        crate::modules::auth::oauth_server::mark_oauth_flow_status(
            crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
            Some("oauth_save_account_failed: E-CRYPTO-KEY-UNAVAILABLE".to_string()),
            None,
        );

        let request = Request::builder()
            .uri("/auth/status")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (status, body) = send(&router, request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["counters"]["failed_total"], Value::from(3));
        assert_eq!(
            body["counters"]["failed_by_code"]["oauth.exchange_failed"],
            Value::from(1)
        );
        assert_eq!(
            body["counters"]["failed_by_code"]["oauth.refresh_token_missing"],
            Value::from(1)
        );
        assert_eq!(
            body["counters"]["failed_by_code"]["oauth.account_save_failed"],
            Value::from(1)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_proxy_metrics_returns_stable_shape() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let compliance_update = Request::builder()
            .method("POST")
            .uri("/proxy/compliance")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "enabled": true,
                    "max_global_requests_per_minute": 120,
                    "max_account_requests_per_minute": 20,
                    "max_account_concurrency": 2,
                    "risk_cooldown_seconds": 300,
                    "max_retry_attempts": 2
                })
                .to_string(),
            ))
            .expect("request");
        let (update_status, _) = send(&router, compliance_update).await;
        assert_eq!(update_status, StatusCode::OK);

        let metrics_request = Request::builder()
            .uri("/proxy/metrics")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (metrics_status, metrics_body) = send(&router, metrics_request).await;
        assert_eq!(metrics_status, StatusCode::OK);

        assert!(metrics_body["timestamp_unix"].is_number());
        assert!(metrics_body["runtime"]["running"].is_boolean());
        assert!(metrics_body["runtime"]["port"].is_number());
        assert!(metrics_body["runtime"]["active_accounts"].is_number());
        assert!(metrics_body["runtime"]["tls_backend"].is_string());
        assert!(
            metrics_body["runtime"]["tls_requested_backend"].is_string()
                || metrics_body["runtime"]["tls_requested_backend"].is_null()
        );
        assert!(metrics_body["runtime"]["tls_compiled_backends"].is_array());
        assert!(metrics_body["runtime"]["tls_canary"].is_object());
        assert!(metrics_body["monitor"]["enabled"].is_boolean());
        assert!(metrics_body["monitor"]["total_requests"].is_number());
        assert!(metrics_body["sticky"]["persist_session_bindings"].is_boolean());
        assert!(metrics_body["sticky"]["scheduling_mode"].is_string());
        assert!(metrics_body["sticky"]["session_bindings_count"].is_number());
        assert!(metrics_body["proxy_pool"]["enabled"].is_boolean());
        assert!(metrics_body["proxy_pool"]["auto_failover"].is_boolean());
        assert!(metrics_body["proxy_pool"]["allow_shared_proxy_fallback"].is_boolean());
        assert!(metrics_body["proxy_pool"]["require_proxy_for_account_requests"].is_boolean());
        assert!(metrics_body["proxy_pool"]["strategy"].is_string());
        assert!(metrics_body["proxy_pool"]["configured_proxies"].is_number());
        assert!(metrics_body["proxy_pool"]["account_bindings_count"].is_number());
        assert!(metrics_body["proxy_pool"]["shared_fallback_selections_total"].is_number());
        assert!(metrics_body["proxy_pool"]["strict_rejections_total"].is_number());
        assert_eq!(metrics_body["compliance"]["enabled"], true);
        assert!(metrics_body["compliance"]["global_requests_in_last_minute"].is_number());
        assert!(metrics_body["compliance"]["total_account_in_flight"].is_number());
        assert!(metrics_body["compliance"]["risk_signals_last_minute"].is_number());
        assert!(metrics_body["compliance"]["account_switches_last_minute"].is_number());
        assert!(metrics_body["compliance"]["accounts_with_403_in_last_minute"].is_number());
        assert!(metrics_body["compliance"]["accounts_with_429_in_last_minute"].is_number());
        assert!(metrics_body["compliance"]["account_403_in_last_minute"].is_object());
        assert!(metrics_body["compliance"]["account_429_in_last_minute"].is_object());
        assert!(metrics_body["compliance"]["refresh_attempts_last_minute"].is_number());
        assert!(metrics_body["compliance"]["refresh_attempts_by_account_last_minute"].is_object());
        assert!(metrics_body["compliance"]["scheduler_refresh_runs_last_minute"].is_number());
        assert!(metrics_body["compliance"]["scheduler_refresh_failures_last_minute"].is_number());
        assert!(
            metrics_body["compliance"]["scheduler_refresh_accounts_attempted_last_minute"]
                .is_number()
        );
        let policies = metrics_body["runtime_apply_policies_supported"]
            .as_array()
            .expect("runtime_apply_policies_supported should be an array");
        assert!(policies.iter().any(|v| v == "always_hot_applied"));
        assert!(policies.iter().any(|v| v == "hot_applied_when_safe"));
        assert!(policies.iter().any(|v| v == "requires_restart"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_google_outbound_policy_returns_stable_shape() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let request = Request::builder()
            .uri("/proxy/google/outbound-policy")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (status, body) = send(&router, request).await;

        assert_eq!(status, StatusCode::OK);
        assert!(body["mode"].is_string());
        assert!(body["inputs"]["google_source"].is_string());
        assert!(body["inputs"]["debug_logging_source"].is_string());
        assert!(body["headers"]["send_host_header_configured"].is_boolean());
        assert!(body["headers"]["send_host_header_effective"].is_boolean());
        assert!(body["headers"]["always_set"].is_array());
        assert!(body["headers"]["json_request_header"].is_object());
        assert!(body["headers"]["passthrough_policy"].is_string());
        assert!(body["headers"]["allowed_passthrough_headers"].is_array());
        assert!(body["headers"]["blocked_categories"].is_array());
        assert!(body["identity_metadata"]["ide_type"].is_string());
        assert!(body["identity_metadata"]["platform"].is_string());
        assert!(body["identity_metadata"]["plugin_type"].is_string());
        assert!(body["debug"]["log_google_outbound_headers"].is_boolean());
        assert!(body["debug"]["redaction_applies_to"].is_array());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_stop_disables_runtime_running_flag() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let stop_request = Request::builder()
            .method("POST")
            .uri("/proxy/stop")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (stop_status, _) = send(&router, stop_request).await;
        assert_eq!(stop_status, StatusCode::OK);

        let status_request = Request::builder()
            .uri("/proxy/status")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (status_code, status_body) = send(&router, status_request).await;
        assert_eq!(status_code, StatusCode::OK);
        assert_eq!(status_body["running"], Value::from(false));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_stop_hook_env_keeps_stop_endpoint_functional() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let _shutdown_hook = ScopedEnvVar::set("ADMIN_STOP_SHUTDOWN", "true");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let stop_request = Request::builder()
            .method("POST")
            .uri("/proxy/stop")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (stop_status, _) = send(&router, stop_request).await;
        assert_eq!(stop_status, StatusCode::OK);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_compliance_post_requires_auth() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let router = build_test_router("admin-test-key");

        let payload = json!({
            "enabled": true,
            "max_global_requests_per_minute": 120,
            "max_account_requests_per_minute": 20,
            "max_account_concurrency": 2,
            "risk_cooldown_seconds": 300,
            "max_retry_attempts": 2
        });
        let request = Request::builder()
            .method("POST")
            .uri("/proxy/compliance")
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("request");

        let (status, _) = send(&router, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_tls_canary_run_requires_auth() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let router = build_test_router("admin-test-key");

        let request = Request::builder()
            .method("POST")
            .uri("/proxy/tls-canary/run")
            .body(Body::empty())
            .expect("request");

        let (status, _) = send(&router, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_tls_canary_run_returns_stable_shape() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let _canary_url = ScopedEnvVar::unset("TLS_CANARY_URL");
        let _canary_timeout = ScopedEnvVar::unset("TLS_CANARY_TIMEOUT_SECS");
        let _canary_required = ScopedEnvVar::unset("TLS_CANARY_REQUIRED");

        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let request = Request::builder()
            .method("POST")
            .uri("/proxy/tls-canary/run")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");

        let (status, body) = send(&router, request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], Value::from(true));
        assert!(body["tls_canary"].is_object());
        assert!(body["tls_canary"]["configured"].is_boolean());
        assert!(body["tls_canary"]["required"].is_boolean());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_compliance_post_updates_runtime_snapshot() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let payload = json!({
            "enabled": true,
            "max_global_requests_per_minute": 150,
            "max_account_requests_per_minute": 25,
            "max_account_concurrency": 3,
            "risk_cooldown_seconds": 301,
            "max_retry_attempts": 4
        });
        let post_request = Request::builder()
            .method("POST")
            .uri("/proxy/compliance")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("request");

        let (post_status, post_body) = send(&router, post_request).await;
        assert_eq!(post_status, StatusCode::OK);
        assert_eq!(post_body["ok"], true);
        assert_eq!(post_body["saved"], true);
        assert_eq!(
            post_body["runtime_apply"]["policy"],
            Value::from("always_hot_applied")
        );
        assert_eq!(post_body["runtime_apply"]["applied"], true);
        assert_eq!(post_body["runtime_apply"]["requires_restart"], false);

        let get_request = Request::builder()
            .uri("/proxy/compliance")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (get_status, get_body) = send(&router, get_request).await;
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(get_body["config"]["enabled"], true);
        assert_eq!(
            get_body["config"]["max_global_requests_per_minute"],
            Value::from(150)
        );
        assert_eq!(
            get_body["config"]["max_account_requests_per_minute"],
            Value::from(25)
        );
        assert_eq!(
            get_body["config"]["max_account_concurrency"],
            Value::from(3)
        );
        assert_eq!(
            get_body["config"]["risk_cooldown_seconds"],
            Value::from(301)
        );
        assert_eq!(get_body["config"]["max_retry_attempts"], Value::from(4));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_sticky_post_updates_runtime_snapshot() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let initial_get = Request::builder()
            .uri("/proxy/sticky")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (initial_status, initial_body) = send(&router, initial_get).await;
        assert_eq!(initial_status, StatusCode::OK);
        assert!(initial_body["persist_session_bindings"].is_boolean());

        let payload = json!({
            "persist_session_bindings": true,
            "scheduling": {
                "mode": "Balance",
                "max_wait_seconds": 33
            }
        });
        let post_request = Request::builder()
            .method("POST")
            .uri("/proxy/sticky")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("request");
        let (post_status, post_body) = send(&router, post_request).await;
        assert_eq!(post_status, StatusCode::OK);
        assert_eq!(post_body["ok"], true);
        assert_eq!(post_body["saved"], true);
        assert_eq!(
            post_body["runtime_apply"]["policy"],
            Value::from("always_hot_applied")
        );
        assert_eq!(post_body["runtime_apply"]["applied"], true);
        assert_eq!(post_body["runtime_apply"]["requires_restart"], false);
        assert_eq!(
            post_body["sticky"]["persist_session_bindings"],
            Value::from(true)
        );
        assert_eq!(
            post_body["sticky"]["scheduling"]["max_wait_seconds"],
            Value::from(33)
        );

        let get_request = Request::builder()
            .uri("/proxy/sticky")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (get_status, get_body) = send(&router, get_request).await;
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(get_body["persist_session_bindings"], Value::from(true));
        assert_eq!(get_body["scheduling"]["max_wait_seconds"], Value::from(33));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_request_timeout_post_updates_runtime_snapshot() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let initial_get = Request::builder()
            .uri("/proxy/request-timeout")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (initial_status, initial_body) = send(&router, initial_get).await;
        assert_eq!(initial_status, StatusCode::OK);
        assert!(initial_body["request_timeout"].is_number());

        let post_request = Request::builder()
            .method("POST")
            .uri("/proxy/request-timeout")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "request_timeout": 45 }).to_string()))
            .expect("request");
        let (post_status, post_body) = send(&router, post_request).await;
        assert_eq!(post_status, StatusCode::OK);
        assert_eq!(post_body["ok"], true);
        assert_eq!(
            post_body["runtime_apply"]["policy"],
            Value::from("always_hot_applied")
        );
        assert_eq!(post_body["runtime_apply"]["applied"], true);
        assert_eq!(post_body["runtime_apply"]["requires_restart"], false);
        assert_eq!(post_body["request_timeout"], Value::from(45));
        assert_eq!(post_body["effective_request_timeout"], Value::from(45));

        let get_request = Request::builder()
            .uri("/proxy/request-timeout")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (get_status, get_body) = send(&router, get_request).await;
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(get_body["request_timeout"], Value::from(45));
        assert_eq!(get_body["effective_request_timeout"], Value::from(45));

        let bad_post = Request::builder()
            .method("POST")
            .uri("/proxy/request-timeout")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "request_timeout": 0 }).to_string()))
            .expect("request");
        let (bad_status, _) = send(&router, bad_post).await;
        assert_eq!(bad_status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_proxy_pool_strategy_post_updates_runtime_snapshot() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let initial_get = Request::builder()
            .uri("/proxy/pool/strategy")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (initial_status, initial_body) = send(&router, initial_get).await;
        assert_eq!(initial_status, StatusCode::OK);
        assert_eq!(initial_body["strategy"], Value::from("priority"));

        let post_request = Request::builder()
            .method("POST")
            .uri("/proxy/pool/strategy")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "strategy": "round_robin" }).to_string()))
            .expect("request");
        let (post_status, post_body) = send(&router, post_request).await;
        assert_eq!(post_status, StatusCode::OK);
        assert_eq!(post_body["ok"], true);
        assert_eq!(post_body["saved"], true);
        assert_eq!(
            post_body["runtime_apply"]["policy"],
            Value::from("hot_applied_when_safe")
        );
        assert_eq!(post_body["runtime_apply"]["applied"], true);
        assert_eq!(post_body["runtime_apply"]["requires_restart"], false);
        assert_eq!(
            post_body["proxy_pool"]["strategy"],
            Value::from("round_robin")
        );

        let get_request = Request::builder()
            .uri("/proxy/pool/strategy")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (get_status, get_body) = send(&router, get_request).await;
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(get_body["strategy"], Value::from("round_robin"));

        let bad_post = Request::builder()
            .method("POST")
            .uri("/proxy/pool/strategy")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({}).to_string()))
            .expect("request");
        let (bad_status, _) = send(&router, bad_post).await;
        assert_eq!(bad_status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_proxy_pool_runtime_post_updates_runtime_snapshot() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let initial_get = Request::builder()
            .uri("/proxy/pool/runtime")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (initial_status, initial_body) = send(&router, initial_get).await;
        assert_eq!(initial_status, StatusCode::OK);
        assert_eq!(initial_body["enabled"], Value::from(false));
        assert_eq!(initial_body["auto_failover"], Value::from(true));
        assert_eq!(
            initial_body["allow_shared_proxy_fallback"],
            Value::from(true)
        );
        assert_eq!(
            initial_body["require_proxy_for_account_requests"],
            Value::from(false)
        );
        assert_eq!(initial_body["health_check_interval"], Value::from(300));

        let post_request = Request::builder()
            .method("POST")
            .uri("/proxy/pool/runtime")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "enabled": true,
                    "auto_failover": false,
                    "allow_shared_proxy_fallback": false,
                    "require_proxy_for_account_requests": true,
                    "health_check_interval": 45
                })
                .to_string(),
            ))
            .expect("request");
        let (post_status, post_body) = send(&router, post_request).await;
        assert_eq!(post_status, StatusCode::OK);
        assert_eq!(post_body["ok"], true);
        assert_eq!(post_body["saved"], true);
        assert_eq!(
            post_body["runtime_apply"]["policy"],
            Value::from("hot_applied_when_safe")
        );
        assert_eq!(post_body["runtime_apply"]["applied"], true);
        assert_eq!(post_body["runtime_apply"]["requires_restart"], false);
        assert_eq!(post_body["proxy_pool"]["enabled"], Value::from(true));
        assert_eq!(post_body["proxy_pool"]["auto_failover"], Value::from(false));
        assert_eq!(
            post_body["proxy_pool"]["allow_shared_proxy_fallback"],
            Value::from(false)
        );
        assert_eq!(
            post_body["proxy_pool"]["require_proxy_for_account_requests"],
            Value::from(true)
        );
        assert_eq!(
            post_body["proxy_pool"]["health_check_interval"],
            Value::from(45)
        );

        let get_request = Request::builder()
            .uri("/proxy/pool/runtime")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (get_status, get_body) = send(&router, get_request).await;
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(get_body["enabled"], Value::from(true));
        assert_eq!(get_body["auto_failover"], Value::from(false));
        assert_eq!(get_body["allow_shared_proxy_fallback"], Value::from(false));
        assert_eq!(
            get_body["require_proxy_for_account_requests"],
            Value::from(true)
        );
        assert_eq!(get_body["health_check_interval"], Value::from(45));

        let bad_post = Request::builder()
            .method("POST")
            .uri("/proxy/pool/runtime")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({}).to_string()))
            .expect("request");
        let (bad_status, _) = send(&router, bad_post).await;
        assert_eq!(bad_status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_save_config_preserves_api_key_when_blank() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let get_config_request = Request::builder()
            .uri("/config")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (config_status, mut config_body) = send(&router, get_config_request).await;
        assert_eq!(config_status, StatusCode::OK);

        config_body["proxy"]["api_key"] = Value::String(api_key.to_string());
        let set_key_request = Request::builder()
            .method("POST")
            .uri("/config")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "config": config_body }).to_string()))
            .expect("request");
        let (set_key_status, _) = send(&router, set_key_request).await;
        assert_eq!(set_key_status, StatusCode::OK);

        let get_config_request_2 = Request::builder()
            .uri("/config")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (_, mut config_body_2) = send(&router, get_config_request_2).await;
        config_body_2["proxy"]["api_key"] = Value::String(String::new());

        let preserve_request = Request::builder()
            .method("POST")
            .uri("/config")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "config": config_body_2 }).to_string()))
            .expect("request");
        let (preserve_status, preserve_body) = send(&router, preserve_request).await;
        assert_eq!(preserve_status, StatusCode::OK);
        assert_eq!(preserve_body["ok"], true);

        let warnings = preserve_body["warnings"]
            .as_array()
            .expect("warnings should be an array");
        assert!(
            warnings
                .iter()
                .any(|v| v == "proxy.api_key_preserved_from_existing"),
            "Expected api key preservation warning"
        );

        let status_request = Request::builder()
            .uri("/proxy/status")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (status_code, _) = send(&router, status_request).await;
        assert_eq!(status_code, StatusCode::OK);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_save_config_hot_applies_google_outbound_policy() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let get_config_request = Request::builder()
            .uri("/config")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (config_status, mut config_body) = send(&router, get_config_request).await;
        assert_eq!(config_status, StatusCode::OK);

        config_body["proxy"]["google"]["mode"] = Value::from("codeassist_compat");
        config_body["proxy"]["google"]["headers"]["send_host_header"] = Value::from(true);
        config_body["proxy"]["google"]["identity_metadata"]["ide_type"] = Value::from("TEST_IDE");
        config_body["proxy"]["google"]["identity_metadata"]["platform"] =
            Value::from("TEST_PLATFORM");
        config_body["proxy"]["google"]["identity_metadata"]["plugin_type"] =
            Value::from("TEST_PLUGIN");
        config_body["proxy"]["debug_logging"]["log_google_outbound_headers"] = Value::from(true);

        let save_request = Request::builder()
            .method("POST")
            .uri("/config")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "config": config_body }).to_string()))
            .expect("request");
        let (save_status, save_body) = send(&router, save_request).await;
        assert_eq!(save_status, StatusCode::OK);
        assert_eq!(save_body["ok"], Value::from(true));

        let policy_request = Request::builder()
            .uri("/proxy/google/outbound-policy")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (policy_status, policy_body) = send(&router, policy_request).await;
        assert_eq!(policy_status, StatusCode::OK);
        assert_eq!(policy_body["mode"], Value::from("codeassist_compat"));
        assert_eq!(
            policy_body["headers"]["send_host_header_configured"],
            Value::from(true)
        );
        assert_eq!(
            policy_body["headers"]["send_host_header_effective"],
            Value::from(true)
        );
        assert_eq!(
            policy_body["identity_metadata"]["ide_type"],
            Value::from("TEST_IDE")
        );
        assert_eq!(
            policy_body["identity_metadata"]["platform"],
            Value::from("TEST_PLATFORM")
        );
        assert_eq!(
            policy_body["identity_metadata"]["plugin_type"],
            Value::from("TEST_PLUGIN")
        );
        assert_eq!(
            policy_body["debug"]["log_google_outbound_headers"],
            Value::from(true)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_scoped_updates_persist_across_restart_like_reinit() {
        let _guard = ADMIN_ENDPOINT_TEST_LOCK
            .lock()
            .expect("admin endpoint test lock");
        let api_key = "admin-test-key";
        let router = build_test_router(api_key);

        let update_timeout = Request::builder()
            .method("POST")
            .uri("/proxy/request-timeout")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "request_timeout": 77 }).to_string()))
            .expect("request");
        let (status_timeout, _) = send(&router, update_timeout).await;
        assert_eq!(status_timeout, StatusCode::OK);

        let update_pool_runtime = Request::builder()
            .method("POST")
            .uri("/proxy/pool/runtime")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "enabled": true,
                    "auto_failover": false,
                    "health_check_interval": 123
                })
                .to_string(),
            ))
            .expect("request");
        let (status_pool_runtime, _) = send(&router, update_pool_runtime).await;
        assert_eq!(status_pool_runtime, StatusCode::OK);

        let update_pool_strategy = Request::builder()
            .method("POST")
            .uri("/proxy/pool/strategy")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({ "strategy": "weighted_round_robin" }).to_string(),
            ))
            .expect("request");
        let (status_pool_strategy, _) = send(&router, update_pool_strategy).await;
        assert_eq!(status_pool_strategy, StatusCode::OK);

        let reinit_router = build_test_router_from_persisted_config(api_key);

        let get_timeout = Request::builder()
            .uri("/proxy/request-timeout")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (timeout_status, timeout_body) = send(&reinit_router, get_timeout).await;
        assert_eq!(timeout_status, StatusCode::OK);
        assert_eq!(timeout_body["request_timeout"], Value::from(77));

        let get_pool_runtime = Request::builder()
            .uri("/proxy/pool/runtime")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (runtime_status, runtime_body) = send(&reinit_router, get_pool_runtime).await;
        assert_eq!(runtime_status, StatusCode::OK);
        assert_eq!(runtime_body["enabled"], Value::from(true));
        assert_eq!(runtime_body["auto_failover"], Value::from(false));
        assert_eq!(runtime_body["health_check_interval"], Value::from(123));
        assert_eq!(
            runtime_body["strategy"],
            Value::from("weighted_round_robin")
        );

        let get_pool_strategy = Request::builder()
            .uri("/proxy/pool/strategy")
            .header("Authorization", format!("Bearer {}", api_key))
            .body(Body::empty())
            .expect("request");
        let (strategy_status, strategy_body) = send(&reinit_router, get_pool_strategy).await;
        assert_eq!(strategy_status, StatusCode::OK);
        assert_eq!(
            strategy_body["strategy"],
            Value::from("weighted_round_robin")
        );
    }
}
