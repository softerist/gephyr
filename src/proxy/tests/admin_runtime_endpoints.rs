#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
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

    static ADMIN_ENDPOINT_TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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
            thought_signature_map: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
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
            thought_signature_map: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
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
            "/proxy/status",
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
        assert!(metrics_body["monitor"]["enabled"].is_boolean());
        assert!(metrics_body["monitor"]["total_requests"].is_number());
        assert!(metrics_body["sticky"]["persist_session_bindings"].is_boolean());
        assert!(metrics_body["sticky"]["scheduling_mode"].is_string());
        assert!(metrics_body["sticky"]["session_bindings_count"].is_number());
        assert_eq!(metrics_body["compliance"]["enabled"], true);
        assert!(metrics_body["compliance"]["global_requests_in_last_minute"].is_number());
        assert!(metrics_body["compliance"]["total_account_in_flight"].is_number());
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
                    "health_check_interval": 45
                })
                .to_string(),
            ))
            .expect("request");
        let (post_status, post_body) = send(&router, post_request).await;
        assert_eq!(post_status, StatusCode::OK);
        assert_eq!(post_body["ok"], true);
        assert_eq!(post_body["saved"], true);
        assert_eq!(post_body["proxy_pool"]["enabled"], Value::from(true));
        assert_eq!(post_body["proxy_pool"]["auto_failover"], Value::from(false));
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
