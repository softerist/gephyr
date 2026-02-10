use crate::proxy::TokenManager;
use axum::{extract::DefaultBodyLimit, routing::get, Router};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, warn};
static PENDING_RELOAD_ACCOUNTS: OnceLock<std::sync::RwLock<HashSet<String>>> = OnceLock::new();
static PENDING_DELETE_ACCOUNTS: OnceLock<std::sync::RwLock<HashSet<String>>> = OnceLock::new();
static GLOBAL_SHUTDOWN_TX: OnceLock<std::sync::RwLock<Option<tokio::sync::watch::Sender<bool>>>> =
    OnceLock::new();
const SHUTDOWN_DRAIN_TIMEOUT_ENV: &str = "ABV_SHUTDOWN_DRAIN_TIMEOUT_SECS";
const DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_SECS: u64 = 10;
const MIN_SHUTDOWN_DRAIN_TIMEOUT_SECS: u64 = 1;
const MAX_SHUTDOWN_DRAIN_TIMEOUT_SECS: u64 = 600;

fn get_pending_reload_accounts() -> &'static std::sync::RwLock<HashSet<String>> {
    PENDING_RELOAD_ACCOUNTS.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

fn get_pending_delete_accounts() -> &'static std::sync::RwLock<HashSet<String>> {
    PENDING_DELETE_ACCOUNTS.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

fn global_shutdown_slot() -> &'static std::sync::RwLock<Option<tokio::sync::watch::Sender<bool>>> {
    GLOBAL_SHUTDOWN_TX.get_or_init(|| std::sync::RwLock::new(None))
}

fn register_global_shutdown_sender(sender: tokio::sync::watch::Sender<bool>) {
    if let Ok(mut slot) = global_shutdown_slot().write() {
        *slot = Some(sender);
    }
}

fn clear_global_shutdown_sender() {
    if let Ok(mut slot) = global_shutdown_slot().write() {
        *slot = None;
    }
}

pub fn request_global_shutdown() -> bool {
    let sender = global_shutdown_slot()
        .read()
        .ok()
        .and_then(|slot| slot.clone());
    if let Some(tx) = sender {
        tx.send(true).is_ok()
    } else {
        false
    }
}

fn normalize_shutdown_drain_timeout_secs(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    trimmed.parse::<u64>().ok().map(|secs| {
        secs.clamp(
            MIN_SHUTDOWN_DRAIN_TIMEOUT_SECS,
            MAX_SHUTDOWN_DRAIN_TIMEOUT_SECS,
        )
    })
}

fn resolve_shutdown_drain_timeout() -> Duration {
    let raw = std::env::var(SHUTDOWN_DRAIN_TIMEOUT_ENV).ok();
    let secs = raw
        .as_deref()
        .and_then(normalize_shutdown_drain_timeout_secs)
        .unwrap_or(DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_SECS);

    if let Some(raw_value) = raw.as_deref() {
        let trimmed = raw_value.trim();
        if !trimmed.is_empty() {
            match trimmed.parse::<u64>() {
                Ok(parsed) if parsed != secs => warn!(
                    "{}={} is out of supported range ({}-{}); using {} seconds",
                    SHUTDOWN_DRAIN_TIMEOUT_ENV,
                    parsed,
                    MIN_SHUTDOWN_DRAIN_TIMEOUT_SECS,
                    MAX_SHUTDOWN_DRAIN_TIMEOUT_SECS,
                    secs
                ),
                Ok(_) => {}
                Err(_) => warn!(
                    "Invalid {} value '{}'; using default {} seconds",
                    SHUTDOWN_DRAIN_TIMEOUT_ENV, trimmed, DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_SECS
                ),
            }
        }
    }

    Duration::from_secs(secs)
}

pub fn trigger_account_reload(account_id: &str) {
    if let Ok(mut pending) = get_pending_reload_accounts().write() {
        pending.insert(account_id.to_string());
        tracing::debug!(
            "[Quota] Queued account {} for TokenManager reload",
            account_id
        );
    }
}
pub fn trigger_account_delete(account_id: &str) {
    if let Ok(mut pending) = get_pending_delete_accounts().write() {
        pending.insert(account_id.to_string());
        tracing::debug!("[Proxy] Queued account {} for cache removal", account_id);
    }
}
pub fn take_pending_reload_accounts() -> Vec<String> {
    if let Ok(mut pending) = get_pending_reload_accounts().write() {
        let accounts: Vec<String> = pending.drain().collect();
        if !accounts.is_empty() {
            tracing::debug!(
                "[Quota] Taking {} pending accounts for reload",
                accounts.len()
            );
        }
        accounts
    } else {
        Vec::new()
    }
}
pub fn take_pending_delete_accounts() -> Vec<String> {
    if let Ok(mut pending) = get_pending_delete_accounts().write() {
        let accounts: Vec<String> = pending.drain().collect();
        if !accounts.is_empty() {
            tracing::debug!(
                "[Proxy] Taking {} pending accounts for cache removal",
                accounts.len()
            );
        }
        accounts
    } else {
        Vec::new()
    }
}

use crate::proxy::state::{AppState, ConfigState, CoreServices, RuntimeState};
pub struct AxumStartConfig {
    pub host: String,
    pub port: u16,
    pub token_manager: Arc<TokenManager>,
    pub custom_mapping: std::collections::HashMap<String, String>,
    pub request_timeout: u64,
    pub upstream_proxy: crate::proxy::config::UpstreamProxyConfig,
    pub user_agent_override: Option<String>,
    pub cors_config: crate::proxy::config::CorsConfig,
    pub security_config: crate::proxy::ProxySecurityConfig,
    pub zai_config: crate::proxy::ZaiConfig,
    pub monitor: Arc<crate::proxy::monitor::ProxyMonitor>,
    pub experimental_config: crate::proxy::config::ExperimentalConfig,
    pub debug_logging: crate::proxy::config::DebugLoggingConfig,
    pub integration: crate::modules::system::integration::SystemManager,
    pub proxy_pool_config: crate::proxy::config::ProxyPoolConfig,
}

#[derive(Clone)]
pub struct AxumServer {
    pub is_running: Arc<RwLock<bool>>,
    pub token_manager: Arc<TokenManager>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl AxumServer {
    pub async fn set_running(&self, running: bool) {
        let mut r = self.is_running.write().await;
        *r = running;
        tracing::info!("Proxy service running status updated to: {}", running);
    }

    pub fn request_shutdown(&self) {
        if self.shutdown_tx.send(true).is_err() {
            tracing::debug!("Shutdown signal receiver is not active");
        }
    }
    pub async fn start(
        config: AxumStartConfig,
    ) -> Result<(Self, tokio::task::JoinHandle<()>), String> {
        let AxumStartConfig {
            host,
            port,
            token_manager,
            custom_mapping,
            request_timeout,
            upstream_proxy,
            user_agent_override,
            cors_config,
            security_config,
            zai_config,
            monitor,
            experimental_config,
            debug_logging,
            integration,
            proxy_pool_config,
        } = config;

        let custom_mapping_state = Arc::new(tokio::sync::RwLock::new(custom_mapping));
        let proxy_state = Arc::new(tokio::sync::RwLock::new(upstream_proxy.clone()));
        let proxy_pool_state = Arc::new(tokio::sync::RwLock::new(proxy_pool_config));
        let proxy_pool_manager =
            crate::proxy::proxy_pool::init_global_proxy_pool(proxy_pool_state.clone());
        proxy_pool_manager.clone().start_health_check_loop();
        let security_state = Arc::new(RwLock::new(security_config));
        let zai_state = Arc::new(RwLock::new(zai_config));
        let provider_rr = Arc::new(AtomicUsize::new(0));
        let experimental_state = Arc::new(RwLock::new(experimental_config));
        let debug_logging_state = Arc::new(RwLock::new(debug_logging));
        let is_running_state = Arc::new(RwLock::new(true));
        let switching_state = Arc::new(RwLock::new(false));
        let account_service = Arc::new(crate::modules::auth::account_service::AccountService::new(
            integration.clone(),
        ));
        let request_timeout_secs = request_timeout.max(5);
        let upstream = {
            let u = Arc::new(crate::proxy::upstream::client::UpstreamClient::new(
                Some(upstream_proxy.clone()),
                Some(proxy_pool_manager.clone()),
            ));
            if user_agent_override.is_some() {
                u.set_user_agent_override(user_agent_override).await;
            }
            u
        };

        let core = Arc::new(CoreServices {
            token_manager: token_manager.clone(),
            upstream: upstream.clone(),
            monitor: monitor.clone(),
            integration: integration.clone(),
            account_service: account_service.clone(),
        });
        let config_state = Arc::new(ConfigState {
            custom_mapping: custom_mapping_state.clone(),
            upstream_proxy: proxy_state.clone(),
            zai: zai_state.clone(),
            experimental: experimental_state.clone(),
            debug_logging: debug_logging_state.clone(),
            security: security_state.clone(),
            request_timeout: Arc::new(AtomicU64::new(request_timeout_secs)),
            update_lock: Arc::new(tokio::sync::Mutex::new(())),
        });
        let runtime_state = Arc::new(RuntimeState {
            provider_rr: provider_rr.clone(),
            switching: switching_state.clone(),
            is_running: is_running_state.clone(),
            port,
            proxy_pool_state: proxy_pool_state.clone(),
            proxy_pool_manager: proxy_pool_manager.clone(),
        });

        let state = AppState {
            core: core.clone(),
            config: config_state.clone(),
            runtime: runtime_state.clone(),
        };
        use crate::proxy::middleware::{cors_layer, service_status_middleware};
        let proxy_routes = crate::proxy::routes::build_proxy_routes(state.clone());
        let admin_routes = crate::proxy::routes::build_admin_routes(state.clone());
        let max_body_size: usize = std::env::var("ABV_MAX_BODY_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100 * 1024 * 1024);
        tracing::info!(
            "Request body size limit: {} MB",
            max_body_size / 1024 / 1024
        );

        let enable_admin_api = std::env::var("ABV_ENABLE_ADMIN_API")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);

        let app = {
            let base = Router::new().merge(proxy_routes);
            let base = if enable_admin_api {
                tracing::warn!("Admin API enabled at /api");
                base.nest("/api", admin_routes).route(
                    "/auth/callback",
                    get(crate::proxy::admin::handle_oauth_callback),
                )
            } else {
                tracing::info!(
                    "Admin API disabled (set ABV_ENABLE_ADMIN_API=true to expose /api routes)"
                );
                base
            };

            base.layer(axum::middleware::from_fn_with_state(
                state.clone(),
                service_status_middleware,
            ))
            .layer(cors_layer(&cors_config))
            .layer(DefaultBodyLimit::max(max_body_size))
            .with_state(state.clone())
        };
        let addr = format!("{}:{}", host, port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Address {} binding failed: {}", addr, e))?;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        register_global_shutdown_sender(shutdown_tx.clone());
        let drain_timeout = resolve_shutdown_drain_timeout();

        tracing::info!("Proxy server started at http://{}", addr);
        tracing::info!(
            "Graceful shutdown drain timeout: {}s (env: {})",
            drain_timeout.as_secs(),
            SHUTDOWN_DRAIN_TIMEOUT_ENV
        );

        let server_instance = Self {
            is_running: is_running_state,
            token_manager: token_manager.clone(),
            shutdown_tx,
        };
        let handle = tokio::spawn(async move {
            use hyper::server::conn::http1;
            use hyper_util::rt::TokioIo;
            use hyper_util::service::TowerToHyperService;
            let mut connection_tasks = tokio::task::JoinSet::new();

            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            tracing::info!("Shutdown signal received; stopping accept loop");
                            break;
                        }
                    }
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, remote_addr)) => {
                                let io = TokioIo::new(stream);
                                use hyper::body::Incoming;
                                use tower::ServiceExt;
                                let app_with_info = app.clone().map_request(
                                    move |mut req: axum::http::Request<Incoming>| {
                                        req.extensions_mut()
                                            .insert(axum::extract::ConnectInfo(remote_addr));
                                        req
                                    },
                                );

                                let service = TowerToHyperService::new(app_with_info);

                                connection_tasks.spawn(async move {
                                    if let Err(err) = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .with_upgrades()
                                        .await
                                    {
                                        debug!("Connection handling ended or failed: {:?}", err);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept connection: {:?}", e);
                            }
                        }
                    }
                }
            }

            let drain_result = tokio::time::timeout(drain_timeout, async {
                while connection_tasks.join_next().await.is_some() {}
            })
            .await;

            if drain_result.is_err() {
                warn!("Timed out draining active connections; aborting remaining tasks");
                connection_tasks.abort_all();
                while connection_tasks.join_next().await.is_some() {}
            }

            clear_global_shutdown_sender();
            tracing::info!("Proxy server shutdown complete");
        });

        Ok((server_instance, handle))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_shutdown_drain_timeout_secs, AxumServer, AxumStartConfig,
        SHUTDOWN_DRAIN_TIMEOUT_ENV,
    };
    use crate::modules::system::integration::SystemManager;
    use crate::proxy::config::{
        CorsConfig, DebugLoggingConfig, ExperimentalConfig, ProxyPoolConfig, UpstreamProxyConfig,
        ZaiConfig,
    };
    use crate::proxy::monitor::ProxyMonitor;
    use crate::proxy::{ProxyAuthMode, ProxySecurityConfig, TokenManager};
    use futures::StreamExt;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::OnceLock;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;
    use tokio::time::Instant;

    static SERVER_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct ScopedEnvVar {
        key: &'static str,
        original: Option<String>,
    }

    impl ScopedEnvVar {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, original }
        }
    }

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            if let Some(value) = self.original.as_deref() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn reserve_local_port() -> u16 {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral test listener");
        listener
            .local_addr()
            .expect("ephemeral listener local_addr")
            .port()
    }

    async fn wait_for_server_ready(port: u16) {
        let client = reqwest::Client::builder().build().expect("reqwest client");
        let url = format!("http://127.0.0.1:{}/health", port);

        for _ in 0..40 {
            let ready = client
                .get(&url)
                .header("Authorization", "Bearer test-api-key")
                .send()
                .await
                .map(|resp| resp.status().is_success())
                .unwrap_or(false);
            if ready {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        panic!("test server did not become ready in time");
    }

    fn test_start_config(port: u16) -> AxumStartConfig {
        let data_dir = std::env::temp_dir().join(format!(
            ".gephyr-shutdown-drain-test-{}",
            uuid::Uuid::new_v4()
        ));
        AxumStartConfig {
            host: "127.0.0.1".to_string(),
            port,
            token_manager: Arc::new(TokenManager::new(data_dir)),
            custom_mapping: HashMap::new(),
            request_timeout: 30,
            upstream_proxy: UpstreamProxyConfig::default(),
            user_agent_override: None,
            cors_config: CorsConfig::default(),
            security_config: ProxySecurityConfig {
                auth_mode: ProxyAuthMode::Strict,
                api_key: "test-api-key".to_string(),
                admin_password: None,
                allow_lan_access: false,
                port,
                security_monitor: crate::proxy::config::SecurityMonitorConfig::default(),
            },
            zai_config: ZaiConfig::default(),
            monitor: Arc::new(ProxyMonitor::new(64)),
            experimental_config: ExperimentalConfig::default(),
            debug_logging: DebugLoggingConfig::default(),
            integration: SystemManager::Headless,
            proxy_pool_config: ProxyPoolConfig::default(),
        }
    }

    #[test]
    fn normalize_shutdown_drain_timeout_accepts_valid_values() {
        assert_eq!(normalize_shutdown_drain_timeout_secs("15"), Some(15));
    }

    #[test]
    fn normalize_shutdown_drain_timeout_rejects_invalid_or_empty_values() {
        assert_eq!(normalize_shutdown_drain_timeout_secs(""), None);
        assert_eq!(normalize_shutdown_drain_timeout_secs("abc"), None);
    }

    #[test]
    fn normalize_shutdown_drain_timeout_clamps_to_supported_bounds() {
        assert_eq!(normalize_shutdown_drain_timeout_secs("0"), Some(1));
        assert_eq!(normalize_shutdown_drain_timeout_secs("99999"), Some(600));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_completes_with_in_flight_request_after_drain_timeout() {
        let _guard = SERVER_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await;
        let _drain_timeout_env = ScopedEnvVar::set(SHUTDOWN_DRAIN_TIMEOUT_ENV, "1");

        let port = reserve_local_port();
        let start_config = test_start_config(port);
        let (server, mut handle) = AxumServer::start(start_config)
            .await
            .expect("server should start");
        wait_for_server_ready(port).await;

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to test server");
        stream
            .write_all(
                b"POST /v1/messages HTTP/1.1\r\n\
Host: 127.0.0.1\r\n\
Authorization: Bearer test-api-key\r\n\
Content-Type: application/json\r\n\
Content-Length: 4096\r\n\
\r\n\
{\"model\":\"claude-3-5-haiku\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]",
            )
            .await
            .expect("write partial request");

        tokio::time::sleep(Duration::from_millis(50)).await;
        server.request_shutdown();

        let joined = tokio::time::timeout(Duration::from_secs(4), &mut handle).await;
        assert!(
            joined.is_ok(),
            "server task should finish after drain timeout and abort"
        );
        let join_result = joined.expect("join timeout result");
        assert!(
            join_result.is_ok(),
            "server task should exit without panic: {join_result:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn http1_health_concurrency_smoke_benchmark() {
        let _guard = SERVER_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await;
        let _drain_timeout_env = ScopedEnvVar::set(SHUTDOWN_DRAIN_TIMEOUT_ENV, "2");

        let port = reserve_local_port();
        let start_config = test_start_config(port);
        let (server, mut handle) = AxumServer::start(start_config)
            .await
            .expect("server should start");
        wait_for_server_ready(port).await;

        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(64)
            .build()
            .expect("reqwest client");
        let total_requests = 1500usize;
        let concurrency = 64usize;
        let url = format!("http://127.0.0.1:{}/health", port);

        let start = Instant::now();
        let statuses: Vec<u16> = futures::stream::iter(0..total_requests)
            .map(|_| {
                let client = client.clone();
                let url = url.clone();
                async move {
                    for attempt in 0..3 {
                        match client
                            .get(&url)
                            .header("Authorization", "Bearer test-api-key")
                            .send()
                            .await
                        {
                            Ok(resp) => return resp.status().as_u16(),
                            Err(_) if attempt < 2 => {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                            Err(err) => panic!("request should succeed: {err}"),
                        }
                    }
                    unreachable!("retry loop always returns or panics");
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;
        let elapsed = start.elapsed();

        let success_count = statuses.iter().filter(|&&status| status == 200).count();
        let rps = total_requests as f64 / elapsed.as_secs_f64();

        assert_eq!(
            success_count, total_requests,
            "all benchmark requests should return 200"
        );
        assert!(
            rps > 200.0,
            "unexpectedly low local HTTP/1.1 throughput: {:.2} req/s",
            rps
        );

        println!(
            "HTTP/1.1 benchmark: total={}, concurrency={}, elapsed_ms={}, rps={:.2}",
            total_requests,
            concurrency,
            elapsed.as_millis(),
            rps
        );

        server.request_shutdown();
        let joined = tokio::time::timeout(Duration::from_secs(5), &mut handle).await;
        assert!(joined.is_ok(), "server should stop after benchmark");
        let join_result = joined.expect("join timeout result");
        assert!(
            join_result.is_ok(),
            "server task should exit without panic: {join_result:?}"
        );
    }
}
