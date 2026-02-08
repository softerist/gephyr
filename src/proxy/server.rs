use crate::proxy::TokenManager;
use axum::{extract::DefaultBodyLimit, routing::get, Router};
use std::collections::HashSet;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;
use tracing::{debug, error};
static PENDING_RELOAD_ACCOUNTS: OnceLock<std::sync::RwLock<HashSet<String>>> = OnceLock::new();
static PENDING_DELETE_ACCOUNTS: OnceLock<std::sync::RwLock<HashSet<String>>> = OnceLock::new();

fn get_pending_reload_accounts() -> &'static std::sync::RwLock<HashSet<String>> {
    PENDING_RELOAD_ACCOUNTS.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

fn get_pending_delete_accounts() -> &'static std::sync::RwLock<HashSet<String>> {
    PENDING_DELETE_ACCOUNTS.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
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
#[derive(Clone)]
pub struct AxumServer {
    pub is_running: Arc<RwLock<bool>>,
    pub token_manager: Arc<TokenManager>,
}

impl AxumServer {
    pub async fn set_running(&self, running: bool) {
        let mut r = self.is_running.write().await;
        *r = running;
        tracing::info!("Proxy service running status updated to: {}", running);
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        host: String,
        port: u16,
        token_manager: Arc<TokenManager>,
        custom_mapping: std::collections::HashMap<String, String>,
        _request_timeout: u64,
        upstream_proxy: crate::proxy::config::UpstreamProxyConfig,
        user_agent_override: Option<String>,
        security_config: crate::proxy::ProxySecurityConfig,
        zai_config: crate::proxy::ZaiConfig,
        monitor: Arc<crate::proxy::monitor::ProxyMonitor>,
        experimental_config: crate::proxy::config::ExperimentalConfig,
        debug_logging: crate::proxy::config::DebugLoggingConfig,

        integration: crate::modules::system::integration::SystemManager,
        proxy_pool_config: crate::proxy::config::ProxyPoolConfig,
    ) -> Result<(Self, tokio::task::JoinHandle<()>), String> {
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
        let thought_signature_map =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let account_service = Arc::new(crate::modules::auth::account_service::AccountService::new(
            integration.clone(),
        ));
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
            request_timeout: 300,
        });
        let runtime_state = Arc::new(RuntimeState {
            thought_signature_map: thought_signature_map.clone(),
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
            .layer(cors_layer())
            .layer(DefaultBodyLimit::max(max_body_size))
            .with_state(state.clone())
        };
        let addr = format!("{}:{}", host, port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Address {} binding failed: {}", addr, e))?;

        tracing::info!("Proxy server started at http://{}", addr);

        let server_instance = Self {
            is_running: is_running_state,
            token_manager: token_manager.clone(),
        };
        let handle = tokio::spawn(async move {
            use hyper::server::conn::http1;
            use hyper_util::rt::TokioIo;
            use hyper_util::service::TowerToHyperService;

            loop {
                match listener.accept().await {
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

                        tokio::task::spawn(async move {
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
        });

        Ok((server_instance, handle))
    }
}
