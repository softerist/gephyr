use crate::proxy::monitor::ProxyMonitor;
use crate::proxy::{ProxyConfig, TokenManager};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
    pub base_url: String,
    pub active_accounts: usize,
}
#[derive(Clone)]
pub struct ProxyServiceState {
    pub instance: Arc<RwLock<Option<ProxyServiceInstance>>>,
    pub monitor: Arc<RwLock<Option<Arc<ProxyMonitor>>>>,
    pub admin_server: Arc<RwLock<Option<AdminServerInstance>>>,
    pub starting: Arc<AtomicBool>,
}

pub struct AdminServerInstance {
    pub axum_server: crate::proxy::AxumServer,
    pub server_handle: tokio::task::JoinHandle<()>,
}
pub struct ProxyServiceInstance {
    pub token_manager: Arc<TokenManager>,
}

impl ProxyServiceState {
    pub fn new() -> Self {
        Self {
            instance: Arc::new(RwLock::new(None)),
            monitor: Arc::new(RwLock::new(None)),
            admin_server: Arc::new(RwLock::new(None)),
            starting: Arc::new(AtomicBool::new(false)),
        }
    }
}

struct StartingGuard(Arc<AtomicBool>);
impl Drop for StartingGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

async fn ensure_monitor(state: &ProxyServiceState) -> Arc<ProxyMonitor> {
    let (monitor, needs_startup_maintenance) = {
        let mut monitor_lock = state.monitor.write().await;
        if let Some(existing) = monitor_lock.as_ref() {
            (existing.clone(), false)
        } else {
            let created = Arc::new(ProxyMonitor::new(1000));
            *monitor_lock = Some(created.clone());
            (created, true)
        }
    };

    if needs_startup_maintenance {
        monitor.run_startup_maintenance().await;
    }

    monitor
}

pub async fn internal_start_proxy_service(
    config: ProxyConfig,
    state: &ProxyServiceState,
    integration: crate::modules::system::integration::SystemManager,
) -> Result<ProxyStatus, String> {
    {
        let instance_lock = state.instance.read().await;
        if instance_lock.is_some() {
            return Err("Service is already running".to_string());
        }
    }
    if state
        .starting
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("Service is starting, please wait...".to_string());
    }
    let _starting_guard = StartingGuard(state.starting.clone());
    let monitor = ensure_monitor(state).await;
    monitor.set_enabled(config.enable_logging);
    crate::proxy::middleware::client_ip::set_trusted_proxies(config.trusted_proxies.clone());

    ensure_admin_server(config.clone(), state, integration.clone()).await?;
    let token_manager = {
        let admin_lock = state.admin_server.read().await;
        admin_lock
            .as_ref()
            .unwrap()
            .axum_server
            .token_manager
            .clone()
    };
    token_manager.start_auto_cleanup().await;
    token_manager
        .update_sticky_config(config.scheduling.clone())
        .await;
    token_manager.update_session_binding_persistence(config.persist_session_bindings);
    token_manager
        .update_compliance_config(config.compliance.clone())
        .await;
    let app_config = crate::modules::system::config::load_app_config()
        .unwrap_or_else(|_| crate::models::AppConfig::new());
    token_manager
        .update_circuit_breaker_config(app_config.circuit_breaker)
        .await;
    if let Some(ref account_id) = config.preferred_account_id {
        token_manager
            .set_preferred_account(Some(account_id.clone()))
            .await;
        tracing::info!("🔒 Fixed account mode restored: {}", account_id);
    }
    let active_accounts = token_manager.load_accounts().await.unwrap_or(0);
    token_manager.restore_persisted_session_bindings();

    if active_accounts == 0 {
        let zai_enabled = config.zai.enabled
            && !matches!(config.zai.dispatch_mode, crate::proxy::ZaiDispatchMode::Off);
        if !zai_enabled {
            tracing::warn!("No available accounts. Proxy logic will pause. Please add them via the management interface.");
            return Ok(ProxyStatus {
                running: false,
                port: config.port,
                base_url: format!("http://127.0.0.1:{}", config.port),
                active_accounts: 0,
            });
        }
    }

    let mut instance_lock = state.instance.write().await;
    let admin_lock = state.admin_server.read().await;
    let axum_server = admin_lock.as_ref().unwrap().axum_server.clone();
    let instance = ProxyServiceInstance {
        token_manager: token_manager.clone(),
    };
    axum_server.set_running(true).await;

    *instance_lock = Some(instance);
    Ok(ProxyStatus {
        running: true,
        port: config.port,
        base_url: format!("http://127.0.0.1:{}", config.port),
        active_accounts,
    })
}
pub async fn ensure_admin_server(
    config: ProxyConfig,
    state: &ProxyServiceState,
    integration: crate::modules::system::integration::SystemManager,
) -> Result<(), String> {
    let mut admin_lock = state.admin_server.write().await;
    if admin_lock.is_some() {
        return Ok(());
    }
    crate::proxy::middleware::client_ip::set_trusted_proxies(config.trusted_proxies.clone());
    let monitor = ensure_monitor(state).await;
    let app_data_dir = crate::modules::auth::account::get_data_dir()?;
    let token_manager = Arc::new(TokenManager::new(app_data_dir));
    let _ = token_manager.load_accounts().await;

    let start_config = crate::proxy::AxumStartConfig {
        host: config.get_bind_address().to_string(),
        port: config.port,
        token_manager,
        custom_mapping: config.custom_mapping.clone(),
        request_timeout: config.request_timeout,
        upstream_proxy: config.upstream_proxy.clone(),
        user_agent_override: config.user_agent_override.clone(),
        cors_config: config.cors.clone(),
        security_config: crate::proxy::ProxySecurityConfig::from_proxy_config(&config),
        zai_config: config.zai.clone(),
        monitor,
        experimental_config: config.experimental.clone(),
        debug_logging: config.debug_logging.clone(),
        integration: integration.clone(),
        proxy_pool_config: config.proxy_pool.clone(),
    };

    let (axum_server, server_handle) = match crate::proxy::AxumServer::start(start_config).await {
        Ok((server, handle)) => (server, handle),
        Err(e) => return Err(format!("Failed to start management server: {}", e)),
    };

    *admin_lock = Some(AdminServerInstance {
        axum_server,
        server_handle,
    });
    crate::proxy::update_thinking_budget_config(config.thinking_budget.clone());

    Ok(())
}

pub async fn internal_stop_proxy_service(state: &ProxyServiceState) -> Result<(), String> {
    {
        let mut instance_lock = state.instance.write().await;
        *instance_lock = None;
    }

    let admin_instance = {
        let mut admin_lock = state.admin_server.write().await;
        admin_lock.take()
    };

    if let Some(admin_instance) = admin_instance {
        admin_instance.axum_server.set_running(false).await;
        admin_instance.axum_server.request_shutdown();

        let mut server_handle = admin_instance.server_handle;
        match tokio::time::timeout(std::time::Duration::from_secs(15), &mut server_handle).await {
            Ok(Ok(())) => {
                tracing::info!("Proxy server task exited cleanly");
            }
            Ok(Err(e)) => {
                tracing::warn!("Proxy server task join error during shutdown: {}", e);
            }
            Err(_) => {
                tracing::warn!("Proxy server shutdown timed out; aborting server task");
                server_handle.abort();
                let _ = server_handle.await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::{internal_start_proxy_service, internal_stop_proxy_service, ProxyServiceState};
    use crate::modules::persistence::proxy_db;
    use crate::modules::system::integration::SystemManager;
    use crate::proxy::monitor::ProxyRequestLog;
    use crate::proxy::ProxyConfig;
    use std::sync::{Mutex, OnceLock};

    static PROXY_STARTUP_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn reserve_local_port() -> u16 {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral test listener");
        listener
            .local_addr()
            .expect("ephemeral listener local_addr")
            .port()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn startup_runs_monitor_maintenance_and_initializes_proxy_db() {
        let _security_guard = crate::proxy::tests::acquire_security_test_lock();
        let _guard = PROXY_STARTUP_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        proxy_db::init_db().expect("proxy db init");
        let old_log_id = format!("startup-maintenance-{}", uuid::Uuid::new_v4());
        let old_timestamp = chrono::Utc::now().timestamp() - (40 * 24 * 3600);
        let seeded_old_log = ProxyRequestLog {
            id: old_log_id.clone(),
            timestamp: old_timestamp,
            method: "GET".to_string(),
            url: "/maintenance-test".to_string(),
            status: 200,
            duration: 1,
            model: None,
            mapped_model: None,
            account_email: None,
            client_ip: Some("127.0.0.1".to_string()),
            error: None,
            request_body: None,
            response_body: None,
            input_tokens: None,
            output_tokens: None,
            protocol: None,
            username: None,
        };
        proxy_db::save_log(&seeded_old_log).expect("seed old proxy log");

        let config = ProxyConfig {
            port: reserve_local_port(),
            enable_logging: false,
            ..ProxyConfig::default()
        };

        let state = ProxyServiceState::new();
        let start_result =
            internal_start_proxy_service(config, &state, SystemManager::Headless).await;
        assert!(
            start_result.is_ok(),
            "service start should succeed: {:?}",
            start_result.err()
        );

        assert!(
            proxy_db::get_log_detail(&old_log_id).is_err(),
            "startup maintenance should clean old proxy logs"
        );

        let _ = internal_stop_proxy_service(&state).await;
    }
}
