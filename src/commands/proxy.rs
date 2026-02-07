use std::sync::Arc;
use tokio::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use serde::{Serialize, Deserialize};
use crate::proxy::{ProxyConfig, TokenManager};
use crate::proxy::monitor::ProxyMonitor;


// Proxy service status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
    pub base_url: String,
    pub active_accounts: usize,
}

// Global state of the proxy service
#[derive(Clone)]
pub struct ProxyServiceState {
    pub instance: Arc<RwLock<Option<ProxyServiceInstance>>>,
    pub monitor: Arc<RwLock<Option<Arc<ProxyMonitor>>>>,
    pub admin_server: Arc<RwLock<Option<AdminServerInstance>>>, //  Persistent management server
    pub starting: Arc<AtomicBool>, //  Indicates whether starting is in progress to prevent deadlocks
}

pub struct AdminServerInstance {
    pub axum_server: crate::proxy::AxumServer,
}

// Proxy service instance
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

// Internal logic to start proxy service (decoupled version)
pub async fn internal_start_proxy_service(
    config: ProxyConfig,
    state: &ProxyServiceState,
    integration: crate::modules::integration::SystemManager,
) -> Result<ProxyStatus, String> {
    // 1. Check status and acquire lock
    {
        let instance_lock = state.instance.read().await;
        if instance_lock.is_some() {
            return Err("Service is already running".to_string());
        }
    }

    // 2. Check if starting is in progress (prevent deadlock & concurrent starts)
    if state.starting.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Err("Service is starting, please wait...".to_string());
    }

    // Use a custom Drop guard to ensure the starting status is reset regardless of success or failure
    let _starting_guard = StartingGuard(state.starting.clone());

    // Ensure monitor exists
    {
        let mut monitor_lock = state.monitor.write().await;
        if monitor_lock.is_none() {
            *monitor_lock = Some(Arc::new(ProxyMonitor::new(1000)));
        }
        // Sync enabled state from config
        if let Some(monitor) = monitor_lock.as_ref() {
            monitor.set_enabled(config.enable_logging);
        }
    }

    let _monitor = state.monitor.read().await.as_ref().unwrap().clone();

    // Check and start management server (if not already running)
    ensure_admin_server(config.clone(), state, integration.clone()).await?;

    // 2.  Reuse Token Manager from the management server (single instance, resolves hot-reload sync issues)
    let token_manager = {
        let admin_lock = state.admin_server.read().await;
        admin_lock.as_ref().unwrap().axum_server.token_manager.clone()
    };

    // Sync configuration to the running TokenManager
    token_manager.start_auto_cleanup().await;
    token_manager.update_sticky_config(config.scheduling.clone()).await;

    //  Load circuit breaker configuration (loaded from main config)
    let app_config = crate::modules::config::load_app_config().unwrap_or_else(|_| crate::models::AppConfig::new());
    token_manager.update_circuit_breaker_config(app_config.circuit_breaker).await;

    // 🆕  Restore fixed account mode settings
    if let Some(ref account_id) = config.preferred_account_id {
        token_manager.set_preferred_account(Some(account_id.clone())).await;
        tracing::info!("🔒 Fixed account mode restored: {}", account_id);
    }

    // 3. Load accounts
    let active_accounts = token_manager.load_accounts().await
        .unwrap_or(0);

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

    // Create service instance (logical start)
    let instance = ProxyServiceInstance {
        token_manager: token_manager.clone(),
    };

    //  Ensure the server is logically running
    axum_server.set_running(true).await;

    *instance_lock = Some(instance);

    // After successful start, it's fine for the guard to end and reset the starting status here.
    // However, we could also manually drop it, or trust the guard.
    Ok(ProxyStatus {
        running: true,
        port: config.port,
        base_url: format!("http://127.0.0.1:{}", config.port),
        active_accounts,
    })
}

// Ensure management server is running
pub async fn ensure_admin_server(
    config: ProxyConfig,
    state: &ProxyServiceState,
    integration: crate::modules::integration::SystemManager,
) -> Result<(), String> {
    let mut admin_lock = state.admin_server.write().await;
    if admin_lock.is_some() {
        return Ok(());
    }

    // Ensure monitor exists
    let monitor = {
        let mut monitor_lock = state.monitor.write().await;
        if monitor_lock.is_none() {
            *monitor_lock = Some(Arc::new(ProxyMonitor::new(1000)));
        }
        monitor_lock.as_ref().unwrap().clone()
    };

    // Default empty TokenManager for management interface
    let app_data_dir = crate::modules::account::get_data_dir()?;
    let token_manager = Arc::new(TokenManager::new(app_data_dir));
    //  Load account data, otherwise management interface stats will be 0
    let _ = token_manager.load_accounts().await;

    let (axum_server, _server_handle) =
        match crate::proxy::AxumServer::start(
            config.get_bind_address().to_string(),
            config.port,
            token_manager,
            config.custom_mapping.clone(),
            config.request_timeout,
            config.upstream_proxy.clone(),
            config.user_agent_override.clone(),
            crate::proxy::ProxySecurityConfig::from_proxy_config(&config),
            config.zai.clone(),
            monitor,
            config.experimental.clone(),
            config.debug_logging.clone(),
            integration.clone(),
            config.proxy_pool.clone(),
        ).await {
            Ok((server, handle)) => (server, handle),
            Err(e) => return Err(format!("Failed to start management server: {}", e)),
        };

    *admin_lock = Some(AdminServerInstance {
        axum_server,
    });

    //  Initialize global Thinking Budget configuration
    crate::proxy::update_thinking_budget_config(config.thinking_budget.clone());

    Ok(())
}
