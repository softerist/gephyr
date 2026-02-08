use crate::proxy::TokenManager;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct CoreServices {
    pub token_manager: Arc<TokenManager>,
    pub upstream: Arc<crate::proxy::upstream::client::UpstreamClient>,
    pub monitor: Arc<crate::proxy::monitor::ProxyMonitor>,
    pub integration: crate::modules::integration::SystemManager,
    pub account_service: Arc<crate::modules::account_service::AccountService>,
}

#[derive(Clone)]
pub struct ConfigState {
    pub custom_mapping: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    pub upstream_proxy: Arc<tokio::sync::RwLock<crate::proxy::config::UpstreamProxyConfig>>,
    pub zai: Arc<RwLock<crate::proxy::ZaiConfig>>,
    pub experimental: Arc<RwLock<crate::proxy::config::ExperimentalConfig>>,
    pub debug_logging: Arc<RwLock<crate::proxy::config::DebugLoggingConfig>>,
    pub security: Arc<RwLock<crate::proxy::ProxySecurityConfig>>,
    pub request_timeout: u64,
}

#[derive(Clone)]
pub struct RuntimeState {
    pub thought_signature_map: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
    pub provider_rr: Arc<AtomicUsize>,
    pub switching: Arc<RwLock<bool>>,
    pub is_running: Arc<RwLock<bool>>,
    pub port: u16,
    pub proxy_pool_state: Arc<tokio::sync::RwLock<crate::proxy::config::ProxyPoolConfig>>,
    pub proxy_pool_manager: Arc<crate::proxy::proxy_pool::ProxyPoolManager>,
}

// Axum application state
#[derive(Clone)]
pub struct AppState {
    pub core: Arc<CoreServices>,
    pub config: Arc<ConfigState>,
    pub runtime: Arc<RuntimeState>,
}

#[derive(Clone)]
pub struct OpenAIHandlerState {
    pub token_manager: Arc<TokenManager>,
    pub custom_mapping: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    pub upstream: Arc<crate::proxy::upstream::client::UpstreamClient>,
    pub debug_logging: Arc<RwLock<crate::proxy::config::DebugLoggingConfig>>,
}

#[derive(Clone)]
pub struct ModelCatalogState {
    pub custom_mapping: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
}

// Implement FromRef for AppState to allow middleware to extract security state
impl axum::extract::FromRef<AppState> for Arc<RwLock<crate::proxy::ProxySecurityConfig>> {
    fn from_ref(state: &AppState) -> Self {
        state.config.security.clone()
    }
}

impl axum::extract::FromRef<AppState> for CoreServices {
    fn from_ref(state: &AppState) -> Self {
        state.core.as_ref().clone()
    }
}

impl axum::extract::FromRef<AppState> for ConfigState {
    fn from_ref(state: &AppState) -> Self {
        state.config.as_ref().clone()
    }
}

impl axum::extract::FromRef<AppState> for RuntimeState {
    fn from_ref(state: &AppState) -> Self {
        state.runtime.as_ref().clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<CoreServices> {
    fn from_ref(state: &AppState) -> Self {
        state.core.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<ConfigState> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<RuntimeState> {
    fn from_ref(state: &AppState) -> Self {
        state.runtime.clone()
    }
}

impl axum::extract::FromRef<AppState> for OpenAIHandlerState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            token_manager: state.core.token_manager.clone(),
            custom_mapping: state.config.custom_mapping.clone(),
            upstream: state.core.upstream.clone(),
            debug_logging: state.config.debug_logging.clone(),
        }
    }
}

impl axum::extract::FromRef<AppState> for ModelCatalogState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            custom_mapping: state.config.custom_mapping.clone(),
        }
    }
}
