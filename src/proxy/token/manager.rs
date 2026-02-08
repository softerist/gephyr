use crate::proxy::rate_limit::RateLimitTracker;
use crate::proxy::sticky_config::StickySessionConfig;
pub use crate::proxy::token::types::ProxyToken;
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
pub struct TokenManager {
    tokens: Arc<DashMap<String, ProxyToken>>,
    current_index: Arc<AtomicUsize>,
    last_used_account: Arc<tokio::sync::Mutex<Option<(String, std::time::Instant)>>>,
    data_dir: PathBuf,
    rate_limit_tracker: Arc<RateLimitTracker>,
    sticky_config: Arc<tokio::sync::RwLock<StickySessionConfig>>,
    session_accounts: Arc<DashMap<String, String>>,
    preferred_account_id: Arc<tokio::sync::RwLock<Option<String>>>,
    health_scores: Arc<DashMap<String, f32>>,
    circuit_breaker_config: Arc<tokio::sync::RwLock<crate::models::CircuitBreakerConfig>>,
    auto_cleanup_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cancel_token: CancellationToken,
}
impl TokenManager {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            tokens: Arc::new(DashMap::new()),
            current_index: Arc::new(AtomicUsize::new(0)),
            last_used_account: Arc::new(tokio::sync::Mutex::new(None)),
            data_dir,
            rate_limit_tracker: Arc::new(RateLimitTracker::new()),
            sticky_config: Arc::new(tokio::sync::RwLock::new(StickySessionConfig::default())),
            session_accounts: Arc::new(DashMap::new()),
            preferred_account_id: Arc::new(tokio::sync::RwLock::new(None)),
            health_scores: Arc::new(DashMap::new()),
            circuit_breaker_config: Arc::new(tokio::sync::RwLock::new(
                crate::models::CircuitBreakerConfig::default(),
            )),
            auto_cleanup_handle: Arc::new(tokio::sync::Mutex::new(None)),
            cancel_token: CancellationToken::new(),
        }
    }
    pub async fn start_auto_cleanup(&self) {
        crate::proxy::token::lifecycle::start_auto_cleanup(
            self.rate_limit_tracker.clone(),
            &self.auto_cleanup_handle,
            &self.cancel_token,
        )
        .await;
    }
    pub async fn load_accounts(&self) -> Result<usize, String> {
        crate::proxy::token::account_pool::load_accounts(
            &self.data_dir,
            self.tokens.as_ref(),
            self.current_index.as_ref(),
            self.last_used_account.as_ref(),
            self.health_scores.as_ref(),
        )
        .await
    }
    pub async fn reload_account(&self, account_id: &str) -> Result<(), String> {
        crate::proxy::token::account_pool::reload_account(
            &self.data_dir,
            self.tokens.as_ref(),
            self.health_scores.as_ref(),
            &self.rate_limit_tracker,
            self.session_accounts.as_ref(),
            &self.preferred_account_id,
            account_id,
        )
        .await
    }
    pub async fn reload_all_accounts(&self) -> Result<usize, String> {
        crate::proxy::token::account_pool::reload_all_accounts(
            &self.data_dir,
            self.tokens.as_ref(),
            self.current_index.as_ref(),
            self.last_used_account.as_ref(),
            self.health_scores.as_ref(),
            &self.rate_limit_tracker,
        )
        .await
    }
    pub fn remove_account(&self, account_id: &str) {
        crate::proxy::token::account_pool::remove_account(
            self.tokens.as_ref(),
            self.health_scores.as_ref(),
            &self.rate_limit_tracker,
            self.session_accounts.as_ref(),
            &self.preferred_account_id,
            account_id,
        );
    }
    #[cfg(test)]
    pub fn get_model_quota_from_json_for_test(
        account_path: &PathBuf,
        model_name: &str,
    ) -> Option<i32> {
        crate::proxy::token::quota::get_model_quota_from_json(account_path, model_name)
    }
    pub async fn graceful_shutdown(&self, timeout: std::time::Duration) {
        crate::proxy::token::lifecycle::graceful_shutdown(
            &self.cancel_token,
            &self.auto_cleanup_handle,
            timeout,
        )
        .await;
    }
    pub async fn abort_background_tasks(&self) {
        crate::proxy::token::lifecycle::abort_background_tasks(&self.auto_cleanup_handle).await;
    }
}
#[path = "manager_ops.rs"]
mod manager_ops;
#[path = "manager_runtime.rs"]
mod manager_runtime;
#[path = "manager_runtime_preferred.rs"]
mod manager_runtime_preferred;
#[path = "manager_runtime_rotation.rs"]
mod manager_runtime_rotation;
#[path = "manager_runtime_shared.rs"]
mod manager_runtime_shared;
#[path = "manager_selection.rs"]
mod manager_selection;
#[cfg(test)]
#[path = "manager_tests.rs"]
mod manager_tests;
