use crate::proxy::rate_limit::RateLimitTracker;
use crate::proxy::sticky_config::StickySessionConfig;
pub use crate::proxy::token::types::ProxyToken;
use dashmap::DashMap;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const STICKY_EVENT_BUFFER_SIZE: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct StickyDecisionEvent {
    pub timestamp_unix: i64,
    pub action: String,
    pub session_id: String,
    pub bound_account_id: Option<String>,
    pub selected_account_id: Option<String>,
    pub model: Option<String>,
    pub wait_seconds: Option<u64>,
    pub max_wait_seconds: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StickyDebugSnapshot {
    pub persist_session_bindings: bool,
    pub scheduling: StickySessionConfig,
    pub session_bindings: HashMap<String, String>,
    pub recent_events: Vec<StickyDecisionEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComplianceDebugSnapshot {
    pub config: crate::proxy::config::ComplianceConfig,
    pub global_requests_in_last_minute: usize,
    pub account_requests_in_last_minute: HashMap<String, usize>,
    pub account_in_flight: HashMap<String, usize>,
    pub account_cooldown_seconds_remaining: HashMap<String, u64>,
}

#[derive(Default)]
pub(super) struct ComplianceRuntimeState {
    pub global_request_timestamps: VecDeque<std::time::Instant>,
    pub account_request_timestamps: HashMap<String, VecDeque<std::time::Instant>>,
    pub account_in_flight: HashMap<String, usize>,
    pub account_cooldown_until: HashMap<String, std::time::Instant>,
}

pub struct ComplianceRequestGuard {
    account_id: String,
    state: Arc<std::sync::Mutex<ComplianceRuntimeState>>,
}

pub(super) struct StickyEventRecord<'a> {
    pub action: &'a str,
    pub session_id: &'a str,
    pub bound_account_id: Option<&'a str>,
    pub selected_account_id: Option<&'a str>,
    pub model: Option<&'a str>,
    pub wait_seconds: Option<u64>,
    pub max_wait_seconds: Option<u64>,
    pub reason: Option<&'a str>,
}

impl Drop for ComplianceRequestGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(count) = state.account_in_flight.get_mut(&self.account_id) {
                if *count > 1 {
                    *count -= 1;
                } else {
                    state.account_in_flight.remove(&self.account_id);
                }
            }
        }
    }
}

pub struct TokenManager {
    tokens: Arc<DashMap<String, ProxyToken>>,
    current_index: Arc<AtomicUsize>,
    last_used_account: Arc<tokio::sync::Mutex<Option<(String, std::time::Instant)>>>,
    data_dir: PathBuf,
    rate_limit_tracker: Arc<RateLimitTracker>,
    sticky_config: Arc<tokio::sync::RwLock<StickySessionConfig>>,
    session_accounts: Arc<DashMap<String, String>>,
    persist_session_bindings: Arc<AtomicBool>,
    preferred_account_id: Arc<tokio::sync::RwLock<Option<String>>>,
    health_scores: Arc<DashMap<String, f32>>,
    circuit_breaker_config: Arc<tokio::sync::RwLock<crate::models::CircuitBreakerConfig>>,
    sticky_events: Arc<std::sync::Mutex<VecDeque<StickyDecisionEvent>>>,
    auto_cleanup_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cancel_token: CancellationToken,
    compliance_config: Arc<tokio::sync::RwLock<crate::proxy::config::ComplianceConfig>>,
    compliance_state: Arc<std::sync::Mutex<ComplianceRuntimeState>>,
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
            persist_session_bindings: Arc::new(AtomicBool::new(false)),
            preferred_account_id: Arc::new(tokio::sync::RwLock::new(None)),
            health_scores: Arc::new(DashMap::new()),
            circuit_breaker_config: Arc::new(tokio::sync::RwLock::new(
                crate::models::CircuitBreakerConfig::default(),
            )),
            sticky_events: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            auto_cleanup_handle: Arc::new(tokio::sync::Mutex::new(None)),
            cancel_token: CancellationToken::new(),
            compliance_config: Arc::new(tokio::sync::RwLock::new(
                crate::proxy::config::ComplianceConfig::default(),
            )),
            compliance_state: Arc::new(std::sync::Mutex::new(ComplianceRuntimeState::default())),
        }
    }

    pub(super) fn record_sticky_event(&self, record: StickyEventRecord<'_>) {
        let event = StickyDecisionEvent {
            timestamp_unix: chrono::Utc::now().timestamp(),
            action: record.action.to_string(),
            session_id: record.session_id.to_string(),
            bound_account_id: record.bound_account_id.map(|v| v.to_string()),
            selected_account_id: record.selected_account_id.map(|v| v.to_string()),
            model: record.model.map(|v| v.to_string()),
            wait_seconds: record.wait_seconds,
            max_wait_seconds: record.max_wait_seconds,
            reason: record.reason.map(|v| v.to_string()),
        };

        if let Ok(mut queue) = self.sticky_events.lock() {
            queue.push_back(event);
            while queue.len() > STICKY_EVENT_BUFFER_SIZE {
                queue.pop_front();
            }
        }
    }
    pub(super) fn set_persist_session_bindings_enabled(&self, enabled: bool) {
        self.persist_session_bindings
            .store(enabled, Ordering::Relaxed);
    }
    pub(super) fn clear_persisted_session_bindings_file(&self) {
        let path = self.data_dir.join("session_bindings.json");
        let tmp_path = self.data_dir.join("session_bindings.json.tmp");
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(tmp_path);
    }
    pub(super) fn persist_session_bindings_internal(&self) {
        if !self.persist_session_bindings.load(Ordering::Relaxed) {
            return;
        }

        let bindings: std::collections::HashMap<String, String> = self
            .session_accounts
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect();
        let path = self.data_dir.join("session_bindings.json");
        let tmp_path = self.data_dir.join("session_bindings.json.tmp");

        if let Err(e) = std::fs::create_dir_all(&self.data_dir) {
            tracing::warn!(
                "Failed to create data directory for session bindings persistence: {}",
                e
            );
            return;
        }
        let content = match serde_json::to_string_pretty(&bindings) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to serialize session bindings: {}", e);
                return;
            }
        };
        if let Err(e) = std::fs::write(&tmp_path, content) {
            tracing::warn!("Failed to write session bindings temp file: {}", e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, &path) {
            // Windows rename fails when destination exists; fall back to replace semantics.
            let _ = std::fs::remove_file(&path);
            if let Err(e2) = std::fs::rename(&tmp_path, &path) {
                tracing::warn!(
                    "Failed to move session bindings temp file into place: {} / {}",
                    e,
                    e2
                );
                let _ = std::fs::remove_file(&tmp_path);
            }
        }
    }
    pub(super) fn restore_session_bindings_internal(&self) {
        if !self.persist_session_bindings.load(Ordering::Relaxed) {
            return;
        }

        let path = self.data_dir.join("session_bindings.json");
        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("Failed to read persisted session bindings: {}", e);
                }
                return;
            }
        };
        let persisted: std::collections::HashMap<String, String> =
            match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Failed to parse persisted session bindings JSON: {}", e);
                    return;
                }
            };

        self.session_accounts.clear();
        let valid_accounts: std::collections::HashSet<String> =
            self.tokens.iter().map(|e| e.key().clone()).collect();
        let mut restored = 0usize;
        let mut dropped = 0usize;
        for (session_id, account_id) in persisted {
            if valid_accounts.contains(&account_id) {
                self.session_accounts.insert(session_id, account_id);
                restored += 1;
            } else {
                dropped += 1;
            }
        }
        if restored > 0 || dropped > 0 {
            tracing::info!(
                "Session bindings restored: restored={}, dropped={}",
                restored,
                dropped
            );
        }
        if dropped > 0 {
            self.persist_session_bindings_internal();
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
        self.persist_session_bindings_internal();
    }
    pub async fn run_startup_health_check(
        &self,
    ) -> crate::proxy::token::startup_health::HealthCheckSummary {
        crate::proxy::token::startup_health::run_startup_health_check(&self.tokens, &self.data_dir)
            .await
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
#[path = "manager_compliance.rs"]
mod manager_compliance;
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
