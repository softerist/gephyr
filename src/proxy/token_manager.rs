// Remove redundant top-level imports, as these are handled by full paths or local imports in the code
use dashmap::DashMap;
use std::collections::{HashSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::proxy::rate_limit::RateLimitTracker;
use crate::proxy::sticky_config::StickySessionConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnDiskAccountState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ProxyToken {
    pub account_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub timestamp: i64,
    pub email: String,
    pub account_path: PathBuf, // Account file path, used for updates
    pub project_id: Option<String>,
    pub subscription_tier: Option<String>, // "FREE" | "PRO" | "ULTRA"
    pub remaining_quota: Option<i32>,      // Remaining quota for priority sorting
    pub protected_models: HashSet<String>,
    pub health_score: f32,                 //  Health score (0.0 - 1.0)
    pub reset_time: Option<i64>,           //  Quota reset timestamp (for sorting optimization)
    pub validation_blocked: bool,          //  Check for validation block (VALIDATION_REQUIRED temporary block)
    pub validation_blocked_until: i64,     //  Timestamp until which the account is blocked
    pub model_quotas: HashMap<String, i32>, // In-memory cache for model-specific quotas
}

pub struct TokenManager {
    tokens: Arc<DashMap<String, ProxyToken>>, // account_id -> ProxyToken
    current_index: Arc<AtomicUsize>,
    last_used_account: Arc<tokio::sync::Mutex<Option<(String, std::time::Instant)>>>,
    data_dir: PathBuf,
    rate_limit_tracker: Arc<RateLimitTracker>, // Added: Rate limit tracker
    sticky_config: Arc<tokio::sync::RwLock<StickySessionConfig>>, // Added: Scheduling config
    session_accounts: Arc<DashMap<String, String>>, // Added: Session to account mapping (SessionID -> AccountID)
    preferred_account_id: Arc<tokio::sync::RwLock<Option<String>>>, //  Preferred account ID (fixed account mode)
    health_scores: Arc<DashMap<String, f32>>,                       // account_id -> health_score
    circuit_breaker_config: Arc<tokio::sync::RwLock<crate::models::CircuitBreakerConfig>>, //  Circuit breaker config cache
    // Supports actively aborting background tasks during graceful shutdown
    auto_cleanup_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cancel_token: CancellationToken,
}

impl TokenManager {
    // Create new TokenManager
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            tokens: Arc::new(DashMap::new()),
            current_index: Arc::new(AtomicUsize::new(0)),
            last_used_account: Arc::new(tokio::sync::Mutex::new(None)),
            data_dir,
            rate_limit_tracker: Arc::new(RateLimitTracker::new()),
            sticky_config: Arc::new(tokio::sync::RwLock::new(StickySessionConfig::default())),
            session_accounts: Arc::new(DashMap::new()),
            preferred_account_id: Arc::new(tokio::sync::RwLock::new(None)), // 
            health_scores: Arc::new(DashMap::new()),
            circuit_breaker_config: Arc::new(tokio::sync::RwLock::new(
                crate::models::CircuitBreakerConfig::default(),
            )),
            auto_cleanup_handle: Arc::new(tokio::sync::Mutex::new(None)),
            cancel_token: CancellationToken::new(),
        }
    }

    // Start background task to automatically clean up rate limit records (check and clear expired records every 15 seconds)
    pub async fn start_auto_cleanup(&self) {
        let tracker = self.rate_limit_tracker.clone();
        let cancel = self.cancel_token.child_token();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("Auto-cleanup task received cancel signal");
                        break;
                    }
                    _ = interval.tick() => {
                        let cleaned = tracker.cleanup_expired();
                        if cleaned > 0 {
                            tracing::info!(
                                "Auto-cleanup: Removed {} expired rate limit record(s)",
                                cleaned
                            );
                        }
                    }
                }
            }
        });

        // Abort old task first (to prevent task leakage), then store new handle
        let mut guard = self.auto_cleanup_handle.lock().await;
        if let Some(old) = guard.take() {
            old.abort();
            tracing::warn!("Aborted previous auto-cleanup task");
        }
        *guard = Some(handle);

        tracing::info!("Rate limit auto-cleanup task started (interval: 15s)");
    }

    // Load all accounts from the main application's account directory
    pub async fn load_accounts(&self) -> Result<usize, String> {
        let accounts_dir = self.data_dir.join("accounts");

        if !accounts_dir.exists() {
            return Err(format!("Account directory does not exist: {:?}", accounts_dir));
        }

        // Reload should reflect current on-disk state (accounts can be added/removed/disabled).
        self.tokens.clear();
        self.current_index.store(0, Ordering::SeqCst);
        {
            let mut last_used = self.last_used_account.lock().await;
            *last_used = None;
        }

        let entries = std::fs::read_dir(&accounts_dir)
            .map_err(|e| format!("Failed to read account directory: {}", e))?;

        let mut count = 0;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            // Try loading account
            match self.load_single_account(&path).await {
                Ok(Some(token)) => {
                    let account_id = token.account_id.clone();
                    self.tokens.insert(account_id, token);
                    count += 1;
                }
                Ok(None) => {
                    // Skip invalid account
                }
                Err(e) => {
                    tracing::debug!("Failed to load account {:?}: {}", path, e);
                }
            }
        }

        Ok(count)
    }

    // Reload a specific account (real-time sync after quota updates)
    pub async fn reload_account(&self, account_id: &str) -> Result<(), String> {
        let path = self
            .data_dir
            .join("accounts")
            .join(format!("{}.json", account_id));
        if !path.exists() {
            return Err(format!("Account file does not exist: {:?}", path));
        }

        match self.load_single_account(&path).await {
            Ok(Some(token)) => {
                self.tokens.insert(account_id.to_string(), token);
                // Automatically clear this account's rate-limit records on reload
                self.clear_rate_limit(account_id);
                Ok(())
            }
            Ok(None) => {
                // Fully remove account from in-memory pool if disabled/unavailable
                // load_single_account returning None means the account should be skipped in its
                // current state (disabled / proxy_disabled / quota_protection / validation_blocked...).
                self.remove_account(account_id);
                Ok(())
            }
            Err(e) => Err(format!("Failed to sync account: {}", e)),
        }
    }

    // Reload all accounts
    pub async fn reload_all_accounts(&self) -> Result<usize, String> {
        let count = self.load_accounts().await?;
        // Automatically clear all rate-limit records when reloading all accounts
        self.clear_all_rate_limits();
        Ok(count)
    }

    // Fully remove a specific account and its related data from memory
    pub fn remove_account(&self, account_id: &str) {
        // 1. Remove token from DashMap
        if self.tokens.remove(account_id).is_some() {
            tracing::info!("[Proxy] Removed account {} from memory cache", account_id);
        }

        // 2. Clear associated health scores
        self.health_scores.remove(account_id);

        // 3. Clear all rate limit records for this account
        self.clear_rate_limit(account_id);

        // 4. Clear all session bindings involving this account
        self.session_accounts.retain(|_, v| v != account_id);

        // 5. If it's the current preferred account, also clear it
        if let Ok(mut preferred) = self.preferred_account_id.try_write() {
            if preferred.as_deref() == Some(account_id) {
                *preferred = None;
                tracing::info!("[Proxy] Cleared preferred account status for {}", account_id);
            }
        }
    }

    // Check if an account has been disabled on disk.
    //
    // Safety net: avoids selecting a disabled account when the in-memory pool hasn't been
    // reloaded yet (e.g. fixed account mode / sticky session).
    //
    // Note: this is intentionally tolerant to transient read/parse failures (e.g. concurrent
    // writes). Failures are reported as `Unknown` so callers can skip without purging the in-memory
    // token pool.
    async fn get_account_state_on_disk(account_path: &std::path::PathBuf) -> OnDiskAccountState {
        const MAX_RETRIES: usize = 2;
        const RETRY_DELAY_MS: u64 = 5;

        for attempt in 0..=MAX_RETRIES {
            let content = match tokio::fs::read_to_string(account_path).await {
                Ok(c) => c,
                Err(e) => {
                    // If the file is gone, the in-memory token is definitely stale.
                    if e.kind() == std::io::ErrorKind::NotFound {
                        return OnDiskAccountState::Disabled;
                    }
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                        continue;
                    }
                    tracing::debug!(
                        "Failed to read account file on disk {:?}: {}",
                        account_path,
                        e
                    );
                    return OnDiskAccountState::Unknown;
                }
            };

            let account = match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(v) => v,
                Err(e) => {
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                        continue;
                    }
                    tracing::debug!(
                        "Failed to parse account JSON on disk {:?}: {}",
                        account_path,
                        e
                    );
                    return OnDiskAccountState::Unknown;
                }
            };

            let disabled = account
                .get("disabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                || account
                    .get("proxy_disabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                || account
                    .get("quota")
                    .and_then(|q| q.get("is_forbidden"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

            return if disabled {
                OnDiskAccountState::Disabled
            } else {
                OnDiskAccountState::Enabled
            };
        }

        OnDiskAccountState::Unknown
    }

    // Load single account
    async fn load_single_account(&self, path: &PathBuf) -> Result<Option<ProxyToken>, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;

        let mut account: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        // Check if account is manually disabled first (not due to quota protection)
        let is_proxy_disabled = account
            .get("proxy_disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let disabled_reason = account
            .get("proxy_disabled_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if is_proxy_disabled && disabled_reason != "quota_protection" {
            // Account manually disabled
            tracing::debug!(
                "Account skipped due to manual disable: {:?} (email={}, reason={})",
                path,
                account
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unknown>"),
                disabled_reason
            );
            return Ok(None);
        }

        //  Check for validation block (VALIDATION_REQUIRED temporary block)
        if account
            .get("validation_blocked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let block_until = account
                .get("validation_blocked_until")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            let now = chrono::Utc::now().timestamp();

            if now < block_until {
                // Still blocked
                tracing::debug!(
                    "Skipping validation-blocked account: {:?} (email={}, blocked until {})",
                    path,
                    account
                        .get("email")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unknown>"),
                    chrono::DateTime::from_timestamp(block_until, 0)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_else(|| block_until.to_string())
                );
                return Ok(None);
            } else {
                // Block expired - clear it
                account["validation_blocked"] = serde_json::json!(false);
                account["validation_blocked_until"] = serde_json::json!(0);
                account["validation_blocked_reason"] = serde_json::Value::Null;

                let updated_json =
                    serde_json::to_string_pretty(&account).map_err(|e| e.to_string())?;
                std::fs::write(path, updated_json).map_err(|e| e.to_string())?;
                tracing::info!(
                    "Validation block expired and cleared for account: {}",
                    account
                        .get("email")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<unknown>")
                );
            }
        }

        // Final check on the main account switch
        if account
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            tracing::debug!(
                "Skipping disabled account file: {:?} (email={})",
                path,
                account
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unknown>")
            );
            return Ok(None);
        }

        // Safety check: verify state on disk again to handle concurrent mid-parse writes
        if Self::get_account_state_on_disk(path).await == OnDiskAccountState::Disabled {
            tracing::debug!("Account file {:?} is disabled on disk, skipping.", path);
            return Ok(None);
        }

        // Quota protection check - only handle quota protection logic
        // This allows automatic recovery of accounts whose quotas have been restored upon loading
        if self.check_and_protect_quota(&mut account, path).await {
            tracing::debug!(
                "Account skipped due to quota protection: {:?} (email={})",
                path,
                account
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unknown>")
            );
            return Ok(None);
        }

        // [Compatibility] Confirm final state again (may have been modified by check_and_protect_quota)
        if account
            .get("proxy_disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            tracing::debug!(
                "Skipping proxy-disabled account file: {:?} (email={})",
                path,
                account
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unknown>")
            );
            return Ok(None);
        }

        let account_id = account["id"].as_str()
            .ok_or("Missing id field")?
            .to_string();

        let email = account["email"].as_str()
            .ok_or("Missing email field")?
            .to_string();

        let token_obj = account["token"].as_object()
            .ok_or("Missing token field")?;

        let access_token = token_obj["access_token"].as_str()
            .ok_or("Missing access_token")?
            .to_string();

        let refresh_token = token_obj["refresh_token"].as_str()
            .ok_or("Missing refresh_token")?
            .to_string();

        let expires_in = token_obj["expires_in"].as_i64()
            .ok_or("Missing expires_in")?;

        let timestamp = token_obj["expiry_timestamp"].as_i64()
            .ok_or("Missing expiry_timestamp")?;

        // project_id is optional
        let project_id = token_obj
            .get("project_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // [NEW] Extract subscription tier (subscription_tier is "FREE" | "PRO" | "ULTRA")
        let subscription_tier = account
            .get("quota")
            .and_then(|q| q.get("subscription_tier"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Extract max remaining quota percentage for priority sorting (Option<i32> now)
        let remaining_quota = account
            .get("quota")
            .and_then(|q| self.calculate_quota_stats(q));
            // .filter(|&r| r > 0); // Remove >0 filter; 0% is still valid but lower priority

        // [NEW #621] Extract restricted models list
        let protected_models: HashSet<String> = account
            .get("protected_models")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let health_score = self.health_scores.get(&account_id).map(|v| *v).unwrap_or(1.0);

        // Extract the most recent quota reset time (for sorting optimization: the closer the reset time, the higher the priority)
        let reset_time = self.extract_earliest_reset_time(&account);

        // [OPTIMIZATION] Build model quota memory cache to avoid reading from disk during sorting
        let mut model_quotas = HashMap::new();
        if let Some(models) = account.get("quota").and_then(|q| q.get("models")).and_then(|m| m.as_array()) {
            for model in models {
                if let (Some(name), Some(pct)) = (model.get("name").and_then(|v| v.as_str()), model.get("percentage").and_then(|v| v.as_i64())) {
                    // Normalize name to standard ID
                    let standard_id = crate::proxy::common::model_mapping::normalize_to_standard_id(name)
                        .unwrap_or_else(|| name.to_string());
                    model_quotas.insert(standard_id, pct as i32);
                }
            }
        }

        Ok(Some(ProxyToken {
            account_id,
            access_token,
            refresh_token,
            expires_in,
            timestamp,
            email,
            account_path: path.clone(),
            project_id,
            subscription_tier,
            remaining_quota,
            protected_models,
            health_score,
            reset_time,
            validation_blocked: account.get("validation_blocked").and_then(|v| v.as_bool()).unwrap_or(false),
            validation_blocked_until: account.get("validation_blocked_until").and_then(|v| v.as_i64()).unwrap_or(0),
            model_quotas,
        }))
    }

    // Check if the account should be under quota protection
    // If quota is below the threshold, automatically disable the account and return true
    async fn check_and_protect_quota(
        &self,
        account_json: &mut serde_json::Value,
        account_path: &PathBuf,
    ) -> bool {
        // 1. Load quota protection configuration
        let config = match crate::modules::config::load_app_config() {
            Ok(cfg) => cfg.quota_protection,
            Err(_) => return false, // Config loading failed, skip protection
        };

        if !config.enabled {
            return false; // Quota protection not enabled
        }

        // 2. Get quota information
        // Clone quota data for iteration to avoid borrow conflicts; mutations still target account_json
        let quota = match account_json.get("quota") {
            Some(q) => q.clone(),
            None => return false, // No quota info, skip
        };

        // 3. [Compatibility #621] Check if disabled by legacy account-level quota protection, try to restore and convert to model-level
        let is_proxy_disabled = account_json
            .get("proxy_disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let reason = account_json.get("proxy_disabled_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if is_proxy_disabled && reason == "quota_protection" {
            // If disabled by legacy account-level protection, try to restore and convert to model-level
            return self
                .check_and_restore_quota(account_json, account_path, &quota, &config)
                .await;
        }

        // No longer handle other disable reasons, let caller handle manual disable checks

        // 4. Get model list
        let models = match quota.get("models").and_then(|m| m.as_array()) {
            Some(m) => m,
            None => return false,
        };

        // 5. Traverse monitored models, check for protection and restoration
        let threshold = config.threshold_percentage as i32;

        let mut changed = false;

        for model in models {
            let name = model.get("name").and_then(|v| v.as_str()).unwrap_or("");
            // Normalize model name first, then check if it's in the monitoring list
            // This way, claude-opus-4-5-thinking is normalized to claude-sonnet-4-5 for matching
            let standard_id = crate::proxy::common::model_mapping::normalize_to_standard_id(name)
                .unwrap_or_else(|| name.to_string());

            if !config.monitored_models.iter().any(|m| m == &standard_id) {
                continue;
            }

            let percentage = model
                .get("percentage")
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as i32;
            let account_id = account_json
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            if percentage <= threshold {
                // Use normalized standard_id instead of original name
                if self
                    .trigger_quota_protection(
                        account_json,
                        &account_id,
                        account_path,
                        percentage,
                        threshold,
                        &standard_id,
                    )
                    .await
                    .unwrap_or(false)
                {
                    changed = true;
                }
            } else {
                // Try to restore (if previously restricted)
                let protected_models = account_json
                    .get("protected_models")
                    .and_then(|v| v.as_array());
                // Match using normalized standard_id
                let is_protected = protected_models.map_or(false, |arr| {
                    arr.iter().any(|m| m.as_str() == Some(&standard_id as &str))
                });

                if is_protected {
                    // Use normalized standard_id
                    if self
                        .restore_quota_protection(
                            account_json,
                            &account_id,
                            account_path,
                            &standard_id,
                        )
                        .await
                        .unwrap_or(false)
                    {
                        changed = true;
                    }
                }
            }
        }

        let _ = changed; // Avoid unused warning, can be used if later logic needs it

        // We no longer return true due to quota reasons (i.e., no longer skip accounts),
        // but load them and filter during get_token instead.
        false
    }

    // Calculate the maximum remaining quota percentage of the account (for sorting)
    // Return value: Option<i32> (max_percentage)
    fn calculate_quota_stats(&self, quota: &serde_json::Value) -> Option<i32> {
        let models = match quota.get("models").and_then(|m| m.as_array()) {
            Some(m) => m,
            None => return None,
        };

        let mut max_percentage = 0;
        let mut has_data = false;

        for model in models {
            if let Some(pct) = model.get("percentage").and_then(|v| v.as_i64()) {
                let pct_i32 = pct as i32;
                if pct_i32 > max_percentage {
                    max_percentage = pct_i32;
                }
                has_data = true;
            }
        }

        if has_data {
            Some(max_percentage)
        } else {
            None
        }
    }

    // Read quota percentage for a specific model from disk. Sorting uses the target model's quota instead of max
    //
    // # Parameters
    // * `account_path` - Account JSON file path
    // * `model_name` - Target model name (normalized)
    #[cfg(test)]
    fn get_model_quota_from_json(account_path: &PathBuf, model_name: &str) -> Option<i32> {
        let content = std::fs::read_to_string(account_path).ok()?;
        let account: serde_json::Value = serde_json::from_str(&content).ok()?;
        let models = account.get("quota")?.get("models")?.as_array()?;

        for model in models {
            if let Some(name) = model.get("name").and_then(|v| v.as_str()) {
                if crate::proxy::common::model_mapping::normalize_to_standard_id(name)
                    .unwrap_or_else(|| name.to_string())
                    == model_name
                {
                    return model
                        .get("percentage")
                        .and_then(|v| v.as_i64())
                        .map(|p| p as i32);
                }
            }
        }
        None
    }

    // Test helper function: Public access to get_model_quota_from_json
    #[cfg(test)]
    pub fn get_model_quota_from_json_for_test(account_path: &PathBuf, model_name: &str) -> Option<i32> {
        Self::get_model_quota_from_json(account_path, model_name)
    }

    // Returns true if changed
    async fn trigger_quota_protection(
        &self,
        account_json: &mut serde_json::Value,
        account_id: &str,
        account_path: &PathBuf,
        current_val: i32,
        threshold: i32,
        model_name: &str,
    ) -> Result<bool, String> {
        // 1. Initialize protected_models array (if it doesn't exist)
        if account_json.get("protected_models").is_none() {
            account_json["protected_models"] = serde_json::Value::Array(Vec::new());
        }

        let protected_models = account_json["protected_models"].as_array_mut().unwrap();

        // 2. Check if it already exists
        if !protected_models
            .iter()
            .any(|m| m.as_str() == Some(model_name))
        {
            protected_models.push(serde_json::Value::String(model_name.to_string()));

            tracing::info!(
                "Model {} of account {} has been added to the protection list due to quota limit ({}% <= {}%)",
                account_id,
                model_name,
                current_val,
                threshold
            );

            // 3. Write to disk
            std::fs::write(account_path, serde_json::to_string_pretty(account_json).unwrap())
                .map_err(|e| format!("Failed to write file: {}", e))?;

            return Ok(true);
        }

        Ok(false)
    }

    // Check and restore from account-level protection (migrate to model-level, Issue #621)
    async fn check_and_restore_quota(
        &self,
        account_json: &mut serde_json::Value,
        account_path: &PathBuf,
        quota: &serde_json::Value,
        config: &crate::models::QuotaProtectionConfig,
    ) -> bool {
        // [Compatibility] If the account is currently proxy_disabled=true and the reason is quota_protection,
        // we set its proxy_disabled to false, while updating its protected_models list.
        tracing::info!(
            "Migrating account {} from global quota protection mode to model-level protection mode",
            account_json
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );

        account_json["proxy_disabled"] = serde_json::Value::Bool(false);
        account_json["proxy_disabled_reason"] = serde_json::Value::Null;
        account_json["proxy_disabled_at"] = serde_json::Value::Null;

        let threshold = config.threshold_percentage as i32;
        let mut protected_list = Vec::new();

        if let Some(models) = quota.get("models").and_then(|m| m.as_array()) {
            for model in models {
                let name = model.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if !config.monitored_models.iter().any(|m| m == name) { continue; }

                let percentage = model.get("percentage").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                if percentage <= threshold {
                    protected_list.push(serde_json::Value::String(name.to_string()));
                }
            }
        }

        account_json["protected_models"] = serde_json::Value::Array(protected_list);

        let _ = std::fs::write(account_path, serde_json::to_string_pretty(account_json).unwrap());

        false // Return false indicating it's now okay to try loading this account (model-level filtering occurs during get_token)
    }

    // Restore quota protection for specific model
    // Returns true if changed
    async fn restore_quota_protection(
        &self,
        account_json: &mut serde_json::Value,
        account_id: &str,
        account_path: &PathBuf,
        model_name: &str,
    ) -> Result<bool, String> {
        if let Some(arr) = account_json
            .get_mut("protected_models")
            .and_then(|v| v.as_array_mut())
        {
            let original_len = arr.len();
            arr.retain(|m| m.as_str() != Some(model_name));

            if arr.len() < original_len {
                tracing::info!(
                    "Quota for model {} of account {} has been restored, removing from protection list",
                    account_id,
                    model_name
                );
                std::fs::write(
                    account_path,
                    serde_json::to_string_pretty(account_json).unwrap(),
                )
                .map_err(|e| format!("Failed to write file: {}", e))?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    // Candidate pool size for P2C algorithm - randomly select from the top N best candidates
    const P2C_POOL_SIZE: usize = 5;

    // Power of 2 Choices (P2C) selection algorithm
    // Randomly pick 2 from the top 5 candidates, select the one with higher quota -> avoid hotspots
    // Return the selected index
    //
    // # Arguments
    // * `candidates` - Sorted list of candidate tokens
    // * `attempted` - Set of account IDs that have already been attempted and failed
    // * `normalized_target` - Normalized target model name
    // * `quota_protection_enabled` - Whether quota protection is enabled
    fn select_with_p2c<'a>(
        &self,
        candidates: &'a [ProxyToken],
        attempted: &HashSet<String>,
        normalized_target: &str,
        quota_protection_enabled: bool,
    ) -> Option<&'a ProxyToken> {
        use rand::Rng;

        // Filter available tokens
        let available: Vec<&ProxyToken> = candidates.iter()
            .filter(|t| !attempted.contains(&t.account_id))
            .filter(|t| !quota_protection_enabled || !t.protected_models.contains(normalized_target))
            .collect();

        if available.is_empty() { return None; }
        if available.len() == 1 { return Some(available[0]); }

        // P2C: Randomly pick 2 from the top min(P2C_POOL_SIZE, len)
        let pool_size = available.len().min(Self::P2C_POOL_SIZE);
        let mut rng = rand::thread_rng();

        let pick1 = rng.gen_range(0..pool_size);
        let pick2 = rng.gen_range(0..pool_size);
        // Ensure two different candidates are selected
        let pick2 = if pick2 == pick1 {
            (pick1 + 1) % pool_size
        } else {
            pick2
        };

        let c1 = available[pick1];
        let c2 = available[pick2];

        // Select the one with higher quota
        let selected = if c1.remaining_quota.unwrap_or(0) >= c2.remaining_quota.unwrap_or(0) {
            c1
        } else {
            c2
        };

        tracing::debug!(
            "🎲 [P2C] Selected {} ({}%) from [{}({}%), {}({}%)]",
            selected.email, selected.remaining_quota.unwrap_or(0),
            c1.email, c1.remaining_quota.unwrap_or(0),
            c2.email, c2.remaining_quota.unwrap_or(0)
        );

        Some(selected)
    }

    // Send cancellation signal first, then wait for task completion with timeout
    //
    // # Arguments
    // * `timeout` - Timeout for waiting for task completion
    pub async fn graceful_shutdown(&self, timeout: std::time::Duration) {
        tracing::info!("Initiating graceful shutdown of background tasks...");

        // Send cancellation signal to all background tasks
        self.cancel_token.cancel();

        // Wait for task completion with timeout
        match tokio::time::timeout(timeout, self.abort_background_tasks()).await {
            Ok(_) => tracing::info!("All background tasks cleaned up gracefully"),
            Err(_) => tracing::warn!("Graceful cleanup timed out after {:?}, tasks were force-aborted", timeout),
        }
    }

    // Abort and wait for all background tasks to complete
    // abort() only sets the cancellation flag; must await to confirm cleanup completion
    pub async fn abort_background_tasks(&self) {
        Self::abort_task(&self.auto_cleanup_handle, "Auto-cleanup task").await;
    }

    // Abort a single background task and log the result
    //
    // # Arguments
    // * `handle` - Mutex reference to the task handle
    // * `task_name` - Task name (for logging)
    async fn abort_task(
        handle: &tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
        task_name: &str,
    ) {
        let Some(handle) = handle.lock().await.take() else {
            return;
        };

        handle.abort();
        match handle.await {
            Ok(()) => tracing::debug!("{} completed", task_name),
            Err(e) if e.is_cancelled() => tracing::info!("{} aborted", task_name),
            Err(e) => tracing::warn!("{} error: {}", task_name, e),
        }
    }

    // Get currently available Token (supports sticky sessions and smart scheduling)
    // Parameter `quota_group` is used to distinguish between "claude" vs "gemini" groups
    // Parameter `force_rotate` when true ignores locking and forces account switching
    // Parameter `session_id` is used to maintain session stickiness across requests
    // Parameter `target_model` is used to check quota protection
    pub async fn get_token(
        &self,
        quota_group: &str,
        force_rotate: bool,
        session_id: Option<&str>,
        target_model: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        // Check and handle accounts pending reload (quota protection synchronization)
        let pending_reload = crate::proxy::server::take_pending_reload_accounts();
        for account_id in pending_reload {
            if let Err(e) = self.reload_account(&account_id).await {
                tracing::warn!("[Quota] Failed to reload account {}: {}", account_id, e);
            } else {
                tracing::info!(
                    "[Quota] Reloaded account {} (protected_models synced)",
                    account_id
                );
            }
        }

        // Check and handle accounts pending deletion (thoroughly clear cache)
        let pending_delete = crate::proxy::server::take_pending_delete_accounts();
        for account_id in pending_delete {
            self.remove_account(&account_id);
            tracing::info!(
                "[Proxy] Purged deleted account {} from all caches",
                account_id
            );
        }

        // Add 5-second timeout to prevent deadlocks
        let timeout_duration = std::time::Duration::from_secs(5);
        match tokio::time::timeout(
            timeout_duration,
            self.get_token_internal(quota_group, force_rotate, session_id, target_model),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(
                "Token acquisition timeout (5s) - system too busy or deadlock detected".to_string(),
            ),
        }
    }

    // Internal implementation: core logic for obtaining Token
    async fn get_token_internal(
        &self,
        quota_group: &str,
        force_rotate: bool,
        session_id: Option<&str>,
        target_model: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        let mut tokens_snapshot: Vec<ProxyToken> =
            self.tokens.iter().map(|e| e.value().clone()).collect();
        let mut total = tokens_snapshot.len();
        if total == 0 {
            return Err("Token pool is empty".to_string());
        }

        // ===== [OPTIMIZATION] Quota-First Sorting: Protect low quota accounts, balanced usage =====
        // Priority: Target model quota > Health score > Subscription tier > Reset time
        // -> High quota accounts are prioritized to avoid PRO/ULTRA running out first and losing the 5-hour refresh cycle
        // Use targeted model's quota instead of max (all models)
        const RESET_TIME_THRESHOLD_SECS: i64 = 600; // 10-minute threshold; differences smaller than this are considered the same

        let normalized_target =
            crate::proxy::common::model_mapping::normalize_to_standard_id(target_model)
                .unwrap_or_else(|| target_model.to_string());

        tokens_snapshot.sort_by(|a, b| {
            // Priority 1: target model quota (higher is better) -> protect low-quota accounts
            // [OPTIMIZATION] Use in-memory cache; avoid disk I/O reads
            let quota_a = a.model_quotas.get(&normalized_target).copied()
                .unwrap_or(a.remaining_quota.unwrap_or(0));
            let quota_b = b.model_quotas.get(&normalized_target).copied()
                .unwrap_or(b.remaining_quota.unwrap_or(0));

            let quota_cmp = quota_b.cmp(&quota_a);
            if quota_cmp != std::cmp::Ordering::Equal {
                return quota_cmp;
            }

            // Priority 2: Health score (higher is better)
            let health_cmp = b.health_score.partial_cmp(&a.health_score)
                .unwrap_or(std::cmp::Ordering::Equal);
            if health_cmp != std::cmp::Ordering::Equal {
                return health_cmp;
            }

            // Priority 3: Subscription tier (ULTRA > PRO > FREE) -> Prioritize higher tier accounts in case of tie
            let tier_priority = |tier: &Option<String>| {
                let t = tier.as_deref().unwrap_or("").to_lowercase();
                if t.contains("ultra") { 0 }
                else if t.contains("pro") { 1 }
                else if t.contains("free") { 2 }
                else { 3 }
            };
            let tier_cmp = tier_priority(&a.subscription_tier)
                .cmp(&tier_priority(&b.subscription_tier));
            if tier_cmp != std::cmp::Ordering::Equal {
                return tier_cmp;
            }

            // Priority 4: Reset time (earlier is better, but only if diff > 10 min)
            let reset_a = a.reset_time.unwrap_or(i64::MAX);
            let reset_b = b.reset_time.unwrap_or(i64::MAX);
            if (reset_a - reset_b).abs() >= RESET_TIME_THRESHOLD_SECS {
                reset_a.cmp(&reset_b)
            } else {
                std::cmp::Ordering::Equal
            }
        });

        // [DEBUG LOG] Print sorted account order (shows target model's quota)
        tracing::debug!(
            "🔄 [Token Rotation] target={} Accounts: {:?}",
            normalized_target,
            tokens_snapshot.iter().map(|t| format!(
                "{}(quota={}%, reset={:?}, health={:.2})",
                t.email,
                t.model_quotas.get(&normalized_target).copied().unwrap_or(0),
                t.reset_time.map(|ts| {
                    let now = chrono::Utc::now().timestamp();
                    let diff_secs = ts - now;
                    if diff_secs > 0 {
                        format!("{}m", diff_secs / 60)
                    } else {
                        "now".to_string()
                    }
                }),
                t.health_score
            )).collect::<Vec<_>>()
        );

        // 0. Read current scheduling configuration
        let scheduling = self.sticky_config.read().await.clone();
        use crate::proxy::sticky_config::SchedulingMode;

        // [NEW] Check if quota protection is enabled (if disabled, ignore protected_models check)
        let quota_protection_enabled = crate::modules::config::load_app_config()
            .map(|cfg| cfg.quota_protection.enabled)
            .unwrap_or(false);

        // ===== Fixed Account Mode: Prioritize using specific account =====
        let preferred_id = self.preferred_account_id.read().await.clone();
        if let Some(ref pref_id) = preferred_id {
            // Find preferred account
            if let Some(preferred_token) = tokens_snapshot
                .iter()
                .find(|t| &t.account_id == pref_id)
                .cloned()
            {
                // Check if account is available (not rate-limited, not quota-protected)
                match Self::get_account_state_on_disk(&preferred_token.account_path).await {
                    OnDiskAccountState::Disabled => {
                        tracing::warn!(
                            "🔒  Preferred account {} is disabled on disk, purging and falling back",
                            preferred_token.email
                        );
                        self.remove_account(&preferred_token.account_id);
                        tokens_snapshot.retain(|t| t.account_id != preferred_token.account_id);
                        total = tokens_snapshot.len();

                        {
                            let mut preferred = self.preferred_account_id.write().await;
                            if preferred.as_deref() == Some(pref_id.as_str()) {
                                *preferred = None;
                            }
                        }

                        if total == 0 {
                            return Err("Token pool is empty".to_string());
                        }
                    }
                    OnDiskAccountState::Unknown => {
                        tracing::warn!(
                            "🔒  Preferred account {} state on disk is unavailable, falling back",
                            preferred_token.email
                        );
                        // Don't purge on transient read/parse failures; just skip this token for this request.
                        tokens_snapshot.retain(|t| t.account_id != preferred_token.account_id);
                        total = tokens_snapshot.len();
                        if total == 0 {
                            return Err("Token pool is empty".to_string());
                        }
                    }
                    OnDiskAccountState::Enabled => {
                        let normalized_target =
                            crate::proxy::common::model_mapping::normalize_to_standard_id(
                                target_model,
                            )
                            .unwrap_or_else(|| target_model.to_string());

                let is_rate_limited = self
                    .is_rate_limited(&preferred_token.account_id, Some(&normalized_target))
                    .await;
                let is_quota_protected = quota_protection_enabled
                    && preferred_token
                        .protected_models
                        .contains(&normalized_target);

                if !is_rate_limited && !is_quota_protected {
                    tracing::info!(
                        "🔒  Using preferred account: {} (fixed mode)",
                        preferred_token.email
                    );

                    // Use preferred account directly, skip round-robin logic
                    let mut token = preferred_token.clone();

                    // Check if token has expired (refresh 5 minutes in advance)
                    let now = chrono::Utc::now().timestamp();
                    if now >= token.timestamp - 300 {
                        tracing::debug!("Token for account {} is about to expire, refreshing...", token.email);
                        match crate::modules::oauth::refresh_access_token(&token.refresh_token, Some(&token.account_id))
                            .await
                        {
                            Ok(token_response) => {
                                token.access_token = token_response.access_token.clone();
                                token.expires_in = token_response.expires_in;
                                token.timestamp = now + token_response.expires_in;

                                if let Some(mut entry) = self.tokens.get_mut(&token.account_id) {
                                    entry.access_token = token.access_token.clone();
                                    entry.expires_in = token.expires_in;
                                    entry.timestamp = token.timestamp;
                                }
                                let _ = self
                                    .save_refreshed_token(&token.account_id, &token_response)
                                    .await;
                            }
                            Err(e) => {
                                tracing::warn!("Preferred account token refresh failed: {}", e);
                                // Continue using old token, let subsequent logic handle failure
                            }
                        }
                    }

                    // Ensure project_id is present
                    let project_id = if let Some(pid) = &token.project_id {
                        pid.clone()
                    } else {
                        match crate::proxy::project_resolver::fetch_project_id(&token.access_token)
                            .await
                        {
                            Ok(pid) => {
                                if let Some(mut entry) = self.tokens.get_mut(&token.account_id) {
                                    entry.project_id = Some(pid.clone());
                                }
                                let _ = self.save_project_id(&token.account_id, &pid).await;
                                pid
                            }
                            Err(_) => "bamboo-precept-lgxtn".to_string(), // fallback
                        }
                    };

                    return Ok((token.access_token, project_id, token.email, token.account_id, 0));
                } else {
                    if is_rate_limited {
                        tracing::warn!("🔒  Preferred account {} is rate-limited, falling back to round-robin", preferred_token.email);
                    } else {
                        tracing::warn!("🔒  Preferred account {} is quota-protected for {}, falling back to round-robin", preferred_token.email, target_model);
                    }
                }
                    }
                }
            } else {
                tracing::warn!("🔒  Preferred account {} not found in pool, falling back to round-robin", pref_id);
            }
        }

        // Move lock operations outside the loop to avoid redundant locking
        // Pre-fetch a snapshot of last_used_account to avoid multiple locks in the loop
        let last_used_account_id = if quota_group != "image_gen" {
            let last_used = self.last_used_account.lock().await;
            last_used.clone()
        } else {
            None
        };

        let mut attempted: HashSet<String> = HashSet::new();
        let mut last_error: Option<String> = None;
        let mut need_update_last_used: Option<(String, std::time::Instant)> = None;

        for attempt in 0..total {
            let rotate = force_rotate || attempt > 0;

            // ===== [CORE] Sticky Session and Smart Scheduling Logic =====
            let mut target_token: Option<ProxyToken> = None;

            // Normalize target model name to standard ID for quota protection check
            let normalized_target = crate::proxy::common::model_mapping::normalize_to_standard_id(target_model)
                .unwrap_or_else(|| target_model.to_string());

            // Mode A: Sticky session processing (CacheFirst or Balance with session_id)
            if !rotate
                && session_id.is_some()
                && scheduling.mode != SchedulingMode::PerformanceFirst
            {
                let sid = session_id.unwrap();

                // 1. Check if session is already bound to an account
                if let Some(bound_id) = self.session_accounts.get(sid).map(|v| v.clone()) {
                    // Find the corresponding account via account_id first to get its email
                    // 2. Convert email -> account_id to check if the bound account is rate-limited
                    if let Some(bound_token) =
                        tokens_snapshot.iter().find(|t| t.account_id == bound_id)
                    {
                        let key = self
                            .email_to_account_id(&bound_token.email)
                            .unwrap_or_else(|| bound_token.account_id.clone());
                        //  Pass None for specific model wait time if not applicable
                        let reset_sec = self.rate_limit_tracker.get_remaining_wait(&key, None);
                        if reset_sec > 0 {
                            // Unbind and switch account immediately; do not block
                            // Reason: blocking can cause client socket timeouts under concurrency (UND_ERR_SOCKET)
                            tracing::debug!(
                                "Sticky Session: Bound account {} is rate-limited ({}s), unbinding and switching.",
                                bound_token.email, reset_sec
                            );
                            self.session_accounts.remove(sid);
                        } else if !attempted.contains(&bound_id)
                            && !(quota_protection_enabled
                                && bound_token.protected_models.contains(&normalized_target))
                        {
                            // 3. Account is available and not marked as attempt failed, prioritize reuse
                            tracing::debug!("Sticky Session: Successfully reusing bound account {} for session {}", bound_token.email, sid);
                            target_token = Some(bound_token.clone());
                        } else if quota_protection_enabled
                            && bound_token.protected_models.contains(&normalized_target)
                        {
                            tracing::debug!("Sticky Session: Bound account {} is quota-protected for model {} [{}], unbinding and switching.", bound_token.email, normalized_target, target_model);
                            self.session_accounts.remove(sid);
                        }
                    } else {
                        // Bound account no longer exists (possibly deleted); unbind it
                        tracing::debug!(
                            "Sticky Session: Bound account not found for session {}, unbinding",
                            sid
                        );
                        self.session_accounts.remove(sid);
                    }
                }
            }

            // Mode B: Atomic 60s global lock (default protection for cases without session_id)
            // Performance-first mode should skip 60s locking;
            if target_token.is_none()
                && !rotate
                && quota_group != "image_gen"
                && scheduling.mode != SchedulingMode::PerformanceFirst
            {
                // [OPTIMIZATION] Use pre-fetched snapshot, no more locking inside the loop
                if let Some((account_id, last_time)) = &last_used_account_id {
                    // 60s locking logic should check the `attempted` set to avoid retrying failed accounts
                    if last_time.elapsed().as_secs() < 60 && !attempted.contains(account_id) {
                        if let Some(found) =
                            tokens_snapshot.iter().find(|t| &t.account_id == account_id)
                        {
                            // Check rate limit status and quota protection to avoid reusing locked accounts
                            if !self
                                .is_rate_limited(&found.account_id, Some(&normalized_target))
                                .await
                                && !(quota_protection_enabled
                                    && found.protected_models.contains(&normalized_target))
                            {
                                tracing::debug!(
                                    "60s Window: Force reusing last account: {}",
                                    found.email
                                );
                                target_token = Some(found.clone());
                            } else {
                                if self
                                    .is_rate_limited(&found.account_id, Some(&normalized_target))
                                    .await
                                {
                                    tracing::debug!(
                                        "60s Window: Last account {} is rate-limited, skipping",
                                        found.email
                                    );
                                } else {
                                    tracing::debug!("60s Window: Last account {} is quota-protected for model {} [{}], skipping", found.email, normalized_target, target_model);
                                }
                            }
                        }
                    }
                }

                // If no lock, use P2C to select account (avoid hotspots)
                if target_token.is_none() {
                    // If no lock, use P2C to select account (avoid hotspots)
                    let mut non_limited: Vec<ProxyToken> = Vec::new();
                    for t in &tokens_snapshot {
                        if !self.is_rate_limited(&t.account_id, Some(&normalized_target)).await {
                            non_limited.push(t.clone());
                        }
                    }

                    if let Some(selected) = self.select_with_p2c(
                        &non_limited, &attempted, &normalized_target, quota_protection_enabled
                    ) {
                        target_token = Some(selected.clone());
                        need_update_last_used = Some((selected.account_id.clone(), std::time::Instant::now()));

                        // If first-time session assignment and stickiness required, establish binding here
                        if let Some(sid) = session_id {
                            if scheduling.mode != SchedulingMode::PerformanceFirst {
                                self.session_accounts
                                    .insert(sid.to_string(), selected.account_id.clone());
                                tracing::debug!(
                                    "Sticky Session: Bound new account {} to session {}",
                                    selected.email,
                                    sid
                                );
                            }
                        }
                    }
                }
            } else if target_token.is_none() {
                // Mode C: P2C Selection (Instead of pure round-robin)
                tracing::debug!(
                    "🔄 [Mode C] P2C selection from {} candidates",
                    total
                );

                // Filter out non-rate-limited accounts first
                let mut non_limited: Vec<ProxyToken> = Vec::new();
                for t in &tokens_snapshot {
                    if !self.is_rate_limited(&t.account_id, Some(&normalized_target)).await {
                        non_limited.push(t.clone());
                    }
                }

                if let Some(selected) = self.select_with_p2c(
                    &non_limited, &attempted, &normalized_target, quota_protection_enabled
                ) {
                    tracing::debug!("  {} - SELECTED via P2C", selected.email);
                    target_token = Some(selected.clone());

                    if rotate {
                        tracing::debug!("Force Rotation: Switched to account: {}", selected.email);
                    }
                }
            }

            let mut token = match target_token {
                Some(t) => t,
                None => {
                    // Optimistic Reset Strategy: Dual-layer protection mechanism
                    // Compute minimum wait time
                    let min_wait = tokens_snapshot
                        .iter()
                        .filter_map(|t| self.rate_limit_tracker.get_reset_seconds(&t.account_id))
                        .min();

                    // Layer 1: if shortest wait <= 2s, apply buffer delay
                    if let Some(wait_sec) = min_wait {
                        if wait_sec <= 2 {
                            let wait_ms = (wait_sec as f64 * 1000.0) as u64;
                            tracing::warn!(
                                "All accounts rate-limited but shortest wait is {}s. Applying {}ms buffer for state sync...",
                                wait_sec, wait_ms
                            );

                            // Buffer delay
                            tokio::time::sleep(tokio::time::Duration::from_millis(wait_ms)).await;

                            // Retry account selection
                            let retry_token = tokens_snapshot.iter()
                                .find(|t| !attempted.contains(&t.account_id) && !self.is_rate_limited_sync(&t.account_id, None));

                            if let Some(t) = retry_token {
                                tracing::info!(
                                    "✅ Buffer delay successful! Found available account: {}",
                                    t.email
                                );
                                t.clone()
                            } else {
                                // Layer 2: still unavailable after buffer, perform optimistic reset
                                tracing::warn!(
                                    "Buffer delay failed. Executing optimistic reset for all {} accounts...",
                                    tokens_snapshot.len()
                                );

                                // Clear all rate-limit records
                                self.rate_limit_tracker.clear_all();

                                // Retry selection again
                                let final_token = tokens_snapshot
                                    .iter()
                                    .find(|t| !attempted.contains(&t.account_id));

                                if let Some(t) = final_token {
                                    tracing::info!(
                                        "✅ Optimistic reset successful! Using account: {}",
                                        t.email
                                    );
                                    t.clone()
                                } else {
                                    return Err(
                                        "All accounts failed after optimistic reset.".to_string()
                                    );
                                }
                            }
                        } else {
                            return Err(format!("All accounts limited. Wait {}s.", wait_sec));
                        }
                    } else {
                        return Err("All accounts failed or unhealthy.".to_string());
                    }
                }
            };

            // Safety net: avoid selecting an account that has been disabled on disk but still
            // exists in the in-memory snapshot (e.g. stale cache + sticky session binding).
            match Self::get_account_state_on_disk(&token.account_path).await {
                OnDiskAccountState::Disabled => {
                    tracing::warn!(
                        "Selected account {} is disabled on disk, purging and retrying",
                        token.email
                    );
                    attempted.insert(token.account_id.clone());
                    self.remove_account(&token.account_id);
                    continue;
                }
                OnDiskAccountState::Unknown => {
                    tracing::warn!(
                        "Selected account {} state on disk is unavailable, skipping",
                        token.email
                    );
                    attempted.insert(token.account_id.clone());
                    continue;
                }
                OnDiskAccountState::Enabled => {}
            }

            // 3. Check if token expired (refresh 5 minutes in advance)
            let now = chrono::Utc::now().timestamp();
            if now >= token.timestamp - 300 {
                tracing::debug!("Token for account {} is about to expire, refreshing...", token.email);

                // Refresh token via OAuth
                match crate::modules::oauth::refresh_access_token(&token.refresh_token, Some(&token.account_id)).await {
                    Ok(token_response) => {
                        tracing::debug!("Token refresh succeeded!");

                        // Update local in-memory object for subsequent use
                        token.access_token = token_response.access_token.clone();
                        token.expires_in = token_response.expires_in;
                        token.timestamp = now + token_response.expires_in;

                        // Sync update to cross-thread shared DashMap
                        if let Some(mut entry) = self.tokens.get_mut(&token.account_id) {
                            entry.access_token = token.access_token.clone();
                            entry.expires_in = token.expires_in;
                            entry.timestamp = token.timestamp;
                        }

                        // Persist to disk to avoid repeated refresh loops after restart
                        if let Err(e) = self
                            .save_refreshed_token(&token.account_id, &token_response)
                            .await
                        {
                            tracing::debug!("Failed to persist refreshed token ({}): {}", token.email, e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Token refresh failed ({}): {}, trying next account", token.email, e);
                        if e.contains("\"invalid_grant\"") || e.contains("invalid_grant") {
                            tracing::error!(
                                "Disabling account due to invalid_grant ({}): refresh_token likely revoked/expired",
                                token.email
                            );
                            let _ = self
                                .disable_account(
                                    &token.account_id,
                                    &format!("invalid_grant: {}", e),
                                )
                                .await;
                            self.tokens.remove(&token.account_id);
                        }
                        // Avoid leaking account emails to API clients; details are still in logs.
                        last_error = Some(format!("Token refresh failed: {}", e));
                        attempted.insert(token.account_id.clone());

                        // [OPTIMIZATION] mark lock for clearing; avoid locking inside loop
                        if quota_group != "image_gen" {
                            if matches!(&last_used_account_id, Some((id, _)) if id == &token.account_id)
                            {
                                need_update_last_used =
                                    Some((String::new(), std::time::Instant::now()));
                                // Empty string means clear is required
                            }
                        }
                        continue;
                    }
                }
            }

            // 4. Ensure project_id is present
            let project_id = if let Some(pid) = &token.project_id {
                pid.clone()
            } else {
                tracing::debug!("Account {} is missing project_id, attempting to fetch...", token.email);
                match crate::proxy::project_resolver::fetch_project_id(&token.access_token).await {
                    Ok(pid) => {
                        if let Some(mut entry) = self.tokens.get_mut(&token.account_id) {
                            entry.project_id = Some(pid.clone());
                        }
                        let _ = self.save_project_id(&token.account_id, &pid).await;
                        pid
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch project_id for {}: {}", token.email, e);
                        last_error = Some(format!(
                            "Failed to fetch project_id for {}: {}",
                            token.email, e
                        ));
                        attempted.insert(token.account_id.clone());

                        // [OPTIMIZATION] mark lock for clearing; avoid locking inside loop
                        if quota_group != "image_gen" {
                            if matches!(&last_used_account_id, Some((id, _)) if id == &token.account_id)
                            {
                                need_update_last_used =
                                    Some((String::new(), std::time::Instant::now()));
                                // Empty string means clear is required
                            }
                        }
                        continue;
                    }
                }
            };

            // [OPTIMIZATION] Uniformly update last_used_account before successful return (if needed)
            if let Some((new_account_id, new_time)) = need_update_last_used {
                if quota_group != "image_gen" {
                    let mut last_used = self.last_used_account.lock().await;
                    if new_account_id.is_empty() {
                        // Empty string means clear lock is required
                        *last_used = None;
                    } else {
                        *last_used = Some((new_account_id, new_time));
                    }
                }
            }

            return Ok((token.access_token, project_id, token.email, token.account_id, 0));
        }

        Err(last_error.unwrap_or_else(|| "All accounts failed".to_string()))
    }

    async fn disable_account(&self, account_id: &str, reason: &str) -> Result<(), String> {
        let path = if let Some(entry) = self.tokens.get(account_id) {
            entry.account_path.clone()
        } else {
            self.data_dir
                .join("accounts")
                .join(format!("{}.json", account_id))
        };

        let mut content: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path).map_err(|e| format!("Failed to read file: {}", e))?,
        )
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;

        let now = chrono::Utc::now().timestamp();
        content["disabled"] = serde_json::Value::Bool(true);
        content["disabled_at"] = serde_json::Value::Number(now.into());
        content["disabled_reason"] = serde_json::Value::String(truncate_reason(reason, 800));

        std::fs::write(&path, serde_json::to_string_pretty(&content).unwrap())
            .map_err(|e| format!("Failed to write to file: {}", e))?;

        // Remove disabled account from memory to prevent it from being used by 60s lock logic
        self.tokens.remove(account_id);

        tracing::warn!("Account disabled: {} ({:?})", account_id, path);
        Ok(())
    }

    // Save project_id to account file
    async fn save_project_id(&self, account_id: &str, project_id: &str) -> Result<(), String> {
        let entry = self.tokens.get(account_id)
            .ok_or("Account does not exist")?;

        let path = &entry.account_path;

        let mut content: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?
        ).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        content["token"]["project_id"] = serde_json::Value::String(project_id.to_string());

        std::fs::write(path, serde_json::to_string_pretty(&content).unwrap())
            .map_err(|e| format!("Failed to write to file: {}", e))?;

        tracing::debug!("Saved project_id to account {}", account_id);
        Ok(())
    }

    // Save refreshed token to account file
    async fn save_refreshed_token(&self, account_id: &str, token_response: &crate::modules::oauth::TokenResponse) -> Result<(), String> {
        let entry = self.tokens.get(account_id)
            .ok_or("Account does not exist")?;

        let path = &entry.account_path;

        let mut content: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?
        ).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        let now = chrono::Utc::now().timestamp();

        content["token"]["access_token"] = serde_json::Value::String(token_response.access_token.clone());
        content["token"]["expires_in"] = serde_json::Value::Number(token_response.expires_in.into());
        content["token"]["expiry_timestamp"] = serde_json::Value::Number((now + token_response.expires_in).into());

        std::fs::write(path, serde_json::to_string_pretty(&content).unwrap())
            .map_err(|e| format!("Failed to write to file: {}", e))?;

        tracing::debug!("Saved refreshed token to account {}", account_id);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    // Get specific account Token via email (used for warmup and other scenarios requiring a specific account)
    // This method will automatically refresh expired tokens
    pub async fn get_token_by_email(
        &self,
        email: &str,
    ) -> Result<(String, String, String, String, u64), String> {
        // Find account info
        let token_info = {
            let mut found = None;
            for entry in self.tokens.iter() {
                let token = entry.value();
                if token.email == email {
                    found = Some((
                        token.account_id.clone(),
                        token.access_token.clone(),
                        token.refresh_token.clone(),
                        token.timestamp,
                        token.expires_in,
                        chrono::Utc::now().timestamp(),
                        token.project_id.clone(),
                    ));
                    break;
                }
            }
            found
        };

        let (
            account_id,
            current_access_token,
            refresh_token,
            timestamp,
            expires_in,
            now,
            project_id_opt,
        ) = match token_info {
            Some(info) => info,
            None => return Err(format!("Account not found: {}", email)),
        };

        let project_id = project_id_opt.unwrap_or_else(|| "bamboo-precept-lgxtn".to_string());

        // Check if expired (5 minutes early)
        if now < timestamp + expires_in - 300 {
            return Ok((current_access_token, project_id, email.to_string(), account_id, 0));
        }

        tracing::info!("[Warmup] Token for {} is expiring, refreshing...", email);

        // Call OAuth to refresh token
        match crate::modules::oauth::refresh_access_token(&refresh_token, Some(&account_id)).await {
            Ok(token_response) => {
                tracing::info!("[Warmup] Token refresh successful for {}", email);
                let new_now = chrono::Utc::now().timestamp();

                // Update cache
                if let Some(mut entry) = self.tokens.get_mut(&account_id) {
                    entry.access_token = token_response.access_token.clone();
                    entry.expires_in = token_response.expires_in;
                    entry.timestamp = new_now;
                }

                // Save to disk
                let _ = self
                    .save_refreshed_token(&account_id, &token_response)
                    .await;

                Ok((
                    token_response.access_token,
                    project_id,
                    email.to_string(),
                    account_id,
                    0,
                ))
            }
            Err(e) => Err(format!(
                "[Warmup] Token refresh failed for {}: {}",
                email, e
            )),
        }
    }

    // ===== Rate Limit Management Methods =====

    // Mark account as rate-limited (called externally, usually in a handler)
    // Parameter is email; internally automatically converts to account_id
    pub async fn mark_rate_limited(
        &self,
        email: &str,
        status: u16,
        retry_after_header: Option<&str>,
        error_body: &str,
    ) {
        // Check if circuit breaker is enabled (uses memory cache, extremely fast)
        let config = self.circuit_breaker_config.read().await.clone();
        if !config.enabled {
            return;
        }

        // [Alternative] Convert email -> account_id
        let key = self.email_to_account_id(email).unwrap_or_else(|| email.to_string());

        self.rate_limit_tracker.parse_from_error(
            &key,
            status,
            retry_after_header,
            error_body,
            None,
            &config.backoff_steps, // Pass configuration
        );
    }

    // Check if account is in rate limit (supports model-level)
    pub async fn is_rate_limited(&self, account_id: &str, model: Option<&str>) -> bool {
        // Check if circuit breaker is enabled
        let config = self.circuit_breaker_config.read().await;
        if !config.enabled {
            return false;
        }
        self.rate_limit_tracker.is_rate_limited(account_id, model)
    }

    // Check if account is in rate limit (synchronous version, for Iterator only)
    pub fn is_rate_limited_sync(&self, account_id: &str, model: Option<&str>) -> bool {
        // Synchronous version cannot read async RwLock, use blocking_read here
        let config = self.circuit_breaker_config.blocking_read();
        if !config.enabled {
            return false;
        }
        self.rate_limit_tracker.is_rate_limited(account_id, model)
    }

    // Get how many seconds until rate limit reset
    #[allow(dead_code)]
    pub fn get_rate_limit_reset_seconds(&self, account_id: &str) -> Option<u64> {
        self.rate_limit_tracker.get_reset_seconds(account_id)
    }

    // Clear expired rate limit records
    #[allow(dead_code)]
    pub fn clean_expired_rate_limits(&self) {
        self.rate_limit_tracker.cleanup_expired();
    }

    // [Alternative] Find corresponding account_id via email
    // Used to convert email passed from handlers to account_id used by tracker
    fn email_to_account_id(&self, email: &str) -> Option<String> {
        self.tokens
            .iter()
            .find(|entry| entry.value().email == email)
            .map(|entry| entry.value().account_id.clone())
    }

    // Clear rate limit records for a specific account
    pub fn clear_rate_limit(&self, account_id: &str) -> bool {
        self.rate_limit_tracker.clear(account_id)
    }

    // Clear all rate limit records
    pub fn clear_all_rate_limits(&self) {
        self.rate_limit_tracker.clear_all();
    }

    // Mark account request as successful, reset consecutive failure count
    //
    // Called after successful request completion; resets failure count for the account,
    // next failure starts from the shortest lockout time (smart rate limiting).
    pub fn mark_account_success(&self, account_id: &str) {
        self.rate_limit_tracker.mark_success(account_id);
    }

    // Check if there are available Google accounts
    //
    // For smart judgment in "fallback-only" mode: use external providers only when all Google accounts are unavailable.
    //
    // # Arguments
    // - `quota_group`: Quota group ("claude" or "gemini"), not currently used but reserved for future expansion
    // - `target_model`: Target model name (normalized), used for quota protection check
    //
    // # Returns
    // - `true`: At least one available account (not rate-limited and not quota-protected)
    // - `false`: All accounts unavailable (rate-limited or quota-protected)
    //
    // # Example
    // ```ignore
    // // Check if available accounts exist for claude-sonnet requests
    // let has_available = token_manager.has_available_account("claude", "claude-sonnet-4-20250514").await;
    // if !has_available {
    //     // Switch to external provider
    // }
    // ```
    pub async fn has_available_account(&self, _quota_group: &str, target_model: &str) -> bool {
        // Check if quota protection is enabled
        let quota_protection_enabled = crate::modules::config::load_app_config()
            .map(|cfg| cfg.quota_protection.enabled)
            .unwrap_or(false);

        // Traverse all accounts, check if any are available
        for entry in self.tokens.iter() {
            let token = entry.value();

            // 1. Check if rate-limited
            if self.is_rate_limited(&token.account_id, None).await {
                tracing::debug!(
                    "[Fallback Check] Account {} is rate-limited, skipping",
                    token.email
                );
                continue;
            }

            // 2. Check if quota-protected (if enabled)
            if quota_protection_enabled && token.protected_models.contains(target_model) {
                tracing::debug!(
                    "[Fallback Check] Account {} is quota-protected for model {}, skipping",
                    token.email,
                    target_model
                );
                continue;
            }

            // Found at least one available account
            tracing::debug!(
                "[Fallback Check] Found available account: {} for model {}",
                token.email,
                target_model
            );
            return true;
        }

        // All accounts are unavailable
        tracing::info!(
            "[Fallback Check] No available Google accounts for model {}, fallback should be triggered",
            target_model
        );
        false
    }

    // Get quota reset time from account file
    //
    // Return the most recent quota reset time string (ISO 8601 format) for the account
    //
    // # Arguments
    // - `account_id`: Account ID (used to locate account file)
    pub fn get_quota_reset_time(&self, account_id: &str) -> Option<String> {
        // Find account file directly via account_id (filename is {account_id}.json)
        let account_path = self.data_dir.join("accounts").join(format!("{}.json", account_id));

        let content = std::fs::read_to_string(&account_path).ok()?;
        let account: serde_json::Value = serde_json::from_str(&content).ok()?;

        // Get the earliest reset_time in quota.models (most conservative lockout strategy)
        account
            .get("quota")
            .and_then(|q| q.get("models"))
            .and_then(|m| m.as_array())
            .and_then(|models| {
                models.iter()
                    .filter_map(|m| m.get("reset_time").and_then(|r| r.as_str()))
                    .filter(|s| !s.is_empty())
                    .min()
                    .map(|s| s.to_string())
            })
    }

    // Precisely lock account using quota reset time
    //
    // When API returns 429 but no quotaResetDelay, try using the account's quota reset time
    //
    // # Arguments
    // - `account_id`: Account ID
    // - `reason`: Rate limit reason (QuotaExhausted/ServerError, etc.)
    // - `model`: Optional model name, for model-level rate limiting
    pub fn set_precise_lockout(&self, account_id: &str, reason: crate::proxy::rate_limit::RateLimitReason, model: Option<String>) -> bool {
        if let Some(reset_time_str) = self.get_quota_reset_time(account_id) {
            tracing::info!("Found quota reset time for account {}: {}", account_id, reset_time_str);
            self.rate_limit_tracker.set_lockout_until_iso(account_id, &reset_time_str, reason, model)
        } else {
            tracing::debug!("Quota reset time for account {} not found, will use default backoff strategy", account_id);
            false
        }
    }

    // Refresh quota in real-time and precisely lock account
    //
    // Call this method when 429 occurs:
    // 1. Call quota refresh API in real-time to get the latest reset_time
    // 2. Precisely lock account using the latest reset_time
    // 3. If retrieval fails, return false to let caller use fallback strategy
    //
    // # Arguments
    // - `model`: Optional model name, for model-level rate limiting
    pub async fn fetch_and_lock_with_realtime_quota(
        &self,
        email: &str,
        reason: crate::proxy::rate_limit::RateLimitReason,
        model: Option<String>,
    ) -> bool {
        // 1. Get access_token and account_id for the account from tokens
        // Also get account_id to ensure lockout key matches check key
        let (access_token, account_id) = {
            let mut found: Option<(String, String)> = None;
            for entry in self.tokens.iter() {
                if entry.value().email == email {
                    found = Some((
                        entry.value().access_token.clone(),
                        entry.value().account_id.clone(),
                    ));
                    break;
                }
            }
            found
        }.unzip();

        let (access_token, account_id) = match (access_token, account_id) {
            (Some(token), Some(id)) => (token, id),
            _ => {
                tracing::warn!("Failed to find access_token for account {}, unable to refresh quota in real-time", email);
                return false;
            }
        };

        // 2. Call quota refresh API
        tracing::info!("Account {} is refreshing quota in real-time...", email);
        match crate::modules::quota::fetch_quota(&access_token, email, Some(&account_id)).await {
            Ok((quota_data, _project_id)) => {
                // 3. Extract reset_time from latest quota
                let earliest_reset = quota_data
                    .models
                    .iter()
                    .filter_map(|m| {
                        if !m.reset_time.is_empty() {
                            Some(m.reset_time.as_str())
                        } else {
                            None
                        }
                    })
                    .min();

                if let Some(reset_time_str) = earliest_reset {
                    tracing::info!(
                        "Account {} real-time quota refresh successful, reset_time: {}",
                        email,
                        reset_time_str
                    );
                    // Use account_id as key, consistent with is_rate_limited check
                    self.rate_limit_tracker.set_lockout_until_iso(&account_id, reset_time_str, reason, model)
                } else {
                    tracing::warn!("Account {} quota refresh successful but no reset_time found", email);
                    false
                }
            }
            Err(e) => {
                tracing::warn!("Account {} real-time quota refresh failed: {:?}", email, e);
                false
            }
        }
    }

    // Mark account as rate-limited (async version, supports real-time quota refresh)
    //
    // Multi-level fallback strategy:
    // 1. Priority: API returns quotaResetDelay → use directly
    // 2. Sub-optimal: Real-time quota refresh → get latest reset_time
    // 3. Backup: Use locally cached quota → read account file
    // 4. Final fallback: Exponential backoff strategy → default lockout time
    //
    // # Arguments
    // - `email`: Account email, used to find account info
    // - `status`: HTTP status code (e.g., 429, 500, etc.)
    // - `retry_after_header`: Optional Retry-After response header
    // - `error_body`: Error response body, used to parse quotaResetDelay
    // - `model`: Optional model name, for model-level rate limiting
    pub async fn mark_rate_limited_async(
        &self,
        email: &str,
        status: u16,
        retry_after_header: Option<&str>,
        error_body: &str,
        model: Option<&str>, // [NEW] Added model parameter
    ) {
        // Check if circuit breaker is enabled
        let config = self.circuit_breaker_config.read().await.clone();
        if !config.enabled {
            return;
        }

        //  Convert email to account_id for consistent tracking
        let account_id = self.email_to_account_id(email).unwrap_or_else(|| email.to_string());

        // Check if API returned precise retry time
        let has_explicit_retry_time = retry_after_header.is_some() ||
            error_body.contains("quotaResetDelay");

        if has_explicit_retry_time {
            // API returned precise time (quotaResetDelay); use directly without real-time refresh
            if let Some(m) = model {
                tracing::debug!(
                    "429 response for model {} of account {} contains quotaResetDelay, using API provided time directly",
                    account_id,
                    m
                );
            } else {
                tracing::debug!(
                    "429 response for account {} contains quotaResetDelay, using API provided time directly",
                    account_id
                );
            }
            self.rate_limit_tracker.parse_from_error(
                &account_id,
                status,
                retry_after_header,
                error_body,
                model.map(|s| s.to_string()),
                &config.backoff_steps, // Pass configuration
            );
            return;
        }

        // Determine rate limit reason
        let reason = if error_body.to_lowercase().contains("model_capacity") {
            crate::proxy::rate_limit::RateLimitReason::ModelCapacityExhausted
        } else if error_body.to_lowercase().contains("exhausted")
            || error_body.to_lowercase().contains("quota")
        {
            crate::proxy::rate_limit::RateLimitReason::QuotaExhausted
        } else {
            crate::proxy::rate_limit::RateLimitReason::Unknown
        };

        // API did not return quotaResetDelay; need real-time quota refresh for precise lockout time
        if let Some(m) = model {
            tracing::info!(
                "Account {} response for model {} did not contain quotaResetDelay, attempting to refresh quota in real-time...",
                account_id,
                m
            );
        } else {
            tracing::info!(
                "Account {} 429 response did not contain quotaResetDelay, attempting to refresh quota in real-time...",
                account_id
            );
        }

        // Pass email instead of account_id as fetch_and_lock_with_realtime_quota expects email
        if self.fetch_and_lock_with_realtime_quota(email, reason, model.map(|s| s.to_string())).await {
            tracing::info!("Account {} has been locked with real-time quota precision", email);
            return;
        }

        // Real-time refresh failed; try using locally cached quota reset time
        if self.set_precise_lockout(&account_id, reason, model.map(|s| s.to_string())) {
            tracing::info!("Account {} has been locked with locally cached quota", account_id);
            return;
        }

        // Both failed; fall back to exponential backoff strategy
        tracing::warn!("Account {} unable to fetch quota reset time, using exponential backoff strategy", account_id);
        self.rate_limit_tracker.parse_from_error(
            &account_id,
            status,
            retry_after_header,
            error_body,
            model.map(|s| s.to_string()),
            &config.backoff_steps, // Pass configuration
        );
    }

    // ===== Scheduling Configuration Methods =====

    // Get current scheduling configuration
    pub async fn get_sticky_config(&self) -> StickySessionConfig {
        self.sticky_config.read().await.clone()
    }

    // Update scheduling configuration
    pub async fn update_sticky_config(&self, new_config: StickySessionConfig) {
        let mut config = self.sticky_config.write().await;
        *config = new_config;
        tracing::debug!("Scheduling configuration updated: {:?}", *config);
    }

    // Update circuit breaker configuration
    pub async fn update_circuit_breaker_config(&self, config: crate::models::CircuitBreakerConfig) {
        let mut lock = self.circuit_breaker_config.write().await;
        *lock = config;
        tracing::debug!("Circuit breaker configuration updated");
    }

    // Get circuit breaker configuration
    pub async fn get_circuit_breaker_config(&self) -> crate::models::CircuitBreakerConfig {
        self.circuit_breaker_config.read().await.clone()
    }

    // Clear sticky mapping for a specific session
    #[allow(dead_code)]
    pub fn clear_session_binding(&self, session_id: &str) {
        self.session_accounts.remove(session_id);
    }

    // Clear sticky mappings for all sessions
    pub fn clear_all_sessions(&self) {
        self.session_accounts.clear();
    }

    // ===== Fixed Account Mode Methods =====

    // Set preferred account ID (Fixed account mode)
    // Pass Some(account_id) to enable fixed account mode, None to restore round-robin mode
    pub async fn set_preferred_account(&self, account_id: Option<String>) {
        let mut preferred = self.preferred_account_id.write().await;
        if let Some(ref id) = account_id {
            tracing::info!("🔒  Fixed account mode enabled: {}", id);
        } else {
            tracing::info!("🔄  Round-robin mode enabled (no preferred account)");
        }
        *preferred = account_id;
    }

    // Get currently preferred account ID
    pub async fn get_preferred_account(&self) -> Option<String> {
        self.preferred_account_id.read().await.clone()
    }

    // Exchange Authorization Code for Refresh Token (Web OAuth)
    pub async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<String, String> {
        crate::modules::oauth::exchange_code(code, redirect_uri)
            .await
            .and_then(|t| {
                t.refresh_token
                    .ok_or_else(|| "No refresh token returned by Google".to_string())
            })
    }

    // Get OAuth URL (supports custom Redirect URI)
    pub fn get_oauth_url_with_redirect(&self, redirect_uri: &str, state: &str) -> String {
        crate::modules::oauth::get_auth_url(redirect_uri, state)
    }

    // Get user info (Email, etc.)
    pub async fn get_user_info(
        &self,
        refresh_token: &str,
    ) -> Result<crate::modules::oauth::UserInfo, String> {
        // Get Access Token first
        let token = crate::modules::oauth::refresh_access_token(refresh_token, None)
            .await
            .map_err(|e| format!("Failed to refresh Access Token: {}", e))?;

        crate::modules::oauth::get_user_info(&token.access_token, None).await
    }

    // Add new account (backend-only, no desktop app handle required).
    pub async fn add_account(&self, email: &str, refresh_token: &str) -> Result<(), String> {
        // 1. Get Access Token (validate refresh_token validity)
        let token_info = crate::modules::oauth::refresh_access_token(refresh_token, None)
            .await
            .map_err(|e| format!("Invalid refresh token: {}", e))?;

        // 2. Get Project ID
        let project_id = crate::proxy::project_resolver::fetch_project_id(&token_info.access_token)
            .await
            .unwrap_or_else(|_| "bamboo-precept-lgxtn".to_string()); // Fallback

        // 3. Delegate to modules::account::add_account (includes file write, index update, locks)
        let email_clone = email.to_string();
        let refresh_token_clone = refresh_token.to_string();

        tokio::task::spawn_blocking(move || {
            let token_data = crate::models::TokenData::new(
                token_info.access_token,
                refresh_token_clone,
                token_info.expires_in,
                Some(email_clone.clone()),
                Some(project_id),
                None, // session_id
            );

            crate::modules::account::upsert_account(email_clone, None, token_data)
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| format!("Failed to save account: {}", e))?;

        // 4. Reload (update memory)
        self.reload_all_accounts().await.map(|_| ())
    }

    // Record successful request, increase health score
    pub fn record_success(&self, account_id: &str) {
        self.health_scores
            .entry(account_id.to_string())
            .and_modify(|s| *s = (*s + 0.05).min(1.0))
            .or_insert(1.0);
        tracing::debug!("📈 Health score increased for account {}", account_id);
    }

    // Record failed request, decrease health score
    pub fn record_failure(&self, account_id: &str) {
        self.health_scores
            .entry(account_id.to_string())
            .and_modify(|s| *s = (*s - 0.2).max(0.0))
            .or_insert(0.8);
        tracing::warn!("📉 Health score decreased for account {}", account_id);
    }

    // Extract the most recent reset timestamp from account quota info
    //
    // Claude models (sonnet/opus) share the same refresh time; just take the claude series reset_time
    // Return Unix timestamp (seconds), for comparison during sorting
    fn extract_earliest_reset_time(&self, account: &serde_json::Value) -> Option<i64> {
        let models = account
            .get("quota")
            .and_then(|q| q.get("models"))
            .and_then(|m| m.as_array())?;

        let mut earliest_ts: Option<i64> = None;

        for model in models {
            // Prioritize taking claude series reset_time (shared by sonnet/opus)
            let model_name = model.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if !model_name.contains("claude") {
                continue;
            }

            if let Some(reset_time_str) = model.get("reset_time").and_then(|r| r.as_str()) {
                if reset_time_str.is_empty() {
                    continue;
                }
                // Parse ISO 8601 time string as timestamp
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(reset_time_str) {
                    let ts = dt.timestamp();
                    if earliest_ts.is_none() || ts < earliest_ts.unwrap() {
                        earliest_ts = Some(ts);
                    }
                }
            }
        }

        // if no claude model time, try taking any model's most recent time
        if earliest_ts.is_none() {
            for model in models {
                if let Some(reset_time_str) = model.get("reset_time").and_then(|r| r.as_str()) {
                    if reset_time_str.is_empty() {
                        continue;
                    }
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(reset_time_str) {
                        let ts = dt.timestamp();
                        if earliest_ts.is_none() || ts < earliest_ts.unwrap() {
                            earliest_ts = Some(ts);
                        }
                    }
                }
            }
        }

        earliest_ts
    }

    // Helper to find account ID by email
    pub fn get_account_id_by_email(&self, email: &str) -> Option<String> {
        for entry in self.tokens.iter() {
            if entry.value().email == email {
                return Some(entry.key().clone());
            }
        }
        None
    }

    // Set validation blocked status for an account (internal)
    pub async fn set_validation_block(&self, account_id: &str, block_until: i64, reason: &str) -> Result<(), String> {
        // 1. Update memory
        if let Some(mut token) = self.tokens.get_mut(account_id) {
             token.validation_blocked = true;
             token.validation_blocked_until = block_until;
        }

        // 2. Persist to disk
        let path = self.data_dir.join("accounts").join(format!("{}.json", account_id));
        if !path.exists() {
             return Err(format!("Account file not found: {:?}", path));
        }

        let content = std::fs::read_to_string(&path)
             .map_err(|e| format!("Failed to read account file: {}", e))?;

        let mut account: serde_json::Value = serde_json::from_str(&content)
             .map_err(|e| format!("Failed to parse account JSON: {}", e))?;

        account["validation_blocked"] = serde_json::Value::Bool(true);
        account["validation_blocked_until"] = serde_json::Value::Number(serde_json::Number::from(block_until));
        account["validation_blocked_reason"] = serde_json::Value::String(reason.to_string());

        // Clear sticky session if blocked
        self.session_accounts.retain(|_, v| *v != account_id);

        let json_str = serde_json::to_string_pretty(&account)
             .map_err(|e| format!("Failed to serialize account JSON: {}", e))?;

        std::fs::write(&path, json_str)
             .map_err(|e| format!("Failed to write account file: {}", e))?;

        tracing::info!(
             "🚫 Account {} validation blocked until {} (reason: {})",
             account_id,
             block_until,
             reason
        );

        Ok(())
    }

    // Public method to set validation block (called from handlers)
    pub async fn set_validation_block_public(&self, account_id: &str, block_until: i64, reason: &str) -> Result<(), String> {
        self.set_validation_block(account_id, block_until, reason).await
    }

    // Set is_forbidden status for an account (called when proxy encounters 403)
    pub async fn set_forbidden(&self, account_id: &str, reason: &str) -> Result<(), String> {
        // 1. Persist to disk - update quota.is_forbidden in account JSON
        let path = self.data_dir.join("accounts").join(format!("{}.json", account_id));
        if !path.exists() {
            return Err(format!("Account file not found: {:?}", path));
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read account file: {}", e))?;

        let mut account: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse account JSON: {}", e))?;

        // Update quota.is_forbidden
        if let Some(quota) = account.get_mut("quota") {
            quota["is_forbidden"] = serde_json::Value::Bool(true);
        } else {
            // Create quota object if not exists
            account["quota"] = serde_json::json!({
                "models": [],
                "last_updated": chrono::Utc::now().timestamp(),
                "is_forbidden": true
            });
        }

        // Clear sticky session if forbidden
        self.session_accounts.retain(|_, v| *v != account_id);

        let json_str = serde_json::to_string_pretty(&account)
            .map_err(|e| format!("Failed to serialize account JSON: {}", e))?;

        std::fs::write(&path, json_str)
            .map_err(|e| format!("Failed to write account file: {}", e))?;

        // Remove account from memory pool to avoid re-selection during retries
        self.remove_account(account_id);

        tracing::warn!(
            "🚫 Account {} marked as forbidden (403): {}",
            account_id,
            truncate_reason(reason, 100)
        );

        Ok(())
    }
}

// Truncate overly long reason strings
fn truncate_reason(reason: &str, max_len: usize) -> String {
    if reason.len() <= max_len {
        reason.to_string()
    } else {
        format!("{}...", &reason[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[tokio::test]
    async fn test_reload_account_purges_cache_when_account_becomes_proxy_disabled() {
        let tmp_root = std::env::temp_dir().join(format!(
            "antigravity-token-manager-test-{}",
            uuid::Uuid::new_v4()
        ));
        let accounts_dir = tmp_root.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let account_id = "acc1";
        let email = "a@test.com";
        let now = chrono::Utc::now().timestamp();
        let account_path = accounts_dir.join(format!("{}.json", account_id));

        let account_json = serde_json::json!({
            "id": account_id,
            "email": email,
            "token": {
                "access_token": "atk",
                "refresh_token": "rtk",
                "expires_in": 3600,
                "expiry_timestamp": now + 3600
            },
            "disabled": false,
            "proxy_disabled": false,
            "created_at": now,
            "last_used": now
        });
        std::fs::write(&account_path, serde_json::to_string_pretty(&account_json).unwrap()).unwrap();

        let manager = TokenManager::new(tmp_root.clone());
        manager.load_accounts().await.unwrap();
        assert!(manager.tokens.get(account_id).is_some());

        // Prime extra caches to ensure remove_account() is really called.
        manager
            .session_accounts
            .insert("sid1".to_string(), account_id.to_string());
        {
            let mut preferred = manager.preferred_account_id.write().await;
            *preferred = Some(account_id.to_string());
        }

        // Mark account as proxy-disabled on disk (manual disable).
        let mut disabled_json = account_json.clone();
        disabled_json["proxy_disabled"] = serde_json::Value::Bool(true);
        disabled_json["proxy_disabled_reason"] = serde_json::Value::String("manual".to_string());
        disabled_json["proxy_disabled_at"] = serde_json::Value::Number(now.into());
        std::fs::write(&account_path, serde_json::to_string_pretty(&disabled_json).unwrap()).unwrap();

        manager.reload_account(account_id).await.unwrap();

        assert!(manager.tokens.get(account_id).is_none());
        assert!(manager.session_accounts.get("sid1").is_none());
        assert!(manager.preferred_account_id.read().await.is_none());

        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    #[tokio::test]
    async fn test_fixed_account_mode_skips_preferred_when_disabled_on_disk_without_reload() {
        let tmp_root = std::env::temp_dir().join(format!(
            "antigravity-token-manager-test-fixed-mode-{}",
            uuid::Uuid::new_v4()
        ));
        let accounts_dir = tmp_root.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let now = chrono::Utc::now().timestamp();

        let write_account = |id: &str, email: &str, proxy_disabled: bool| {
            let account_path = accounts_dir.join(format!("{}.json", id));
            let json = serde_json::json!({
                "id": id,
                "email": email,
                "token": {
                    "access_token": format!("atk-{}", id),
                    "refresh_token": format!("rtk-{}", id),
                    "expires_in": 3600,
                    "expiry_timestamp": now + 3600,
                    "project_id": format!("pid-{}", id)
                },
                "disabled": false,
                "proxy_disabled": proxy_disabled,
                "proxy_disabled_reason": if proxy_disabled { "manual" } else { "" },
                "created_at": now,
                "last_used": now
            });
            std::fs::write(&account_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
        };

        // Two accounts in pool.
        write_account("acc1", "a@test.com", false);
        write_account("acc2", "b@test.com", false);

        let manager = TokenManager::new(tmp_root.clone());
        manager.load_accounts().await.unwrap();

        // Enable fixed account mode for acc1.
        manager.set_preferred_account(Some("acc1".to_string())).await;

        // Disable acc1 on disk WITHOUT reloading the in-memory pool (simulates stale cache).
        write_account("acc1", "a@test.com", true);

        let (_token, _project_id, email, account_id, _wait_ms) = manager
            .get_token("gemini", false, Some("sid1"), "gemini-1.5-flash")
            .await
            .unwrap();

        // Should fall back to another account instead of using the disabled preferred one.
        assert_eq!(account_id, "acc2");
        assert_eq!(email, "b@test.com");
        assert!(manager.tokens.get("acc1").is_none());
        assert!(manager.get_preferred_account().await.is_none());

        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    #[tokio::test]
    async fn test_sticky_session_skips_bound_account_when_disabled_on_disk_without_reload() {
        let tmp_root = std::env::temp_dir().join(format!(
            "antigravity-token-manager-test-sticky-disabled-{}",
            uuid::Uuid::new_v4()
        ));
        let accounts_dir = tmp_root.join("accounts");
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let now = chrono::Utc::now().timestamp();

        let write_account = |id: &str, email: &str, percentage: i64, proxy_disabled: bool| {
            let account_path = accounts_dir.join(format!("{}.json", id));
            let json = serde_json::json!({
                "id": id,
                "email": email,
                "token": {
                    "access_token": format!("atk-{}", id),
                    "refresh_token": format!("rtk-{}", id),
                    "expires_in": 3600,
                    "expiry_timestamp": now + 3600,
                    "project_id": format!("pid-{}", id)
                },
                "quota": {
                    "models": [
                        { "name": "gemini-1.5-flash", "percentage": percentage }
                    ]
                },
                "disabled": false,
                "proxy_disabled": proxy_disabled,
                "proxy_disabled_reason": if proxy_disabled { "manual" } else { "" },
                "created_at": now,
                "last_used": now
            });
            std::fs::write(&account_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
        };

        // Two accounts in pool. acc1 has higher quota -> should be selected and bound first.
        write_account("acc1", "a@test.com", 90, false);
        write_account("acc2", "b@test.com", 10, false);

        let manager = TokenManager::new(tmp_root.clone());
        manager.load_accounts().await.unwrap();

        // Prime: first request should bind the session to acc1.
        let (_token, _project_id, _email, account_id, _wait_ms) = manager
            .get_token("gemini", false, Some("sid1"), "gemini-1.5-flash")
            .await
            .unwrap();
        assert_eq!(account_id, "acc1");
        assert_eq!(
            manager.session_accounts.get("sid1").map(|v| v.clone()),
            Some("acc1".to_string())
        );

        // Disable acc1 on disk WITHOUT reloading the in-memory pool (simulates stale cache).
        write_account("acc1", "a@test.com", 90, true);

        let (_token, _project_id, email, account_id, _wait_ms) = manager
            .get_token("gemini", false, Some("sid1"), "gemini-1.5-flash")
            .await
            .unwrap();

        // Should fall back to another account instead of reusing the disabled bound one.
        assert_eq!(account_id, "acc2");
        assert_eq!(email, "b@test.com");
        assert!(manager.tokens.get("acc1").is_none());
        assert_ne!(
            manager.session_accounts.get("sid1").map(|v| v.clone()),
            Some("acc1".to_string())
        );

        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    // Create ProxyToken for testing
    fn create_test_token(
        email: &str,
        tier: Option<&str>,
        health_score: f32,
        reset_time: Option<i64>,
        remaining_quota: Option<i32>,
    ) -> ProxyToken {
        ProxyToken {
            account_id: email.to_string(),
            access_token: "test_token".to_string(),
            refresh_token: "test_refresh".to_string(),
            expires_in: 3600,
            timestamp: chrono::Utc::now().timestamp() + 3600,
            email: email.to_string(),
            account_path: PathBuf::from("/tmp/test"),
            project_id: None,
            subscription_tier: tier.map(|s| s.to_string()),
            remaining_quota,
            protected_models: HashSet::new(),
            health_score,
            reset_time,
            validation_blocked: false,
            validation_blocked_until: 0,
            model_quotas: HashMap::new(),
        }
    }

    // Test sorting comparison function (consistent with logic in get_token_internal)
    fn compare_tokens(a: &ProxyToken, b: &ProxyToken) -> Ordering {
        const RESET_TIME_THRESHOLD_SECS: i64 = 600; // 10-minute threshold

        let tier_priority = |tier: &Option<String>| {
            let t = tier.as_deref().unwrap_or("").to_lowercase();
            if t.contains("ultra") { 0 }
            else if t.contains("pro") { 1 }
            else if t.contains("free") { 2 }
            else { 3 }
        };

        // First: compare by subscription tier
        let tier_cmp = tier_priority(&a.subscription_tier).cmp(&tier_priority(&b.subscription_tier));
        if tier_cmp != Ordering::Equal {
            return tier_cmp;
        }

        // Second: compare by health score (higher is better)
        let health_cmp = b.health_score.partial_cmp(&a.health_score).unwrap_or(Ordering::Equal);
        if health_cmp != Ordering::Equal {
            return health_cmp;
        }

        // Third: compare by reset time (earlier/closer is better)
        let reset_a = a.reset_time.unwrap_or(i64::MAX);
        let reset_b = b.reset_time.unwrap_or(i64::MAX);
        let reset_diff = (reset_a - reset_b).abs();

        if reset_diff >= RESET_TIME_THRESHOLD_SECS {
            let reset_cmp = reset_a.cmp(&reset_b);
            if reset_cmp != Ordering::Equal {
                return reset_cmp;
            }
        }

        // Fourth: compare by remaining quota percentage (higher is better)
        let quota_a = a.remaining_quota.unwrap_or(0);
        let quota_b = b.remaining_quota.unwrap_or(0);
        quota_b.cmp(&quota_a)
    }

    #[test]
    fn test_sorting_tier_priority() {
        // ULTRA > PRO > FREE
        let ultra = create_test_token("ultra@test.com", Some("ULTRA"), 1.0, None, Some(50));
        let pro = create_test_token("pro@test.com", Some("PRO"), 1.0, None, Some(50));
        let free = create_test_token("free@test.com", Some("FREE"), 1.0, None, Some(50));

        assert_eq!(compare_tokens(&ultra, &pro), Ordering::Less);
        assert_eq!(compare_tokens(&pro, &free), Ordering::Less);
        assert_eq!(compare_tokens(&ultra, &free), Ordering::Less);
        assert_eq!(compare_tokens(&free, &ultra), Ordering::Greater);
    }

    #[test]
    fn test_sorting_health_score_priority() {
        // For the same tier, higher health score is prioritized
        let high_health = create_test_token("high@test.com", Some("PRO"), 1.0, None, Some(50));
        let low_health = create_test_token("low@test.com", Some("PRO"), 0.5, None, Some(50));

        assert_eq!(compare_tokens(&high_health, &low_health), Ordering::Less);
        assert_eq!(compare_tokens(&low_health, &high_health), Ordering::Greater);
    }

    #[test]
    fn test_sorting_reset_time_priority() {
        let now = chrono::Utc::now().timestamp();

        // Closer reset time (30 minutes later) is prioritized over further one (5 hours later)
        let soon_reset = create_test_token("soon@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(50));  // 30 minutes later
        let late_reset = create_test_token("late@test.com", Some("PRO"), 1.0, Some(now + 18000), Some(50)); // 5 hours later

        assert_eq!(compare_tokens(&soon_reset, &late_reset), Ordering::Less);
        assert_eq!(compare_tokens(&late_reset, &soon_reset), Ordering::Greater);
    }

    #[test]
    fn test_sorting_reset_time_threshold() {
        let now = chrono::Utc::now().timestamp();

        // Differences less than 10 minutes (600 seconds) are considered the same priority; sort by quota
        let reset_a = create_test_token("a@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(80));  // 30 minutes later, 80% quota
        let reset_b = create_test_token("b@test.com", Some("PRO"), 1.0, Some(now + 2100), Some(50));  // 35 minutes later, 50% quota

        // Difference of 5 mins < 10 mins threshold, considered same, sort by quota (80% > 50%)
        assert_eq!(compare_tokens(&reset_a, &reset_b), Ordering::Less);
    }

    #[test]
    fn test_sorting_reset_time_beyond_threshold() {
        let now = chrono::Utc::now().timestamp();

        // Difference exceeds 10 minutes, sort by reset time (ignoring quota)
        let soon_low_quota = create_test_token("soon@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(20));   // 30 minutes later, 20%
        let late_high_quota = create_test_token("late@test.com", Some("PRO"), 1.0, Some(now + 18000), Some(90)); // 5 hours later, 90%

        // Difference of 4.5 hours > 10 minutes, reset time prioritized, 30 minutes < 5 hours
        assert_eq!(compare_tokens(&soon_low_quota, &late_high_quota), Ordering::Less);
    }

    #[test]
    fn test_sorting_quota_fallback() {
        // When other conditions are identical, higher quota is prioritized
        let high_quota = create_test_token("high@test.com", Some("PRO"), 1.0, None, Some(80));
        let low_quota = create_test_token("low@test.com", Some("PRO"), 1.0, None, Some(20));

        assert_eq!(compare_tokens(&high_quota, &low_quota), Ordering::Less);
        assert_eq!(compare_tokens(&low_quota, &high_quota), Ordering::Greater);
    }

    #[test]
    fn test_sorting_missing_reset_time() {
        let now = chrono::Utc::now().timestamp();

        // Accounts without reset_time should be placed after those with reset_time
        let with_reset = create_test_token("with@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(50));
        let without_reset = create_test_token("without@test.com", Some("PRO"), 1.0, None, Some(50));

        assert_eq!(compare_tokens(&with_reset, &without_reset), Ordering::Less);
    }

    #[test]
    fn test_full_sorting_integration() {
        let now = chrono::Utc::now().timestamp();

        let mut tokens = vec![
            create_test_token("free_high@test.com", Some("FREE"), 1.0, Some(now + 1800), Some(90)),
            create_test_token("pro_low_health@test.com", Some("PRO"), 0.5, Some(now + 1800), Some(90)),
            create_test_token("pro_soon@test.com", Some("PRO"), 1.0, Some(now + 1800), Some(50)),   // 30 minutes later
            create_test_token("pro_late@test.com", Some("PRO"), 1.0, Some(now + 18000), Some(90)),  // 5 hours later
            create_test_token("ultra@test.com", Some("ULTRA"), 1.0, Some(now + 36000), Some(10)),
        ];

        tokens.sort_by(compare_tokens);

        // Expected order:
        // 1. ULTRA (highest tier, even with furthest reset time)
        // 2. PRO + high health score + reset in 30 minutes
        // 3. PRO + high health score + reset in 5 hours
        // 4. PRO + low health score
        // 5. FREE (lowest tier, even with highest quota)
        assert_eq!(tokens[0].email, "ultra@test.com");
        assert_eq!(tokens[1].email, "pro_soon@test.com");
        assert_eq!(tokens[2].email, "pro_late@test.com");
        assert_eq!(tokens[3].email, "pro_low_health@test.com");
        assert_eq!(tokens[4].email, "free_high@test.com");
    }

    #[test]
    fn test_realistic_scenario() {
        // Simulate scenario described by the user:
        // account a resets in 4h55m
        // account b resets in 31m
        // account b (31 mins later) should be prioritized
        let now = chrono::Utc::now().timestamp();

        let account_a = create_test_token("a@test.com", Some("PRO"), 1.0, Some(now + 295 * 60), Some(80)); // 4h55m
        let account_b = create_test_token("b@test.com", Some("PRO"), 1.0, Some(now + 31 * 60), Some(30));  // 31m

        // b should be ahead of a (reset time is closer)
        assert_eq!(compare_tokens(&account_b, &account_a), Ordering::Less);

        let mut tokens = vec![account_a.clone(), account_b.clone()];
        tokens.sort_by(compare_tokens);

        assert_eq!(tokens[0].email, "b@test.com");
        assert_eq!(tokens[1].email, "a@test.com");
    }

    #[test]
    fn test_extract_earliest_reset_time() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        // Test extraction of reset_time containing Claude models
        let account_with_claude = serde_json::json!({
            "quota": {
                "models": [
                    {"name": "gemini-flash", "reset_time": "2025-01-31T10:00:00Z"},
                    {"name": "claude-sonnet", "reset_time": "2025-01-31T08:00:00Z"},
                    {"name": "claude-opus", "reset_time": "2025-01-31T08:00:00Z"}
                ]
            }
        });

        let result = manager.extract_earliest_reset_time(&account_with_claude);
        assert!(result.is_some());
        // Should return Claude's time (08:00) instead of Gemini's (10:00)
        let expected_ts = chrono::DateTime::parse_from_rfc3339("2025-01-31T08:00:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(result.unwrap(), expected_ts);
    }

    #[test]
    fn test_extract_reset_time_no_claude() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        // When no Claude model is present, the nearest time from any model should be taken
        let account_no_claude = serde_json::json!({
            "quota": {
                "models": [
                    {"name": "gemini-flash", "reset_time": "2025-01-31T10:00:00Z"},
                    {"name": "gemini-pro", "reset_time": "2025-01-31T08:00:00Z"}
                ]
            }
        });

        let result = manager.extract_earliest_reset_time(&account_no_claude);
        assert!(result.is_some());
        let expected_ts = chrono::DateTime::parse_from_rfc3339("2025-01-31T08:00:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(result.unwrap(), expected_ts);
    }

    #[test]
    fn test_extract_reset_time_missing_quota() {
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        // Should return None when quota field is missing
        let account_no_quota = serde_json::json!({
            "email": "test@test.com"
        });

        assert!(manager.extract_earliest_reset_time(&account_no_quota).is_none());
    }

    // ===== P2C Algorithm Test =====

    // Create test Token with protected_models
    fn create_test_token_with_protected(
        email: &str,
        remaining_quota: Option<i32>,
        protected_models: HashSet<String>,
    ) -> ProxyToken {
        ProxyToken {
            account_id: email.to_string(),
            access_token: "test_token".to_string(),
            refresh_token: "test_refresh".to_string(),
            expires_in: 3600,
            timestamp: chrono::Utc::now().timestamp() + 3600,
            email: email.to_string(),
            account_path: PathBuf::from("/tmp/test"),
            project_id: None,
            subscription_tier: Some("PRO".to_string()),
            remaining_quota,
            protected_models,
            health_score: 1.0,
            reset_time: None,
            validation_blocked: false,
            validation_blocked_until: 0,
            model_quotas: HashMap::new(),
        }
    }

    #[test]
    fn test_p2c_selects_higher_quota() {
        // P2C should select account with higher quota
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let low_quota = create_test_token("low@test.com", Some("PRO"), 1.0, None, Some(20));
        let high_quota = create_test_token("high@test.com", Some("PRO"), 1.0, None, Some(80));

        let candidates = vec![low_quota, high_quota];
        let attempted: HashSet<String> = HashSet::new();

        // Run multiple times to ensure high quota account is selected
        for _ in 0..10 {
            let result = manager.select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
            assert!(result.is_some());
            // P2C selects the one with higher quota from two candidates
            // Since there are only two candidates, high_quota should always be selected
            assert_eq!(result.unwrap().email, "high@test.com");
        }
    }

    #[test]
    fn test_p2c_skips_attempted() {
        // P2C should skip accounts already attempted
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let token_a = create_test_token("a@test.com", Some("PRO"), 1.0, None, Some(80));
        let token_b = create_test_token("b@test.com", Some("PRO"), 1.0, None, Some(50));

        let candidates = vec![token_a, token_b];
        let mut attempted: HashSet<String> = HashSet::new();
        attempted.insert("a@test.com".to_string());

        let result = manager.select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
        assert!(result.is_some());
        assert_eq!(result.unwrap().email, "b@test.com");
    }

    #[test]
    fn test_p2c_skips_protected_models() {
        // P2C should skip accounts protected for target model (quota_protection_enabled = true)
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let mut protected = HashSet::new();
        protected.insert("claude-sonnet".to_string());

        let protected_account = create_test_token_with_protected("protected@test.com", Some(90), protected);
        let normal_account = create_test_token_with_protected("normal@test.com", Some(50), HashSet::new());

        let candidates = vec![protected_account, normal_account];
        let attempted: HashSet<String> = HashSet::new();

        let result = manager.select_with_p2c(&candidates, &attempted, "claude-sonnet", true);
        assert!(result.is_some());
        assert_eq!(result.unwrap().email, "normal@test.com");
    }

    #[test]
    fn test_p2c_single_candidate() {
        // Directly return when there is a single candidate
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let token = create_test_token("single@test.com", Some("PRO"), 1.0, None, Some(50));
        let candidates = vec![token];
        let attempted: HashSet<String> = HashSet::new();

        let result = manager.select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
        assert!(result.is_some());
        assert_eq!(result.unwrap().email, "single@test.com");
    }

    #[test]
    fn test_p2c_empty_candidates() {
        // Return None for empty candidates
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let candidates: Vec<ProxyToken> = vec![];
        let attempted: HashSet<String> = HashSet::new();

        let result = manager.select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
        assert!(result.is_none());
    }

    #[test]
    fn test_p2c_all_attempted() {
        // Return None when all accounts have been attempted
        let manager = TokenManager::new(PathBuf::from("/tmp/test"));

        let token_a = create_test_token("a@test.com", Some("PRO"), 1.0, None, Some(80));
        let token_b = create_test_token("b@test.com", Some("PRO"), 1.0, None, Some(50));

        let candidates = vec![token_a, token_b];
        let mut attempted: HashSet<String> = HashSet::new();
        attempted.insert("a@test.com".to_string());
        attempted.insert("b@test.com".to_string());

        let result = manager.select_with_p2c(&candidates, &attempted, "claude-sonnet", false);
        assert!(result.is_none());
    }
}
