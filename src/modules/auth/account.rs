use serde::Serialize;
use serde_json;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

use crate::models::{
    Account, AccountIndex, AccountSummary, DeviceProfile, DeviceProfileVersion, QuotaData,
    TokenData,
};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::time::{Duration, Instant};
static ACCOUNT_INDEX_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
#[derive(Default)]
struct IndexLoadLogThrottle {
    last_logged_at: Option<Instant>,
    last_count: Option<usize>,
}
static INDEX_LOAD_LOG_THROTTLE: Lazy<Mutex<IndexLoadLogThrottle>> =
    Lazy::new(|| Mutex::new(IndexLoadLogThrottle::default()));

#[derive(Default)]
struct ListAccountsLogThrottle {
    last_logged_at: Option<Instant>,
}
static LIST_ACCOUNTS_LOG_THROTTLE: Lazy<Mutex<ListAccountsLogThrottle>> =
    Lazy::new(|| Mutex::new(ListAccountsLogThrottle::default()));

fn should_log_loaded_index(count: usize) -> bool {
    let Ok(mut state) = INDEX_LOAD_LOG_THROTTLE.lock() else {
        return true;
    };

    let now = Instant::now();
    let elapsed_ok = state
        .last_logged_at
        .map(|t| t.elapsed() >= Duration::from_secs(30))
        .unwrap_or(true);
    let count_changed = state.last_count != Some(count);

    if elapsed_ok || count_changed {
        state.last_logged_at = Some(now);
        state.last_count = Some(count);
        true
    } else {
        false
    }
}

fn should_log_listing_accounts() -> bool {
    let Ok(mut state) = LIST_ACCOUNTS_LOG_THROTTLE.lock() else {
        return true;
    };
    let now = Instant::now();
    let elapsed_ok = state
        .last_logged_at
        .map(|t| t.elapsed() >= Duration::from_secs(30))
        .unwrap_or(true);
    if elapsed_ok {
        state.last_logged_at = Some(now);
        true
    } else {
        false
    }
}
const DATA_DIR: &str = ".gephyr";
const ACCOUNTS_INDEX: &str = "accounts.json";
const ACCOUNTS_DIR: &str = "accounts";
pub fn get_data_dir() -> Result<PathBuf, String> {
    fn ensure_dir(path: &PathBuf) -> Result<(), String> {
        if !path.exists() {
            fs::create_dir_all(path).map_err(|e| format!("failed_to_create_data_dir: {}", e))?;
        }
        Ok(())
    }
    if let Ok(env_path) = std::env::var("DATA_DIR") {
        if !env_path.trim().is_empty() {
            let data_dir = PathBuf::from(env_path);
            ensure_dir(&data_dir)?;
            return Ok(data_dir);
        }
    }
    if cfg!(test) {
        let data_dir = std::env::temp_dir().join(format!(".gephyr-test-{}", std::process::id()));
        ensure_dir(&data_dir)?;
        return Ok(data_dir);
    }

    if let Some(home) = dirs::home_dir() {
        let data_dir = home.join(DATA_DIR);
        if ensure_dir(&data_dir).is_ok() {
            return Ok(data_dir);
        }
    }
    let fallback_dir = std::env::temp_dir().join(DATA_DIR);
    ensure_dir(&fallback_dir)?;
    Ok(fallback_dir)
}
pub fn get_accounts_dir() -> Result<PathBuf, String> {
    let data_dir = get_data_dir()?;
    let accounts_dir = data_dir.join(ACCOUNTS_DIR);

    if !accounts_dir.exists() {
        fs::create_dir_all(&accounts_dir)
            .map_err(|e| format!("failed_to_create_accounts_dir: {}", e))?;
    }

    Ok(accounts_dir)
}
pub fn load_account_index() -> Result<AccountIndex, String> {
    let data_dir = get_data_dir()?;
    let index_path = data_dir.join(ACCOUNTS_INDEX);

    if !index_path.exists() {
        crate::modules::system::logger::log_warn("Account index file not found");
        return Ok(AccountIndex::new());
    }

    let content = fs::read_to_string(&index_path)
        .map_err(|e| format!("failed_to_read_account_index: {}", e))?;
    if content.trim().is_empty() {
        crate::modules::system::logger::log_warn("Account index is empty, initializing new index");
        return Ok(AccountIndex::new());
    }

    let index: AccountIndex = serde_json::from_str(&content)
        .map_err(|e| format!("failed_to_parse_account_index: {}", e))?;

    if should_log_loaded_index(index.accounts.len()) {
        crate::modules::system::logger::log_info(&format!(
            "Successfully loaded index with {} accounts",
            index.accounts.len()
        ));
    }
    Ok(index)
}
pub fn save_account_index(index: &AccountIndex) -> Result<(), String> {
    let data_dir = get_data_dir()?;
    let index_path = data_dir.join(ACCOUNTS_INDEX);
    let temp_path = data_dir.join(format!("{}.tmp", ACCOUNTS_INDEX));

    let content = serde_json::to_string_pretty(index)
        .map_err(|e| format!("failed_to_serialize_account_index: {}", e))?;
    fs::write(&temp_path, content)
        .map_err(|e| format!("failed_to_write_temp_index_file: {}", e))?;
    fs::rename(temp_path, index_path).map_err(|e| format!("failed_to_replace_index_file: {}", e))
}
pub fn load_account(account_id: &str) -> Result<Account, String> {
    let accounts_dir = get_accounts_dir()?;
    let account_path = accounts_dir.join(format!("{}.json", account_id));

    if !account_path.exists() {
        return Err(format!("Account not found: {}", account_id));
    }

    let content = fs::read_to_string(&account_path)
        .map_err(|e| format!("failed_to_read_account_data: {}", e))?;

    serde_json::from_str(&content).map_err(|e| format!("failed_to_parse_account_data: {}", e))
}
pub fn save_account(account: &Account) -> Result<(), String> {
    let accounts_dir = get_accounts_dir()?;
    let account_path = accounts_dir.join(format!("{}.json", account.id));

    let content = serde_json::to_string_pretty(account)
        .map_err(|e| format!("failed_to_serialize_account_data: {}", e))?;

    fs::write(&account_path, content).map_err(|e| format!("failed_to_save_account_data: {}", e))
}

pub fn startup_preflight_verify_persisted_tokens() -> Result<(), String> {
    let data_dir = get_data_dir()?;
    let accounts_dir = data_dir.join(ACCOUNTS_DIR);
    if !accounts_dir.exists() {
        return Ok(());
    }

    let entries = std::fs::read_dir(&accounts_dir)
        .map_err(|e| format!("failed_to_read_accounts_dir: {}", e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed_to_read_accounts_dir_entry: {}", e))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let content =
            std::fs::read_to_string(&path).map_err(|e| format!("read_failed {:?}: {}", path, e))?;
        let value: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("parse_failed {:?}: {}", path, e))?;

        let email = value
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let account_id = value
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");

        let access_token = value
            .get("token")
            .and_then(|t| t.get("access_token"))
            .and_then(|v| v.as_str());
        let refresh_token = value
            .get("token")
            .and_then(|t| t.get("refresh_token"))
            .and_then(|v| v.as_str());

        if let Some(raw) = access_token {
            if let Err(e) = crate::utils::crypto::preflight_verify_decryptable_secret(raw) {
                return Err(format!(
                    "account={} email={} access_token_decrypt_failed: {}",
                    account_id, email, e
                ));
            }
        }
        if let Some(raw) = refresh_token {
            if let Err(e) = crate::utils::crypto::preflight_verify_decryptable_secret(raw) {
                return Err(format!(
                    "account={} email={} refresh_token_decrypt_failed: {}",
                    account_id, email, e
                ));
            }
        }
    }

    Ok(())
}

pub async fn logout_account(account_id: &str, revoke_remote: bool) -> Result<(), String> {
    // Load the account first. We intentionally do not hold ACCOUNT_INDEX_LOCK across the network
    // request to Google's revoke endpoint.
    let mut account = load_account(account_id)?;

    // If there's nothing to revoke, treat as idempotent local logout.
    let refresh_token_raw = account.token.refresh_token.clone();
    let refresh_token_is_empty = refresh_token_raw.trim().is_empty();

    if revoke_remote && !refresh_token_is_empty {
        // Ensure encryption prerequisites are satisfied (required when tokens are persisted as v2:*).
        crate::utils::crypto::validate_encryption_key_prerequisites()?;
        let refresh_token = crate::utils::crypto::decrypt_secret_or_plaintext(&refresh_token_raw)?;
        crate::modules::auth::oauth::revoke_refresh_token(&refresh_token, Some(account_id)).await?;
    }

    // Local wipe + disable.
    let now = chrono::Utc::now().timestamp();
    account.disabled = true;
    account.disabled_at = Some(now);
    account.disabled_reason = Some("logged_out".to_string());

    account.token.access_token = "".to_string();
    account.token.refresh_token = "".to_string();
    account.token.expires_in = 0;
    account.token.expiry_timestamp = 0;
    account.token.project_id = None;
    account.token.session_id = None;

    save_account(&account)?;

    // Keep account index summary consistent.
    let mut index = load_account_index()?;
    if let Some(summary) = index.accounts.iter_mut().find(|a| a.id == account_id) {
        summary.disabled = true;
    }
    if index.current_account_id.as_deref() == Some(account_id) {
        index.current_account_id = index
            .accounts
            .iter()
            .find(|a| a.id != account_id && !a.disabled && !a.proxy_disabled)
            .map(|a| a.id.clone());
    }
    save_account_index(&index)?;

    crate::proxy::server::trigger_account_reload(account_id);
    Ok(())
}
pub fn list_accounts() -> Result<Vec<Account>, String> {
    if should_log_listing_accounts() {
        crate::modules::system::logger::log_info("Listing accounts...");
    }
    let index = load_account_index()?;
    let mut accounts = Vec::new();

    for summary in &index.accounts {
        match load_account(&summary.id) {
            Ok(account) => accounts.push(account),
            Err(e) => {
                crate::modules::system::logger::log_error(&format!(
                    "Failed to load account {}: {}",
                    summary.id, e
                ));
            }
        }
    }

    Ok(accounts)
}
pub fn add_account(
    email: String,
    name: Option<String>,
    token: TokenData,
    google_sub: Option<String>,
) -> Result<Account, String> {
    let _lock = ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|e| format!("failed_to_acquire_lock: {}", e))?;
    let mut index = load_account_index()?;
    if let Some(sub) = google_sub.as_ref() {
        if index
            .accounts
            .iter()
            .any(|s| s.google_sub.as_deref() == Some(sub.as_str()))
        {
            return Err(format!("Account already exists for google_sub: {}", sub));
        }
    }
    if index.accounts.iter().any(|s| s.email == email) {
        return Err(format!("Account already exists: {}", email));
    }
    let account_id = Uuid::new_v4().to_string();
    let mut account = Account::new(account_id.clone(), email.clone(), token);
    account.google_sub = google_sub.clone();
    account.name = name.clone();
    save_account(&account)?;
    index.accounts.push(AccountSummary {
        id: account_id.clone(),
        email: email.clone(),
        google_sub,
        name: name.clone(),
        disabled: false,
        proxy_disabled: false,
        created_at: account.created_at,
        last_used: account.last_used,
    });
    if index.current_account_id.is_none() {
        index.current_account_id = Some(account_id);
    }

    save_account_index(&index)?;

    Ok(account)
}
pub fn upsert_account(
    email: String,
    name: Option<String>,
    token: TokenData,
    google_sub: Option<String>,
) -> Result<Account, String> {
    let _lock = ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|e| format!("failed_to_acquire_lock: {}", e))?;
    let mut index = load_account_index()?;
    let existing_by_sub = google_sub.as_ref().and_then(|sub| {
        index
            .accounts
            .iter()
            .find(|s| s.google_sub.as_ref() == Some(sub))
            .map(|s| s.id.clone())
    });
    let existing_account_id = existing_by_sub.or_else(|| {
        index
            .accounts
            .iter()
            .find(|s| s.email == email)
            .map(|s| s.id.clone())
    });

    if let Some(account_id) = existing_account_id {
        match load_account(&account_id) {
            Ok(mut account) => {
                let old_access_token = account.token.access_token.clone();
                let old_refresh_token = account.token.refresh_token.clone();
                account.token = token;
                account.name = name.clone();
                account.email = email.clone();
                if let Some(sub) = google_sub.as_ref() {
                    account.google_sub = Some(sub.clone());
                }
                if account.disabled
                    && (account.token.refresh_token != old_refresh_token
                        || account.token.access_token != old_access_token)
                {
                    account.disabled = false;
                    account.disabled_reason = None;
                    account.disabled_at = None;
                }
                account.update_last_used();
                save_account(&account)?;
                if let Some(idx_summary) = index.accounts.iter_mut().find(|s| s.id == account_id) {
                    idx_summary.email = email;
                    idx_summary.name = name;
                    if let Some(sub) = google_sub {
                        idx_summary.google_sub = Some(sub);
                    }
                    save_account_index(&index)?;
                }

                return Ok(account);
            }
            Err(e) => {
                crate::modules::system::logger::log_warn(&format!(
                    "Account {} file missing ({}), recreating...",
                    account_id, e
                ));
                let mut account = Account::new(account_id.clone(), email.clone(), token);
                account.google_sub = google_sub.clone();
                account.name = name.clone();
                save_account(&account)?;
                if let Some(idx_summary) = index.accounts.iter_mut().find(|s| s.id == account_id) {
                    idx_summary.email = email;
                    idx_summary.name = name;
                    if let Some(sub) = google_sub {
                        idx_summary.google_sub = Some(sub);
                    }
                    save_account_index(&index)?;
                }

                return Ok(account);
            }
        }
    }
    drop(_lock);
    add_account(email, name, token, google_sub)
}
pub fn delete_account(account_id: &str) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|e| format!("failed_to_acquire_lock: {}", e))?;
    let mut index = load_account_index()?;
    let original_len = index.accounts.len();
    index.accounts.retain(|s| s.id != account_id);

    if index.accounts.len() == original_len {
        return Err(format!("Account ID not found: {}", account_id));
    }
    if index.current_account_id.as_deref() == Some(account_id) {
        index.current_account_id = index.accounts.first().map(|s| s.id.clone());
    }

    save_account_index(&index)?;
    let accounts_dir = get_accounts_dir()?;
    let account_path = accounts_dir.join(format!("{}.json", account_id));

    if account_path.exists() {
        fs::remove_file(&account_path)
            .map_err(|e| format!("failed_to_delete_account_file: {}", e))?;
    }
    crate::proxy::server::trigger_account_delete(account_id);

    Ok(())
}
pub fn delete_accounts(account_ids: &[String]) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|e| format!("failed_to_acquire_lock: {}", e))?;
    let mut index = load_account_index()?;

    let accounts_dir = get_accounts_dir()?;

    for account_id in account_ids {
        index.accounts.retain(|s| &s.id != account_id);
        if index.current_account_id.as_deref() == Some(account_id) {
            index.current_account_id = None;
        }
        let account_path = accounts_dir.join(format!("{}.json", account_id));
        if account_path.exists() {
            let _ = fs::remove_file(&account_path);
        }
        crate::proxy::server::trigger_account_delete(account_id);
    }
    if index.current_account_id.is_none() {
        index.current_account_id = index.accounts.first().map(|s| s.id.clone());
    }

    save_account_index(&index)
}
pub fn reorder_accounts(account_ids: &[String]) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|e| format!("failed_to_acquire_lock: {}", e))?;
    let mut index = load_account_index()?;
    let id_to_summary: std::collections::HashMap<_, _> = index
        .accounts
        .iter()
        .map(|s| (s.id.clone(), s.clone()))
        .collect();
    let mut new_accounts = Vec::new();
    for id in account_ids {
        if let Some(summary) = id_to_summary.get(id) {
            new_accounts.push(summary.clone());
        }
    }
    for summary in &index.accounts {
        if !account_ids.contains(&summary.id) {
            new_accounts.push(summary.clone());
        }
    }

    index.accounts = new_accounts;

    crate::modules::system::logger::log_info(&format!(
        "Account order updated, {} accounts total",
        index.accounts.len()
    ));

    save_account_index(&index)
}
pub async fn switch_account(
    account_id: &str,
    integration: &(impl crate::modules::system::integration::SystemIntegration + ?Sized),
) -> Result<(), String> {
    use crate::modules::auth::oauth;

    let index = {
        let _lock = ACCOUNT_INDEX_LOCK
            .lock()
            .map_err(|e| format!("failed_to_acquire_lock: {}", e))?;
        load_account_index()?
    };
    if !index.accounts.iter().any(|s| s.id == account_id) {
        return Err(format!("Account not found: {}", account_id));
    }

    let mut account = load_account(account_id)?;
    crate::modules::system::logger::log_info(&format!(
        "Switching to account: {} (ID: {})",
        account.email, account.id
    ));
    let fresh_token = oauth::ensure_fresh_token(&account.token, Some(&account.id))
        .await
        .map_err(|e| format!("Token refresh failed: {}", e))?;
    if fresh_token.access_token != account.token.access_token {
        account.token = fresh_token.clone();
        save_account(&account)?;
    }
    ensure_device_profile_on_switch(&mut account)?;
    integration.on_account_switch(&account).await?;
    {
        let _lock = ACCOUNT_INDEX_LOCK
            .lock()
            .map_err(|e| format!("failed_to_acquire_lock: {}", e))?;
        let mut index = load_account_index()?;
        index.current_account_id = Some(account_id.to_string());
        save_account_index(&index)?;
    }

    account.update_last_used();
    save_account(&account)?;

    crate::modules::system::logger::log_info(&format!(
        "Account switch core logic completed: {}",
        account.email
    ));

    Ok(())
}

fn ensure_device_profile_on_switch(account: &mut Account) -> Result<(), String> {
    if account.device_profile.is_some() {
        return Ok(());
    }

    // Prefer capturing from local IDE storage.json (real telemetry) instead of generating
    // synthetic values. If capture fails, proceed without device headers.
    let storage_path = match crate::modules::system::device::get_storage_path() {
        Ok(path) => path,
        Err(e) => {
            crate::modules::system::logger::log_warn(&format!(
                "[DeviceProfile] No bound profile for {}, and storage.json not available ({}). Proceeding without device profile.",
                account.email, e
            ));
            return Ok(());
        }
    };
    let profile = match crate::modules::system::device::read_profile(&storage_path) {
        Ok(p) => p,
        Err(e) => {
            crate::modules::system::logger::log_warn(&format!(
                "[DeviceProfile] Failed to read storage.json for {} ({}). Proceeding without device profile.",
                account.email, e
            ));
            return Ok(());
        }
    };

    let _ = crate::modules::system::device::save_global_original(&profile);
    apply_profile_to_account(
        account,
        profile.clone(),
        Some("capture_on_switch".to_string()),
        true,
    )?;
    crate::modules::system::logger::log_info(&format!(
        "[DeviceProfile] Captured device profile on switch for {}.",
        account.email
    ));
    Ok(())
}
#[derive(Debug, Serialize)]
pub struct DeviceProfiles {
    pub current_storage: Option<DeviceProfile>,
    pub bound_profile: Option<DeviceProfile>,
    pub history: Vec<DeviceProfileVersion>,
    pub baseline: Option<DeviceProfile>,
}

pub fn get_device_profiles(account_id: &str) -> Result<DeviceProfiles, String> {
    let current = crate::modules::system::device::get_storage_path()
        .ok()
        .and_then(|path| crate::modules::system::device::read_profile(&path).ok());
    let account = load_account(account_id)?;
    Ok(DeviceProfiles {
        current_storage: current,
        bound_profile: account.device_profile.clone(),
        history: account.device_history.clone(),
        baseline: crate::modules::system::device::load_global_original(),
    })
}
pub fn bind_device_profile(account_id: &str, mode: &str) -> Result<DeviceProfile, String> {
    use crate::modules::system::device;

    let profile = match mode {
        "capture" => device::read_profile(&device::get_storage_path()?)?,
        "generate" => device::generate_profile(),
        _ => return Err("mode must be 'capture' or 'generate'".to_string()),
    };

    let mut account = load_account(account_id)?;
    let _ = device::save_global_original(&profile);
    apply_profile_to_account(&mut account, profile.clone(), Some(mode.to_string()), true)?;

    Ok(profile)
}
pub fn bind_device_profile_with_profile(
    account_id: &str,
    profile: DeviceProfile,
    label: Option<String>,
) -> Result<DeviceProfile, String> {
    let mut account = load_account(account_id)?;
    let _ = crate::modules::system::device::save_global_original(&profile);
    apply_profile_to_account(&mut account, profile.clone(), label, true)?;

    Ok(profile)
}

pub fn clear_device_profile(account_id: &str) -> Result<(), String> {
    let mut account = load_account(account_id)?;
    account.device_profile = None;
    for h in account.device_history.iter_mut() {
        h.is_current = false;
    }
    save_account(&account)?;
    Ok(())
}

fn apply_profile_to_account(
    account: &mut Account,
    profile: DeviceProfile,
    label: Option<String>,
    add_history: bool,
) -> Result<(), String> {
    account.device_profile = Some(profile.clone());
    if add_history {
        for h in account.device_history.iter_mut() {
            h.is_current = false;
        }
        account.device_history.push(DeviceProfileVersion {
            id: Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now().timestamp(),
            label: label.unwrap_or_else(|| "generated".to_string()),
            profile: profile.clone(),
            is_current: true,
        });
    }
    save_account(account)?;
    Ok(())
}
pub fn restore_device_version(account_id: &str, version_id: &str) -> Result<DeviceProfile, String> {
    let mut account = load_account(account_id)?;

    let target_profile = if version_id == "baseline" {
        crate::modules::system::device::load_global_original()
            .ok_or("Global original profile not found")?
    } else if let Some(v) = account.device_history.iter().find(|v| v.id == version_id) {
        v.profile.clone()
    } else if version_id == "current" {
        account
            .device_profile
            .clone()
            .ok_or("No currently bound profile")?
    } else {
        return Err("Device profile version not found".to_string());
    };

    account.device_profile = Some(target_profile.clone());
    for h in account.device_history.iter_mut() {
        h.is_current = h.id == version_id;
    }
    save_account(&account)?;
    Ok(target_profile)
}
pub fn delete_device_version(account_id: &str, version_id: &str) -> Result<(), String> {
    if version_id == "baseline" {
        return Err("Original profile cannot be deleted".to_string());
    }
    let mut account = load_account(account_id)?;
    if account
        .device_history
        .iter()
        .any(|v| v.id == version_id && v.is_current)
    {
        return Err("Currently bound profile cannot be deleted".to_string());
    }
    let before = account.device_history.len();
    account.device_history.retain(|v| v.id != version_id);
    if account.device_history.len() == before {
        return Err("Historical device profile not found".to_string());
    }
    save_account(&account)?;
    Ok(())
}
pub fn restore_original_device() -> Result<String, String> {
    if let Some(current_id) = get_current_account_id()? {
        if let Ok(mut account) = load_account(&current_id) {
            if let Some(original) = crate::modules::system::device::load_global_original() {
                account.device_profile = Some(original);
                for h in account.device_history.iter_mut() {
                    h.is_current = false;
                }
                save_account(&account)?;
                return Ok(
                    "Reset current account bound profile to original (not applied to storage)"
                        .to_string(),
                );
            }
        }
    }
    Err("Original profile not found, cannot restore".to_string())
}
pub fn get_current_account_id() -> Result<Option<String>, String> {
    let index = load_account_index()?;
    Ok(index.current_account_id)
}
pub fn get_current_account() -> Result<Option<Account>, String> {
    if let Some(id) = get_current_account_id()? {
        Ok(Some(load_account(&id)?))
    } else {
        Ok(None)
    }
}
pub fn update_account_quota(account_id: &str, quota: QuotaData) -> Result<(), String> {
    let mut account = load_account(account_id)?;
    account.update_quota(quota);
    if let Ok(config) = crate::modules::system::config::load_app_config() {
        if config.quota_protection.enabled {
            if let Some(ref q) = account.quota {
                let threshold = config.quota_protection.threshold_percentage as i32;

                for model in &q.models {
                    let standard_id =
                        match crate::proxy::common::model_mapping::normalize_to_standard_id(
                            &model.name,
                        ) {
                            Some(id) => id,
                            None => continue,
                        };
                    if !config
                        .quota_protection
                        .monitored_models
                        .contains(&standard_id)
                    {
                        continue;
                    }

                    if model.percentage <= threshold {
                        if !account.protected_models.contains(&standard_id) {
                            crate::modules::system::logger::log_info(&format!(
                                "[Quota] Triggering model protection: {} ({} [{}] remaining {}% <= threshold {}%)",
                                account.email, standard_id, model.name, model.percentage, threshold
                            ));
                            account.protected_models.insert(standard_id.clone());
                        }
                    } else if account.protected_models.contains(&standard_id) {
                        crate::modules::system::logger::log_info(&format!(
                            "[Quota] Model protection recovered: {} ({} [{}] quota restored to {}%)",
                            account.email, standard_id, model.name, model.percentage
                        ));
                        account.protected_models.remove(&standard_id);
                    }
                }
                if account.proxy_disabled
                    && account
                        .proxy_disabled_reason
                        .as_ref()
                        .is_some_and(|r| r == "quota_protection")
                {
                    crate::modules::system::logger::log_info(&format!(
                        "[Quota] Migrating account {} from account-level to model-level protection",
                        account.email
                    ));
                    account.proxy_disabled = false;
                    account.proxy_disabled_reason = None;
                    account.proxy_disabled_at = None;
                }
            }
        }
    }
    save_account(&account)?;
    crate::proxy::server::trigger_account_reload(account_id);

    Ok(())
}
pub fn toggle_proxy_status(
    account_id: &str,
    enable: bool,
    reason: Option<&str>,
) -> Result<(), String> {
    let mut account = load_account(account_id)?;

    account.proxy_disabled = !enable;
    account.proxy_disabled_reason = if !enable {
        reason.map(|s| s.to_string())
    } else {
        None
    };
    account.proxy_disabled_at = if !enable {
        Some(chrono::Utc::now().timestamp())
    } else {
        None
    };

    save_account(&account)?;
    let mut index = load_account_index()?;
    if let Some(summary) = index.accounts.iter_mut().find(|a| a.id == account_id) {
        summary.proxy_disabled = !enable;
        save_account_index(&index)?;
    }

    Ok(())
}
pub fn export_accounts_by_ids(
    account_ids: &[String],
) -> Result<crate::models::AccountExportResponse, String> {
    use crate::models::{AccountExportItem, AccountExportResponse};

    let accounts = list_accounts()?;

    let export_items: Vec<AccountExportItem> = accounts
        .into_iter()
        .filter(|acc| account_ids.contains(&acc.id))
        .map(|acc| AccountExportItem {
            email: acc.email,
            refresh_token: acc.token.refresh_token,
        })
        .collect();

    Ok(AccountExportResponse {
        accounts: export_items,
    })
}
pub async fn fetch_quota_with_retry(account: &mut Account) -> crate::error::AppResult<QuotaData> {
    use crate::error::AppError;
    use crate::modules::auth::oauth;
    use reqwest::StatusCode;
    let token = match oauth::ensure_fresh_token(&account.token, Some(&account.id)).await {
        Ok(t) => t,
        Err(e) => {
            if e.contains("invalid_grant") {
                crate::modules::system::logger::log_error(&format!(
                    "Disabling account {} due to invalid_grant during token refresh (quota check)",
                    account.email
                ));
                account.disabled = true;
                account.disabled_at = Some(chrono::Utc::now().timestamp());
                account.disabled_reason = Some(format!("invalid_grant: {}", e));
                let _ = save_account(account);
                crate::proxy::server::trigger_account_reload(&account.id);
            }
            return Err(AppError::OAuth(e));
        }
    };

    if token.access_token != account.token.access_token {
        crate::modules::system::logger::log_info(&format!(
            "Time-based Token refresh: {}",
            account.email
        ));
        account.token = token.clone();
        let name = if account.name.is_none()
            || account.name.as_ref().is_some_and(|n| n.trim().is_empty())
        {
            match oauth::get_user_info(&token.access_token, Some(&account.id)).await {
                Ok(user_info) => user_info.get_display_name(),
                Err(_) => None,
            }
        } else {
            account.name.clone()
        };

        account.name = name.clone();
        upsert_account(
            account.email.clone(),
            name,
            token.clone(),
            account.google_sub.clone(),
        )
        .map_err(AppError::Account)?;
    }
    if account.name.is_none() || account.name.as_ref().is_some_and(|n| n.trim().is_empty()) {
        crate::modules::system::logger::log_info(&format!(
            "Account {} missing display name, attempting to fetch...",
            account.email
        ));
        match oauth::get_user_info(&account.token.access_token, Some(&account.id)).await {
            Ok(user_info) => {
                let display_name = user_info.get_display_name();
                crate::modules::system::logger::log_info(&format!(
                    "Successfully fetched display name: {:?}",
                    display_name
                ));
                account.name = display_name.clone();
                if let Err(e) = upsert_account(
                    account.email.clone(),
                    display_name,
                    account.token.clone(),
                    account.google_sub.clone(),
                ) {
                    crate::modules::system::logger::log_warn(&format!(
                        "Failed to save display name: {}",
                        e
                    ));
                }
            }
            Err(e) => {
                crate::modules::system::logger::log_warn(&format!(
                    "Failed to fetch display name: {}",
                    e
                ));
            }
        }
    }
    let result: crate::error::AppResult<(QuotaData, Option<String>)> =
        crate::modules::system::quota::fetch_quota(
            &account.token.access_token,
            &account.email,
            Some(&account.id),
        )
        .await;
    if let Ok((ref _q, ref project_id)) = result {
        if project_id.is_some() && *project_id != account.token.project_id {
            crate::modules::system::logger::log_info(&format!(
                "Detected project_id update ({}), saving...",
                account.email
            ));
            account.token.project_id = project_id.clone();
            if let Err(e) = upsert_account(
                account.email.clone(),
                account.name.clone(),
                account.token.clone(),
                account.google_sub.clone(),
            ) {
                crate::modules::system::logger::log_warn(&format!(
                    "Failed to sync project_id: {}",
                    e
                ));
            }
        }
    }
    if let Err(AppError::Network(ref e)) = result {
        if let Some(status) = e.status() {
            if status == StatusCode::UNAUTHORIZED {
                crate::modules::system::logger::log_warn(&format!(
                    "401 Unauthorized for {}, forcing refresh...",
                    account.email
                ));
                let token_res = match oauth::refresh_access_token(
                    &account.token.refresh_token,
                    Some(&account.id),
                )
                .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        if e.contains("invalid_grant") {
                            crate::modules::system::logger::log_error(&format!(
                                "Disabling account {} due to invalid_grant during forced refresh (quota check)",
                                account.email
                            ));
                            account.disabled = true;
                            account.disabled_at = Some(chrono::Utc::now().timestamp());
                            account.disabled_reason = Some(format!("invalid_grant: {}", e));
                            let _ = save_account(account);
                            crate::proxy::server::trigger_account_reload(&account.id);
                        }
                        return Err(AppError::OAuth(e));
                    }
                };

                let new_token = TokenData::new(
                    token_res.access_token.clone(),
                    account.token.refresh_token.clone(),
                    token_res.expires_in,
                    account.token.email.clone(),
                    account.token.project_id.clone(),
                    None,
                );
                let name = if account.name.is_none()
                    || account.name.as_ref().is_some_and(|n| n.trim().is_empty())
                {
                    match oauth::get_user_info(&token_res.access_token, Some(&account.id)).await {
                        Ok(user_info) => user_info.get_display_name(),
                        Err(_) => None,
                    }
                } else {
                    account.name.clone()
                };

                account.token = new_token.clone();
                account.name = name.clone();
                upsert_account(
                    account.email.clone(),
                    name,
                    new_token.clone(),
                    account.google_sub.clone(),
                )
                .map_err(AppError::Account)?;
                let retry_result: crate::error::AppResult<(QuotaData, Option<String>)> =
                    crate::modules::system::quota::fetch_quota(
                        &new_token.access_token,
                        &account.email,
                        Some(&account.id),
                    )
                    .await;
                if let Ok((ref _q, ref project_id)) = retry_result {
                    if project_id.is_some() && *project_id != account.token.project_id {
                        crate::modules::system::logger::log_info(&format!(
                            "Detected update of project_id after retry ({}), saving...",
                            account.email
                        ));
                        account.token.project_id = project_id.clone();
                        let _ = upsert_account(
                            account.email.clone(),
                            account.name.clone(),
                            account.token.clone(),
                            account.google_sub.clone(),
                        );
                    }
                }

                if let Err(AppError::Network(ref e)) = retry_result {
                    if let Some(s) = e.status() {
                        if s == StatusCode::FORBIDDEN {
                            let mut q = QuotaData::new();
                            q.is_forbidden = true;
                            return Ok(q);
                        }
                    }
                }
                return retry_result.map(|(q, _)| q);
            }
        }
    }
    result.map(|(q, _)| q)
}

#[derive(Serialize)]
pub struct RefreshStats {
    pub total: usize,
    pub success: usize,
    pub failed: usize,
    pub details: Vec<String>,
}

fn refresh_task_stagger_bounds_ms() -> (u64, u64) {
    let min = std::env::var("ACCOUNT_REFRESH_STAGGER_MIN_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(250);
    let max = std::env::var("ACCOUNT_REFRESH_STAGGER_MAX_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1500);
    if min <= max {
        (min, max)
    } else {
        (max, min)
    }
}

fn per_account_refresh_stagger_ms(account_id: &str, min_ms: u64, max_ms: u64) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    if max_ms == 0 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    account_id.hash(&mut hasher);
    let span = max_ms.saturating_sub(min_ms);
    if span == 0 {
        min_ms
    } else {
        min_ms + (hasher.finish() % (span + 1))
    }
}

fn should_refresh_account_quota(account: &Account) -> bool {
    if account.disabled {
        crate::modules::system::logger::log_info(&format!(
            "  - Skipping {} (Disabled)",
            account.email
        ));
        return false;
    }
    if account.proxy_disabled {
        crate::modules::system::logger::log_info(&format!(
            "  - Skipping {} (Proxy Disabled)",
            account.email
        ));
        return false;
    }
    if let Some(ref q) = account.quota {
        if q.is_forbidden {
            crate::modules::system::logger::log_info(&format!(
                "  - Skipping {} (Forbidden)",
                account.email
            ));
            return false;
        }
    }
    true
}

pub async fn refresh_all_quotas_logic() -> Result<RefreshStats, String> {
    use futures::future::join_all;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    const MAX_CONCURRENT: usize = 5;
    let start = std::time::Instant::now();

    crate::modules::system::logger::log_info(&format!(
        "Starting batch refresh of all account quotas (Concurrent mode, max: {})",
        MAX_CONCURRENT
    ));
    let (stagger_min_ms, stagger_max_ms) = refresh_task_stagger_bounds_ms();
    crate::modules::system::logger::log_info(&format!(
        "Per-account refresh staggering active: {}-{}ms",
        stagger_min_ms, stagger_max_ms
    ));
    let accounts = list_accounts()?;

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));

    let tasks: Vec<_> = accounts
        .into_iter()
        .filter(should_refresh_account_quota)
        .map(|mut account| {
            let email = account.email.clone();
            let account_id = account.id.clone();
            let stagger_ms =
                per_account_refresh_stagger_ms(&account_id, stagger_min_ms, stagger_max_ms);
            let permit = semaphore.clone();
            async move {
                if stagger_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(stagger_ms)).await;
                }
                let _guard = permit.acquire().await.unwrap();
                crate::modules::system::logger::log_info(&format!("  - Processing {}", email));
                match fetch_quota_with_retry(&mut account).await {
                    Ok(quota) => {
                        if let Err(e) = update_account_quota(&account_id, quota) {
                            let msg = format!("Account {}: Save quota failed - {}", email, e);
                            crate::modules::system::logger::log_error(&msg);
                            Err(msg)
                        } else {
                            crate::modules::system::logger::log_info(&format!(
                                "    ✅ {} Success",
                                email
                            ));
                            Ok(())
                        }
                    }
                    Err(e) => {
                        let msg = format!("Account {}: Fetch quota failed - {}", email, e);
                        crate::modules::system::logger::log_error(&msg);
                        Err(msg)
                    }
                }
            }
        })
        .collect();

    let total = tasks.len();
    let results = join_all(tasks).await;

    let mut success = 0;
    let mut failed = 0;
    let mut details = Vec::new();

    for result in results {
        match result {
            Ok(()) => success += 1,
            Err(msg) => {
                failed += 1;
                details.push(msg);
            }
        }
    }

    let elapsed = start.elapsed();
    crate::modules::system::logger::log_info(&format!(
        "Batch refresh completed: {} success, {} failed, took: {}ms",
        success,
        failed,
        elapsed.as_millis()
    ));

    Ok(RefreshStats {
        total,
        success,
        failed,
        details,
    })
}

pub async fn refresh_all_quotas_sequential_logic(
    min_delay_seconds: u64,
    max_delay_seconds: u64,
) -> Result<RefreshStats, String> {
    use rand::Rng;

    let start = std::time::Instant::now();
    let (min_delay_seconds, max_delay_seconds) = if min_delay_seconds <= max_delay_seconds {
        (min_delay_seconds, max_delay_seconds)
    } else {
        (max_delay_seconds, min_delay_seconds)
    };

    crate::modules::system::logger::log_info(&format!(
        "Starting batch refresh of all account quotas (Sequential mode, delay: {}-{}s)",
        min_delay_seconds, max_delay_seconds
    ));

    let accounts: Vec<Account> = list_accounts()?
        .into_iter()
        .filter(should_refresh_account_quota)
        .collect();

    let total = accounts.len();
    let mut success = 0usize;
    let mut failed = 0usize;
    let mut details = Vec::new();

    for (index, mut account) in accounts.into_iter().enumerate() {
        if index > 0 && max_delay_seconds > 0 {
            let delay_seconds = if min_delay_seconds == max_delay_seconds {
                min_delay_seconds
            } else {
                rand::thread_rng().gen_range(min_delay_seconds..=max_delay_seconds)
            };
            if delay_seconds > 0 {
                crate::modules::system::logger::log_info(&format!(
                    "  - Waiting {}s before processing next account",
                    delay_seconds
                ));
                tokio::time::sleep(std::time::Duration::from_secs(delay_seconds)).await;
            }
        }

        let email = account.email.clone();
        let account_id = account.id.clone();
        crate::modules::system::logger::log_info(&format!("  - Processing {}", email));

        match fetch_quota_with_retry(&mut account).await {
            Ok(quota) => {
                if let Err(e) = update_account_quota(&account_id, quota) {
                    let msg = format!("Account {}: Save quota failed - {}", email, e);
                    crate::modules::system::logger::log_error(&msg);
                    failed += 1;
                    details.push(msg);
                } else {
                    crate::modules::system::logger::log_info(&format!("    ✅ {} Success", email));
                    success += 1;
                }
            }
            Err(e) => {
                let msg = format!("Account {}: Fetch quota failed - {}", email, e);
                crate::modules::system::logger::log_error(&msg);
                failed += 1;
                details.push(msg);
            }
        }
    }

    let elapsed = start.elapsed();
    crate::modules::system::logger::log_info(&format!(
        "Sequential quota refresh completed: {} success, {} failed, took: {}ms",
        success,
        failed,
        elapsed.as_millis()
    ));

    Ok(RefreshStats {
        total,
        success,
        failed,
        details,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_device_profile_on_switch, list_accounts, load_account, load_account_index,
        per_account_refresh_stagger_ms, refresh_task_stagger_bounds_ms, upsert_account,
    };
    use crate::models::TokenData;
    use crate::test_utils::ScopedEnvVar;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    static ACCOUNT_TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn write_account_fixture(
        root: &Path,
        account_id: &str,
        email: &str,
        access_token: &str,
        refresh_token: &str,
    ) {
        let now = chrono::Utc::now().timestamp();
        let account = json!({
            "id": account_id,
            "email": email,
            "name": null,
            "token": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 3600,
                "expiry_timestamp": now + 3600,
                "token_type": "Bearer",
                "email": email,
                "project_id": null,
                "session_id": null
            },
            "quota": null,
            "disabled": false,
            "proxy_disabled": false,
            "created_at": now,
            "last_used": now
        });

        let accounts_dir = root.join("accounts");
        std::fs::create_dir_all(&accounts_dir).expect("create accounts dir");
        std::fs::write(
            accounts_dir.join(format!("{}.json", account_id)),
            serde_json::to_string_pretty(&account).expect("serialize account fixture"),
        )
        .expect("write account fixture");
    }

    fn write_index_fixture(root: &Path, summaries: &[(&str, &str)]) {
        let now = chrono::Utc::now().timestamp();
        let accounts: Vec<serde_json::Value> = summaries
            .iter()
            .map(|(id, email)| {
                json!({
                    "id": id,
                    "email": email,
                    "name": null,
                    "disabled": false,
                    "proxy_disabled": false,
                    "created_at": now,
                    "last_used": now
                })
            })
            .collect();
        let index = json!({
            "version": "2.0",
            "accounts": accounts,
            "current_account_id": summaries.first().map(|(id, _)| *id)
        });

        std::fs::write(
            root.join("accounts.json"),
            serde_json::to_string_pretty(&index).expect("serialize index fixture"),
        )
        .expect("write index fixture");
    }

    fn make_temp_data_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            ".gephyr-account-deser-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("create temp data dir");
        dir
    }

    fn make_token(email: &str, suffix: &str) -> TokenData {
        TokenData::new(
            format!("access-{}", suffix),
            format!("refresh-{}", suffix),
            3600,
            Some(email.to_string()),
            None,
            None,
        )
    }

    #[test]
    fn ensure_device_profile_on_switch_does_not_generate_when_storage_override_missing() {
        let _guard = ACCOUNT_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("account env lock");

        // Force deterministic behavior: make get_storage_path fail without scanning the real system.
        let _storage_override = ScopedEnvVar::set(
            "ANTIGRAVITY_STORAGE_JSON_PATH",
            "Z:\\this-path-does-not-exist\\storage.json",
        );

        let mut account = crate::models::account::Account::new(
            "acct-1".to_string(),
            "no-device@example.com".to_string(),
            make_token("no-device@example.com", "t1"),
        );
        account.device_profile = None;

        ensure_device_profile_on_switch(&mut account).expect("should not error");
        assert!(account.device_profile.is_none());
    }

    #[test]
    fn ensure_device_profile_on_switch_captures_when_storage_override_present() {
        let _guard = ACCOUNT_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("account env lock");

        let data_dir = make_temp_data_dir();
        let _data_dir_env = ScopedEnvVar::set("DATA_DIR", data_dir.to_string_lossy().as_ref());

        // Write a minimal storage.json fixture.
        let storage_path = data_dir.join("storage.json");
        let storage = json!({
            "telemetry": {
                "machineId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "devDeviceId": "11111111-1111-4111-8111-111111111111",
                "sqmId": "{22222222-2222-4222-8222-222222222222}"
            }
        });
        std::fs::write(
            &storage_path,
            serde_json::to_string_pretty(&storage).expect("serialize storage.json"),
        )
        .expect("write storage.json");

        let _storage_override = ScopedEnvVar::set(
            "ANTIGRAVITY_STORAGE_JSON_PATH",
            storage_path.to_string_lossy().as_ref(),
        );

        // Persist an account so apply_profile_to_account can save it.
        write_account_fixture(
            &data_dir,
            "acct-switch",
            "switch@example.com",
            "plain-access-token",
            "plain-refresh-token",
        );
        // Ensure the loaded account has no device_profile.
        let mut account = load_account("acct-switch").expect("load account");
        account.device_profile = None;
        super::save_account(&account).expect("save account without device profile");

        ensure_device_profile_on_switch(&mut account).expect("should capture");
        let bound = account
            .device_profile
            .clone()
            .expect("device profile captured");
        assert_eq!(
            bound.machine_id.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            bound.dev_device_id.as_deref(),
            Some("11111111-1111-4111-8111-111111111111")
        );
        assert_eq!(
            bound.sqm_id.as_deref(),
            Some("{22222222-2222-4222-8222-222222222222}")
        );
        // macMachineId was not present in fixture and should remain None.
        assert!(bound.mac_machine_id.is_none());

        let reloaded = load_account("acct-switch").expect("reload");
        assert!(reloaded.device_profile.is_some());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn load_account_accepts_malformed_v2_tokens_via_deserialize_fallback() {
        let _security_guard = crate::proxy::tests::acquire_security_test_lock();
        let _guard = ACCOUNT_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("account env lock");

        let data_dir = make_temp_data_dir();
        let _data_dir_env = ScopedEnvVar::set("DATA_DIR", data_dir.to_string_lossy().as_ref());

        write_account_fixture(
            &data_dir,
            "acct-malformed",
            "malformed@example.com",
            "v2:abc",
            "v2:abc",
        );

        let loaded = load_account("acct-malformed").expect("load account should succeed");
        assert_eq!(loaded.token.access_token, "v2:abc");
        assert_eq!(loaded.token.refresh_token, "v2:abc");

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn list_accounts_keeps_entries_with_malformed_v2_tokens() {
        let _security_guard = crate::proxy::tests::acquire_security_test_lock();
        let _guard = ACCOUNT_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("account env lock");

        let data_dir = make_temp_data_dir();
        let _data_dir_env = ScopedEnvVar::set("DATA_DIR", data_dir.to_string_lossy().as_ref());

        write_account_fixture(
            &data_dir,
            "acct-plain",
            "plain@example.com",
            "plain-access-token",
            "plain-refresh-token",
        );
        write_account_fixture(
            &data_dir,
            "acct-malformed",
            "malformed@example.com",
            "v2:abc",
            "v2:abc",
        );
        write_index_fixture(
            &data_dir,
            &[
                ("acct-plain", "plain@example.com"),
                ("acct-malformed", "malformed@example.com"),
            ],
        );

        let accounts = list_accounts().expect("list_accounts should succeed");
        assert_eq!(
            accounts.len(),
            2,
            "malformed v2 entry should not be dropped"
        );
        let malformed = accounts
            .iter()
            .find(|a| a.id == "acct-malformed")
            .expect("malformed account should still be present");
        assert_eq!(malformed.token.access_token, "v2:abc");
        assert_eq!(malformed.token.refresh_token, "v2:abc");

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn upsert_prefers_google_sub_over_email() {
        let _security_guard = crate::proxy::tests::acquire_security_test_lock();
        let _guard = ACCOUNT_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("account env lock");

        let data_dir = make_temp_data_dir();
        let _data_dir_env = ScopedEnvVar::set("DATA_DIR", data_dir.to_string_lossy().as_ref());
        let _enc_key_env = ScopedEnvVar::set("ENCRYPTION_KEY", "test-encryption-key");

        let first = upsert_account(
            "old@example.com".to_string(),
            Some("Old".to_string()),
            make_token("old@example.com", "old"),
            Some("google-sub-1".to_string()),
        )
        .expect("initial upsert");

        let second = upsert_account(
            "new@example.com".to_string(),
            Some("New".to_string()),
            make_token("new@example.com", "new"),
            Some("google-sub-1".to_string()),
        )
        .expect("upsert by google_sub");

        assert_eq!(first.id, second.id, "must reuse same account id by sub");
        assert_eq!(second.email, "new@example.com");
        assert_eq!(second.google_sub.as_deref(), Some("google-sub-1"));

        let loaded = load_account(&first.id).expect("load updated account");
        assert_eq!(loaded.email, "new@example.com");
        assert_eq!(loaded.google_sub.as_deref(), Some("google-sub-1"));

        let index = load_account_index().expect("load index");
        assert_eq!(index.accounts.len(), 1);
        assert_eq!(index.accounts[0].email, "new@example.com");
        assert_eq!(
            index.accounts[0].google_sub.as_deref(),
            Some("google-sub-1")
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn upsert_backfills_google_sub() {
        let _security_guard = crate::proxy::tests::acquire_security_test_lock();
        let _guard = ACCOUNT_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("account env lock");

        let data_dir = make_temp_data_dir();
        let _data_dir_env = ScopedEnvVar::set("DATA_DIR", data_dir.to_string_lossy().as_ref());
        let _enc_key_env = ScopedEnvVar::set("ENCRYPTION_KEY", "test-encryption-key");

        let first = upsert_account(
            "backfill@example.com".to_string(),
            None,
            make_token("backfill@example.com", "initial"),
            None,
        )
        .expect("initial email-only upsert");
        assert!(first.google_sub.is_none());

        let second = upsert_account(
            "backfill@example.com".to_string(),
            None,
            make_token("backfill@example.com", "second"),
            Some("google-sub-backfill".to_string()),
        )
        .expect("backfill sub");

        assert_eq!(first.id, second.id);
        assert_eq!(second.google_sub.as_deref(), Some("google-sub-backfill"));

        let loaded = load_account(&first.id).expect("load updated account");
        assert_eq!(loaded.google_sub.as_deref(), Some("google-sub-backfill"));

        let index = load_account_index().expect("load index");
        assert_eq!(
            index.accounts[0].google_sub.as_deref(),
            Some("google-sub-backfill")
        );

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn refresh_stagger_is_deterministic_and_in_range() {
        let _guard = ACCOUNT_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("account env lock");
        let a = per_account_refresh_stagger_ms("acct-1", 250, 1500);
        let b = per_account_refresh_stagger_ms("acct-1", 250, 1500);
        let c = per_account_refresh_stagger_ms("acct-2", 250, 1500);

        assert_eq!(a, b);
        assert!((250..=1500).contains(&a));
        assert!((250..=1500).contains(&c));
    }

    #[test]
    fn refresh_stagger_bounds_swap_when_reversed() {
        let _guard = ACCOUNT_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("account env lock");
        std::env::set_var("ACCOUNT_REFRESH_STAGGER_MIN_MS", "1900");
        std::env::set_var("ACCOUNT_REFRESH_STAGGER_MAX_MS", "300");

        let (min_ms, max_ms) = refresh_task_stagger_bounds_ms();
        assert_eq!(min_ms, 300);
        assert_eq!(max_ms, 1900);

        std::env::remove_var("ACCOUNT_REFRESH_STAGGER_MIN_MS");
        std::env::remove_var("ACCOUNT_REFRESH_STAGGER_MAX_MS");
    }
}
