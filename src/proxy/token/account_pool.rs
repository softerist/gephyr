use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::proxy::token::types::ProxyToken;

pub(crate) fn remove_account(
    tokens: &DashMap<String, ProxyToken>,
    health_scores: &DashMap<String, f32>,
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    session_accounts: &DashMap<String, String>,
    preferred_account_id: &tokio::sync::RwLock<Option<String>>,
    account_id: &str,
) {
    if tokens.remove(account_id).is_some() {
        tracing::info!("[Proxy] Removed account {} from memory cache", account_id);
    }

    health_scores.remove(account_id);
    crate::proxy::token::rate::clear_rate_limit(rate_limit_tracker, account_id);
    session_accounts.retain(|_, v| v != account_id);

    if let Ok(mut preferred) = preferred_account_id.try_write() {
        if preferred.as_deref() == Some(account_id) {
            *preferred = None;
            tracing::info!("[Proxy] Cleared preferred account status for {}", account_id);
        }
    }
}

pub(crate) async fn load_accounts(
    data_dir: &PathBuf,
    tokens: &DashMap<String, ProxyToken>,
    current_index: &AtomicUsize,
    last_used_account: &tokio::sync::Mutex<Option<(String, Instant)>>,
    health_scores: &DashMap<String, f32>,
) -> Result<usize, String> {
    let accounts_dir = data_dir.join("accounts");

    if !accounts_dir.exists() {
        return Err(format!("Account directory does not exist: {:?}", accounts_dir));
    }

    tokens.clear();
    current_index.store(0, Ordering::SeqCst);
    {
        let mut last_used = last_used_account.lock().await;
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

        match crate::proxy::token::loader::load_single_account(&path, health_scores).await {
            Ok(Some(token)) => {
                let account_id = token.account_id.clone();
                tokens.insert(account_id, token);
                count += 1;
            }
            Ok(None) => {}
            Err(e) => tracing::debug!("Failed to load account {:?}: {}", path, e),
        }
    }

    Ok(count)
}

pub(crate) async fn reload_account(
    data_dir: &PathBuf,
    tokens: &DashMap<String, ProxyToken>,
    health_scores: &DashMap<String, f32>,
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    session_accounts: &DashMap<String, String>,
    preferred_account_id: &tokio::sync::RwLock<Option<String>>,
    account_id: &str,
) -> Result<(), String> {
    let path = data_dir.join("accounts").join(format!("{}.json", account_id));
    if !path.exists() {
        return Err(format!("Account file does not exist: {:?}", path));
    }

    match crate::proxy::token::loader::load_single_account(&path, health_scores).await {
        Ok(Some(token)) => {
            tokens.insert(account_id.to_string(), token);
            crate::proxy::token::rate::clear_rate_limit(rate_limit_tracker, account_id);
            Ok(())
        }
        Ok(None) => {
            remove_account(
                tokens,
                health_scores,
                rate_limit_tracker,
                session_accounts,
                preferred_account_id,
                account_id,
            );
            Ok(())
        }
        Err(e) => Err(format!("Failed to sync account: {}", e)),
    }
}

pub(crate) async fn reload_all_accounts(
    data_dir: &PathBuf,
    tokens: &DashMap<String, ProxyToken>,
    current_index: &AtomicUsize,
    last_used_account: &tokio::sync::Mutex<Option<(String, Instant)>>,
    health_scores: &DashMap<String, f32>,
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
) -> Result<usize, String> {
    let count = load_accounts(
        data_dir,
        tokens,
        current_index,
        last_used_account,
        health_scores,
    )
    .await?;
    crate::proxy::token::rate::clear_all_rate_limits(rate_limit_tracker);
    Ok(count)
}
