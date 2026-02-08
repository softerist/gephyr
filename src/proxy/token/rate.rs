use std::path::PathBuf;

pub(crate) async fn mark_rate_limited(
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    circuit_breaker_config: &tokio::sync::RwLock<crate::models::CircuitBreakerConfig>,
    account_key: &str,
    status: u16,
    retry_after_header: Option<&str>,
    error_body: &str,
) {
    let config = circuit_breaker_config.read().await.clone();
    if !config.enabled {
        return;
    }

    rate_limit_tracker.parse_from_error(
        account_key,
        status,
        retry_after_header,
        error_body,
        None,
        &config.backoff_steps,
    );
}

pub(crate) async fn is_rate_limited(
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    circuit_breaker_config: &tokio::sync::RwLock<crate::models::CircuitBreakerConfig>,
    account_id: &str,
    model: Option<&str>,
) -> bool {
    let config = circuit_breaker_config.read().await;
    if !config.enabled {
        return false;
    }
    rate_limit_tracker.is_rate_limited(account_id, model)
}

pub(crate) fn is_rate_limited_sync(
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    circuit_breaker_config: &tokio::sync::RwLock<crate::models::CircuitBreakerConfig>,
    account_id: &str,
    model: Option<&str>,
) -> bool {
    let config = circuit_breaker_config.blocking_read();
    if !config.enabled {
        return false;
    }
    rate_limit_tracker.is_rate_limited(account_id, model)
}

pub(crate) fn get_rate_limit_reset_seconds(
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    account_id: &str,
) -> Option<u64> {
    rate_limit_tracker.get_reset_seconds(account_id)
}

pub(crate) fn clean_expired_rate_limits(
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
) {
    rate_limit_tracker.cleanup_expired();
}

pub(crate) fn clear_rate_limit(
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    account_id: &str,
) -> bool {
    rate_limit_tracker.clear(account_id)
}

pub(crate) fn clear_all_rate_limits(
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
) {
    rate_limit_tracker.clear_all();
}

pub(crate) fn mark_account_success(
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    account_id: &str,
) {
    rate_limit_tracker.mark_success(account_id);
}

pub(crate) fn set_precise_lockout(
    data_dir: &PathBuf,
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    account_id: &str,
    reason: crate::proxy::rate_limit::RateLimitReason,
    model: Option<String>,
) -> bool {
    if let Some(reset_time_str) = crate::proxy::token::persistence::get_quota_reset_time(data_dir, account_id) {
        tracing::info!(
            "Found quota reset time for account {}: {}",
            account_id,
            reset_time_str
        );
        rate_limit_tracker.set_lockout_until_iso(account_id, &reset_time_str, reason, model)
    } else {
        tracing::debug!(
            "Quota reset time for account {} not found, will use default backoff strategy",
            account_id
        );
        false
    }
}
