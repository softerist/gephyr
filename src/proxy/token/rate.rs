use dashmap::DashMap;
use std::path::Path;

use crate::proxy::token::types::ProxyToken;

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
    data_dir: &Path,
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    account_id: &str,
    reason: crate::proxy::rate_limit::RateLimitReason,
    model: Option<String>,
) -> bool {
    if let Some(reset_time_str) =
        crate::proxy::token::persistence::get_quota_reset_time(data_dir, account_id)
    {
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

pub(crate) async fn fetch_and_lock_with_realtime_quota(
    tokens: &DashMap<String, ProxyToken>,
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    email: &str,
    reason: crate::proxy::rate_limit::RateLimitReason,
    model: Option<String>,
) -> bool {
    let found = tokens.iter().find_map(|entry| {
        let token = entry.value();
        if token.email == email {
            Some((token.access_token.clone(), token.account_id.clone()))
        } else {
            None
        }
    });

    let (access_token, account_id) = match found {
        Some(pair) => pair,
        None => {
            tracing::warn!(
                "Failed to find access_token for account {}, unable to refresh quota in real-time",
                email
            );
            return false;
        }
    };

    tracing::info!("Account {} is refreshing quota in real-time...", email);
    match crate::modules::system::quota::fetch_quota(&access_token, email, Some(&account_id)).await
    {
        Ok((quota_data, _project_id)) => {
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
                rate_limit_tracker.set_lockout_until_iso(&account_id, reset_time_str, reason, model)
            } else {
                tracing::warn!(
                    "Account {} quota refresh successful but no reset_time found",
                    email
                );
                false
            }
        }
        Err(e) => {
            tracing::warn!("Account {} real-time quota refresh failed: {:?}", email, e);
            false
        }
    }
}

pub(crate) struct RateLimitedAsyncContext<'a> {
    pub tokens: &'a DashMap<String, ProxyToken>,
    pub data_dir: &'a Path,
    pub rate_limit_tracker: &'a crate::proxy::rate_limit::RateLimitTracker,
    pub circuit_breaker_config: &'a tokio::sync::RwLock<crate::models::CircuitBreakerConfig>,
}

pub(crate) struct RateLimitedEvent<'a> {
    pub email: &'a str,
    pub status: u16,
    pub retry_after_header: Option<&'a str>,
    pub error_body: &'a str,
    pub model: Option<&'a str>,
}

pub(crate) async fn mark_rate_limited_async(
    context: RateLimitedAsyncContext<'_>,
    event: RateLimitedEvent<'_>,
) {
    let config = context.circuit_breaker_config.read().await.clone();
    if !config.enabled {
        return;
    }

    let account_id = crate::proxy::token::lookup::account_id_by_email(context.tokens, event.email)
        .unwrap_or_else(|| event.email.to_string());

    let has_explicit_retry_time =
        event.retry_after_header.is_some() || event.error_body.contains("quotaResetDelay");

    if has_explicit_retry_time {
        if let Some(m) = event.model {
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
        context.rate_limit_tracker.parse_from_error(
            &account_id,
            event.status,
            event.retry_after_header,
            event.error_body,
            event.model.map(|s| s.to_string()),
            &config.backoff_steps,
        );
        return;
    }

    let reason = if event.error_body.to_lowercase().contains("model_capacity") {
        crate::proxy::rate_limit::RateLimitReason::ModelCapacityExhausted
    } else if event.error_body.to_lowercase().contains("exhausted")
        || event.error_body.to_lowercase().contains("quota")
    {
        crate::proxy::rate_limit::RateLimitReason::QuotaExhausted
    } else {
        crate::proxy::rate_limit::RateLimitReason::Unknown
    };

    if let Some(m) = event.model {
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

    if fetch_and_lock_with_realtime_quota(
        context.tokens,
        context.rate_limit_tracker,
        event.email,
        reason,
        event.model.map(|s| s.to_string()),
    )
    .await
    {
        tracing::info!(
            "Account {} has been locked with real-time quota precision",
            event.email
        );
        return;
    }

    if set_precise_lockout(
        context.data_dir,
        context.rate_limit_tracker,
        &account_id,
        reason,
        event.model.map(|s| s.to_string()),
    ) {
        tracing::info!(
            "Account {} has been locked with locally cached quota",
            account_id
        );
        return;
    }

    tracing::warn!(
        "Account {} unable to fetch quota reset time, using exponential backoff strategy",
        account_id
    );
    context.rate_limit_tracker.parse_from_error(
        &account_id,
        event.status,
        event.retry_after_header,
        event.error_body,
        event.model.map(|s| s.to_string()),
        &config.backoff_steps,
    );
}