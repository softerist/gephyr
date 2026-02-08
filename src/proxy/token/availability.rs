use dashmap::DashMap;

use crate::proxy::token::types::ProxyToken;

pub(crate) async fn has_available_account(
    tokens: &DashMap<String, ProxyToken>,
    rate_limit_tracker: &crate::proxy::rate_limit::RateLimitTracker,
    circuit_breaker_config: &tokio::sync::RwLock<crate::models::CircuitBreakerConfig>,
    target_model: &str,
) -> bool {
    let quota_protection_enabled = crate::modules::system::config::load_app_config()
        .map(|cfg| cfg.quota_protection.enabled)
        .unwrap_or(false);

    for entry in tokens.iter() {
        let token = entry.value();

        if crate::proxy::token::rate::is_rate_limited(
            rate_limit_tracker,
            circuit_breaker_config,
            &token.account_id,
            None,
        )
        .await
        {
            tracing::debug!(
                "[Fallback Check] Account {} is rate-limited, skipping",
                token.email
            );
            continue;
        }

        if quota_protection_enabled && token.protected_models.contains(target_model) {
            tracing::debug!(
                "[Fallback Check] Account {} is quota-protected for model {}, skipping",
                token.email,
                target_model
            );
            continue;
        }

        tracing::debug!(
            "[Fallback Check] Found available account: {} for model {}",
            token.email,
            target_model
        );
        return true;
    }

    tracing::info!(
        "[Fallback Check] No available Google accounts for model {}, fallback should be triggered",
        target_model
    );
    false
}
