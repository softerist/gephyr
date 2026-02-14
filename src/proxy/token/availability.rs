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
            Some(target_model),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CircuitBreakerConfig;
    use crate::proxy::rate_limit::{RateLimitReason, RateLimitTracker};
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};
    use tokio::sync::RwLock;

    fn make_token(account_id: &str, email: &str) -> ProxyToken {
        ProxyToken {
            account_id: account_id.to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_in: 3600,
            timestamp: chrono::Utc::now().timestamp(),
            email: email.to_string(),
            account_path: PathBuf::new(),
            project_id: None,
            subscription_tier: None,
            remaining_quota: None,
            protected_models: HashSet::new(),
            health_score: 1.0,
            reset_time: None,
            validation_blocked: false,
            validation_blocked_until: 0,
            model_quotas: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_has_available_account_respects_model_specific_rate_limit() {
        let tokens: DashMap<String, ProxyToken> = DashMap::new();
        tokens.insert("acc-1".to_string(), make_token("acc-1", "acc1@example.com"));

        let tracker = RateLimitTracker::new();
        tracker.set_lockout_until(
            "acc-1",
            SystemTime::now() + Duration::from_secs(60),
            RateLimitReason::QuotaExhausted,
            Some("gemini-2.5-pro".to_string()),
        );
        let circuit_breaker = RwLock::new(CircuitBreakerConfig::default());

        let available =
            has_available_account(&tokens, &tracker, &circuit_breaker, "gemini-2.5-pro").await;
        assert!(
            !available,
            "Model-scoped lock should make the account unavailable for that model"
        );
    }

    #[tokio::test]
    async fn test_has_available_account_allows_other_models_when_model_specific_lock_exists() {
        let tokens: DashMap<String, ProxyToken> = DashMap::new();
        tokens.insert("acc-1".to_string(), make_token("acc-1", "acc1@example.com"));

        let tracker = RateLimitTracker::new();
        tracker.set_lockout_until(
            "acc-1",
            SystemTime::now() + Duration::from_secs(60),
            RateLimitReason::QuotaExhausted,
            Some("gemini-2.5-pro".to_string()),
        );
        let circuit_breaker = RwLock::new(CircuitBreakerConfig::default());

        let available =
            has_available_account(&tokens, &tracker, &circuit_breaker, "gemini-2.5-flash").await;
        assert!(
            available,
            "Model-scoped lock should not block availability for unrelated models"
        );
    }
}