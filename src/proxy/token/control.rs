use dashmap::DashMap;

use crate::proxy::sticky_config::StickySessionConfig;

pub(crate) async fn get_sticky_config(
    sticky_config: &tokio::sync::RwLock<StickySessionConfig>,
) -> StickySessionConfig {
    sticky_config.read().await.clone()
}

pub(crate) async fn update_sticky_config(
    sticky_config: &tokio::sync::RwLock<StickySessionConfig>,
    new_config: StickySessionConfig,
) {
    let mut config = sticky_config.write().await;
    *config = new_config;
    tracing::debug!("Scheduling configuration updated: {:?}", *config);
}

pub(crate) async fn update_circuit_breaker_config(
    circuit_breaker_config: &tokio::sync::RwLock<crate::models::CircuitBreakerConfig>,
    config: crate::models::CircuitBreakerConfig,
) {
    let mut lock = circuit_breaker_config.write().await;
    *lock = config;
    tracing::debug!("Circuit breaker configuration updated");
}

pub(crate) async fn get_circuit_breaker_config(
    circuit_breaker_config: &tokio::sync::RwLock<crate::models::CircuitBreakerConfig>,
) -> crate::models::CircuitBreakerConfig {
    circuit_breaker_config.read().await.clone()
}

pub(crate) fn clear_all_sessions(session_accounts: &DashMap<String, String>) {
    session_accounts.clear();
}

pub(crate) async fn set_preferred_account(
    preferred_account_id: &tokio::sync::RwLock<Option<String>>,
    account_id: Option<String>,
) {
    let mut preferred = preferred_account_id.write().await;
    if let Some(ref id) = account_id {
        tracing::info!("🔒  Fixed account mode enabled: {}", id);
    } else {
        tracing::info!("🔄  Round-robin mode enabled (no preferred account)");
    }
    *preferred = account_id;
}

pub(crate) async fn get_preferred_account(
    preferred_account_id: &tokio::sync::RwLock<Option<String>>,
) -> Option<String> {
    preferred_account_id.read().await.clone()
}