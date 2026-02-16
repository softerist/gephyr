pub mod crypto;
pub mod proxy;
pub mod user_token;

use crate::modules;

pub use modules::auth::account::RefreshStats;

fn scheduler_refresh_account_delay_bounds_seconds() -> (u64, u64) {
    let min = std::env::var("SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5);
    let max = std::env::var("SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);
    if min <= max {
        (min, max)
    } else {
        (max, min)
    }
}

#[cfg(test)]
mod tests {
    use super::scheduler_refresh_account_delay_bounds_seconds;
    use crate::test_utils::lock_env;

    #[test]
    fn scheduler_refresh_account_delay_defaults_are_reasonable() {
        let _guard = lock_env();
        std::env::remove_var("SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS");
        std::env::remove_var("SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS");
        assert_eq!(scheduler_refresh_account_delay_bounds_seconds(), (5, 30));
    }

    #[test]
    fn scheduler_refresh_account_delay_bounds_swap_when_reversed() {
        let _guard = lock_env();
        std::env::set_var("SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS", "30");
        std::env::set_var("SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS", "5");
        assert_eq!(scheduler_refresh_account_delay_bounds_seconds(), (5, 30));
        std::env::remove_var("SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS");
        std::env::remove_var("SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS");
    }
}

pub async fn refresh_all_quotas_internal(
    proxy_state: &crate::commands::proxy::ProxyServiceState,
) -> Result<RefreshStats, String> {
    let (min_delay_seconds, max_delay_seconds) = scheduler_refresh_account_delay_bounds_seconds();
    let stats = modules::auth::account::refresh_all_quotas_sequential_logic(
        min_delay_seconds,
        max_delay_seconds,
    )
    .await?;

    let instance_lock = proxy_state.instance.read().await;
    if let Some(instance) = instance_lock.as_ref() {
        let _ = instance.token_manager.reload_all_accounts().await;
    }

    Ok(stats)
}

pub async fn clear_log_cache() -> Result<(), String> {
    modules::system::logger::clear_logs()
}
