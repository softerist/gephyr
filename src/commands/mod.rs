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

pub async fn clear_antigravity_cache() -> Result<modules::system::cache::ClearResult, String> {
    modules::system::cache::clear_antigravity_cache(None)
}

pub async fn get_antigravity_cache_paths() -> Result<Vec<String>, String> {
    Ok(modules::system::cache::get_existing_cache_paths()
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect())
}

pub async fn open_data_folder() -> Result<(), String> {
    Err("Opening the data folder is disabled in headless mode".to_string())
}

pub async fn get_antigravity_path(bypass_config: Option<bool>) -> Result<String, String> {
    if bypass_config != Some(true) {
        if let Ok(config) = crate::modules::system::config::load_app_config() {
            if let Some(path) = config.antigravity_executable {
                if std::path::Path::new(&path).exists() {
                    return Ok(path);
                }
            }
        }
    }

    match crate::modules::system::process::get_antigravity_executable_path() {
        Some(path) => Ok(path.to_string_lossy().to_string()),
        None => Err("Antigravity executable path not found".to_string()),
    }
}

pub async fn get_antigravity_args() -> Result<Vec<String>, String> {
    match crate::modules::system::process::get_args_from_running_process() {
        Some(args) => Ok(args),
        None => Err("No running Antigravity process found".to_string()),
    }
}
