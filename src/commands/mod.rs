pub mod proxy;
pub mod user_token;

use crate::modules;

pub use modules::auth::account::RefreshStats;

pub async fn refresh_all_quotas_internal(
    proxy_state: &crate::commands::proxy::ProxyServiceState,
) -> Result<RefreshStats, String> {
    let stats = modules::auth::account::refresh_all_quotas_logic().await?;

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
