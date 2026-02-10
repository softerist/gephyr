mod commands;
pub mod constants;
pub mod error;
mod models;
mod modules;
mod proxy;
mod utils;

use modules::system::logger;
use tracing::{error, info, warn};
#[cfg(target_os = "macos")]
fn increase_nofile_limit() {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            info!(
                "Current open file limit: soft={}, hard={}",
                rl.rlim_cur, rl.rlim_max
            );
            let target = 4096.min(rl.rlim_max);
            if rl.rlim_cur < target {
                rl.rlim_cur = target;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) == 0 {
                    info!("Successfully increased hard file limit to {}", target);
                } else {
                    warn!("Failed to increase file descriptor limit");
                }
            }
        }
    }
}

fn parse_env_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_auth_mode(value: &str) -> Option<crate::proxy::ProxyAuthMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(crate::proxy::ProxyAuthMode::Off),
        "strict" => Some(crate::proxy::ProxyAuthMode::Strict),
        "all_except_health" => Some(crate::proxy::ProxyAuthMode::AllExceptHealth),
        _ => None,
    }
}

fn apply_headless_env_overrides(config: &mut crate::models::AppConfig) {
    if let Ok(key) = std::env::var("ABV_API_KEY").or_else(|_| std::env::var("API_KEY")) {
        if !key.trim().is_empty() {
            info!("Using API key from environment");
            config.proxy.api_key = key;
        }
    }

    if let Ok(password) =
        std::env::var("ABV_WEB_PASSWORD").or_else(|_| std::env::var("WEB_PASSWORD"))
    {
        if !password.trim().is_empty() {
            info!("Using web admin password from environment");
            config.proxy.admin_password = Some(password);
        }
    }

    if let Ok(mode) = std::env::var("ABV_AUTH_MODE").or_else(|_| std::env::var("AUTH_MODE")) {
        if mode.trim().eq_ignore_ascii_case("auto") {
            warn!("Auth mode 'auto' is deprecated; coercing to 'strict' in headless mode");
            config.proxy.auth_mode = crate::proxy::ProxyAuthMode::Strict;
        } else {
            match parse_auth_mode(&mode) {
                Some(parsed) => {
                    info!("Using auth mode from environment: {:?}", parsed);
                    config.proxy.auth_mode = parsed;
                }
                None => warn!("Ignoring invalid auth mode value: {}", mode),
            }
        }
    }

    if let Ok(allow_lan) =
        std::env::var("ABV_ALLOW_LAN_ACCESS").or_else(|_| std::env::var("ALLOW_LAN_ACCESS"))
    {
        if let Some(parsed) = parse_env_bool(&allow_lan) {
            config.proxy.allow_lan_access = parsed;
            info!(
                "Using LAN access setting from environment: {}",
                config.proxy.allow_lan_access
            );
        } else {
            warn!("Ignoring invalid LAN access value: {}", allow_lan);
        }
    }
}

fn apply_security_hardening(config: &mut crate::models::AppConfig) {
    if matches!(config.proxy.auth_mode, crate::proxy::ProxyAuthMode::Off) {
        warn!("Auth mode was Off, forcing Strict in headless mode");
        config.proxy.auth_mode = crate::proxy::ProxyAuthMode::Strict;
    }
}

async fn start_headless_runtime() -> Result<(), String> {
    let proxy_state = commands::proxy::ProxyServiceState::new();
    let mut config = modules::system::config::load_app_config()
        .map_err(|e| format!("failed_to_load_config_for_headless_mode: {}", e))?;

    apply_headless_env_overrides(&mut config);
    apply_security_hardening(&mut config);
    modules::system::validation::validate_app_config(&config).map_err(|errors| {
        format!(
            "configuration_validation_failed:\n{}",
            errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;

    info!(
        "Starting headless proxy service on port {}",
        config.proxy.port
    );
    if config.proxy.allow_lan_access {
        warn!("LAN access is enabled (bind address will be 0.0.0.0)");
    } else {
        info!("LAN access is disabled (bind address will be 127.0.0.1)");
    }

    commands::proxy::internal_start_proxy_service(
        config.proxy,
        &proxy_state,
        crate::modules::system::integration::SystemManager::Headless,
    )
    .await
    .map_err(|e| format!("failed_to_start_headless_proxy_service: {}", e))?;

    modules::system::scheduler::start_scheduler(proxy_state.clone());
    info!("Headless scheduler started");
    Ok(())
}

pub fn run() {
    #[cfg(target_os = "macos")]
    increase_nofile_limit();

    logger::init_logger();

    if let Err(e) = modules::stats::token_stats::init_db() {
        error!("Failed to initialize token stats database: {}", e);
    }
    if let Err(e) = modules::persistence::security_db::init_db() {
        error!("Failed to initialize security database: {}", e);
    }
    if let Err(e) = modules::persistence::user_token_db::init_db() {
        error!("Failed to initialize user token database: {}", e);
    }

    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|arg| arg == "--headless") {
        warn!("Starting headless runtime (`--headless` is optional).");
    }

    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    runtime.block_on(async {
        if let Err(e) = start_headless_runtime().await {
            error!("{}", e);
            std::process::exit(1);
        }

        info!("Headless service is running. Press Ctrl+C to exit.");
        let _ = tokio::signal::ctrl_c().await;
        info!("Shutting down headless service");
    });
}
