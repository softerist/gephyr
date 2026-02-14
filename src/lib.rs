mod commands;
pub mod constants;
pub mod error;
mod models;
mod modules;
mod proxy;
#[cfg(test)]
mod test_utils;
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
                    warn!("[W-RUNTIME-NOFILE-LIMIT] failed_to_increase_file_descriptor_limit");
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
    if let Ok(key) = std::env::var("API_KEY") {
        if !key.trim().is_empty() {
            info!("Using API key from environment");
            config.proxy.api_key = key;
        }
    }

    if let Ok(port) = std::env::var("PORT") {
        let trimmed = port.trim();
        if !trimmed.is_empty() {
            match trimmed.parse::<u16>() {
                Ok(p) if p > 0 => {
                    config.proxy.port = p;
                    info!("Using proxy port from environment: {}", p);
                }
                _ => warn!("[W-PORT-INVALID] ignoring_invalid_port_value: {}", port),
            }
        }
    }

    if let Ok(password) = std::env::var("WEB_PASSWORD") {
        if !password.trim().is_empty() {
            info!("Using web admin password from environment");
            config.proxy.admin_password = Some(password);
        }
    }

    if let Ok(mode) = std::env::var("AUTH_MODE") {
        if mode.trim().eq_ignore_ascii_case("auto") {
            warn!(
                "[W-AUTH-MODE-AUTO-DEPRECATED] auth_mode_auto_is_deprecated_coercing_to_strict_in_headless_mode"
            );
            config.proxy.auth_mode = crate::proxy::ProxyAuthMode::Strict;
        } else {
            match parse_auth_mode(&mode) {
                Some(parsed) => {
                    info!("Using auth mode from environment: {:?}", parsed);
                    config.proxy.auth_mode = parsed;
                }
                None => warn!(
                    "[W-AUTH-MODE-INVALID] ignoring_invalid_auth_mode_value: {}",
                    mode
                ),
            }
        }
    }

    if let Ok(allow_lan) = std::env::var("ALLOW_LAN_ACCESS") {
        if let Some(parsed) = parse_env_bool(&allow_lan) {
            config.proxy.allow_lan_access = parsed;
            info!(
                "Using LAN access setting from environment: {}",
                config.proxy.allow_lan_access
            );
        } else {
            warn!(
                "[W-LAN-ACCESS-INVALID] ignoring_invalid_lan_access_value: {}",
                allow_lan
            );
        }
    }
}

fn apply_security_hardening(config: &mut crate::models::AppConfig) {
    if matches!(config.proxy.auth_mode, crate::proxy::ProxyAuthMode::Off) {
        warn!("[W-AUTH-MODE-HARDENED] auth_mode_off_forcing_strict_in_headless_mode");
        config.proxy.auth_mode = crate::proxy::ProxyAuthMode::Strict;
    }
}

async fn start_headless_runtime() -> Result<commands::proxy::ProxyServiceState, String> {
    let proxy_state = commands::proxy::ProxyServiceState::new();
    crate::utils::crypto::validate_encryption_key_prerequisites().map_err(|e| {
        format!(
            "ERROR [E-CRYPTO-KEY-UNAVAILABLE] startup_encryption_preflight_failed: {} Refusing to start because encrypted token/config operations would fail at runtime. In Docker/container environments machine UID may be unavailable. Remediation: set ENCRYPTION_KEY, restart Gephyr, then rerun OAuth login.",
            e
        )
    })?;
    if let Err(e) = crate::modules::auth::account::startup_preflight_verify_persisted_tokens() {
        return Err(format!(
            "ERROR [E-CRYPTO-KEY-MISMATCH] startup_token_decryption_preflight_failed: {} Remediation: ensure ENCRYPTION_KEY matches the key used when these tokens were stored, or run --reencrypt-secrets with the correct key.",
            e
        ));
    }
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
    crate::utils::http::log_tls_startup_diagnostics();
    if let Err(e) = crate::utils::http::run_tls_startup_canary_probe().await {
        if crate::utils::http::tls_canary_required() {
            return Err(format!(
                "ERROR [E-TLS-CANARY-REQUIRED] tls_startup_canary_probe_failed: {}",
                e
            ));
        }
        warn!("[W-TLS-CANARY-FAILED] {}", e);
    }

    info!(
        "Starting headless proxy service on port {}",
        config.proxy.port
    );
    if config.proxy.allow_lan_access {
        warn!("[W-LAN-ACCESS-ENABLED] lan_access_enabled_bind_address_0_0_0_0");
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
    Ok(proxy_state)
}

pub fn run() {
    #[cfg(target_os = "macos")]
    increase_nofile_limit();

    logger::init_logger();

    if let Err(e) = modules::stats::token_stats::init_db() {
        error!(
            "[E-DB-TOKEN-STATS-INIT] failed_to_initialize_token_stats_database: {}",
            e
        );
    }
    if let Err(e) = modules::persistence::security_db::init_db() {
        error!(
            "[E-DB-SECURITY-INIT] failed_to_initialize_security_database: {}",
            e
        );
    }
    if let Err(e) = modules::persistence::user_token_db::init_db() {
        error!(
            "[E-DB-USER-TOKEN-INIT] failed_to_initialize_user_token_database: {}",
            e
        );
    }

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--reencrypt-secrets") {
        info!("Running one-time secret re-encryption utility");
        match commands::crypto::reencrypt_all_secrets() {
            Ok(report) => {
                info!(
                    "Secret re-encryption completed: config_rewritten={}, accounts_total={}, accounts_rewritten={}, accounts_failed={}",
                    report.config_rewritten,
                    report.accounts_total,
                    report.accounts_rewritten,
                    report.accounts_failed
                );
                return;
            }
            Err(e) => {
                error!("[E-SECRET-REENCRYPT] secret_reencryption_failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    if !args.iter().any(|arg| arg == "--headless") {
        warn!("[W-RUNTIME-HEADLESS-DEFAULT] starting_headless_runtime_headless_flag_is_optional");
    }

    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    runtime.block_on(async {
        let proxy_state = match start_headless_runtime().await {
            Ok(state) => state,
            Err(e) => {
                error!("[E-RUNTIME-STARTUP] {}", e);
                std::process::exit(1);
            }
        };

        info!("Headless service is running. Press Ctrl+C to exit.");
        let _ = tokio::signal::ctrl_c().await;
        info!("Shutting down headless service");
        if let Err(e) = commands::proxy::internal_stop_proxy_service(&proxy_state).await {
            warn!(
                "[W-RUNTIME-STOP] failed_to_stop_proxy_service_cleanly: {}",
                e
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{apply_headless_env_overrides, apply_security_hardening, parse_auth_mode};
    use crate::models::AppConfig;
    use crate::proxy::ProxyAuthMode;
    use crate::test_utils::ScopedEnvVar;
    use std::sync::{Mutex, OnceLock};

    static LIB_TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn parse_auth_mode_rejects_auto() {
        assert!(parse_auth_mode("auto").is_none());
    }

    #[test]
    fn headless_env_auto_auth_mode_is_coerced_to_strict() {
        let _guard = LIB_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lib env test lock");
        let _auth_mode = ScopedEnvVar::set("AUTH_MODE", "auto");

        let mut config = AppConfig::default();
        config.proxy.auth_mode = ProxyAuthMode::AllExceptHealth;

        apply_headless_env_overrides(&mut config);
        apply_security_hardening(&mut config);

        assert!(matches!(config.proxy.auth_mode, ProxyAuthMode::Strict));
    }

    #[test]
    fn headless_env_port_overrides_config_port() {
        let _guard = LIB_TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lib env test lock");
        let _port = ScopedEnvVar::set("PORT", "8045");

        let mut config = AppConfig::default();
        config.proxy.port = 8145;
        apply_headless_env_overrides(&mut config);

        assert_eq!(config.proxy.port, 8045);
    }
}