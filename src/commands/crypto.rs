use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ReencryptReport {
    pub config_rewritten: bool,
    pub accounts_total: usize,
    pub accounts_rewritten: usize,
    pub accounts_failed: usize,
    pub failed_accounts: Vec<String>,
}

fn reencrypt_all_secrets_from_data_dir(data_dir: &Path) -> Result<ReencryptReport, String> {
    let config_path = data_dir.join("config.json");
    let config = if config_path.exists() {
        let config_content = fs::read_to_string(&config_path)
            .map_err(|e| format!("failed_to_read_config_for_reencryption: {}", e))?;
        serde_json::from_str::<crate::models::AppConfig>(&config_content)
            .map_err(|e| format!("failed_to_parse_config_for_reencryption: {}", e))?
    } else {
        crate::models::AppConfig::default()
    };
    let rewritten_config = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("failed_to_serialize_config_for_reencryption: {}", e))?;
    fs::write(&config_path, rewritten_config)
        .map_err(|e| format!("failed_to_write_config_for_reencryption: {}", e))?;

    let accounts_dir = data_dir.join("accounts");
    fs::create_dir_all(&accounts_dir)
        .map_err(|e| format!("failed_to_prepare_accounts_dir_for_reencryption: {}", e))?;

    let mut report = ReencryptReport {
        config_rewritten: true,
        accounts_total: 0,
        accounts_rewritten: 0,
        accounts_failed: 0,
        failed_accounts: Vec::new(),
    };

    let entries = fs::read_dir(&accounts_dir)
        .map_err(|e| format!("failed_to_read_accounts_dir_for_reencryption: {}", e))?;
    for entry in entries {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                report.accounts_failed += 1;
                report
                    .failed_accounts
                    .push(format!("read_dir_entry_error: {}", e));
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }

        let Some(account_id) = path
            .file_stem()
            .and_then(|v| v.to_str())
            .map(|v| v.to_string())
        else {
            report.accounts_failed += 1;
            report.failed_accounts.push(format!(
                "invalid_account_file_name: {}",
                path.to_string_lossy()
            ));
            continue;
        };

        report.accounts_total += 1;
        let rewrite_result = fs::read_to_string(&path)
            .map_err(|e| {
                format!(
                    "failed_to_read_account_for_reencryption({account_id}): {}",
                    e
                )
            })
            .and_then(|content| {
                serde_json::from_str::<crate::models::Account>(&content).map_err(|e| {
                    format!(
                        "failed_to_parse_account_for_reencryption({account_id}): {}",
                        e
                    )
                })
            })
            .and_then(|account| {
                serde_json::to_string_pretty(&account).map_err(|e| {
                    format!(
                        "failed_to_serialize_account_for_reencryption({account_id}): {}",
                        e
                    )
                })
            })
            .and_then(|rewritten| {
                fs::write(&path, rewritten).map_err(|e| {
                    format!(
                        "failed_to_write_account_for_reencryption({account_id}): {}",
                        e
                    )
                })
            });

        if rewrite_result.is_ok() {
            report.accounts_rewritten += 1;
        } else {
            report.accounts_failed += 1;
            report.failed_accounts.push(account_id);
        }
    }

    if report.accounts_failed > 0 {
        return Err(format!(
            "secret_reencryption_completed_with_failures: failed={} accounts={:?}",
            report.accounts_failed, report.failed_accounts
        ));
    }

    Ok(report)
}

pub fn reencrypt_all_secrets() -> Result<ReencryptReport, String> {
    let data_dir = crate::modules::auth::account::get_data_dir()?;
    reencrypt_all_secrets_from_data_dir(&data_dir)
}

#[cfg(test)]
mod tests {
    use super::reencrypt_all_secrets_from_data_dir;
    use crate::models::{Account, TokenData};
    use crate::proxy::config::{ProxyAuth, ProxyEntry, ProxySelectionStrategy};
    use std::sync::{Mutex, OnceLock};

    static REENCRYPT_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct ScopedEnvVar {
        key: &'static str,
        original: Option<String>,
    }

    impl ScopedEnvVar {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, original }
        }
    }

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            if let Some(value) = self.original.as_deref() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn build_test_account(id: &str, email: &str) -> Account {
        let token = TokenData::new(
            "access-token".to_string(),
            "refresh-token".to_string(),
            3600,
            Some(email.to_string()),
            None,
            None,
        );
        Account::new(id.to_string(), email.to_string(), token)
    }

    #[test]
    fn reencrypt_command_rewrites_mixed_legacy_and_v2_records() {
        let _security_guard = crate::proxy::tests::acquire_security_test_lock();
        let _guard = REENCRYPT_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("reencrypt test lock");

        let data_dir = std::env::temp_dir().join(format!(
            ".gephyr-reencrypt-command-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&data_dir).expect("create temp dir");
        let _enc_key_env = ScopedEnvVar::set("ABV_ENCRYPTION_KEY", "reencrypt-test-key");

        let mut cfg = crate::models::AppConfig::default();
        cfg.proxy.proxy_pool.enabled = true;
        cfg.proxy.proxy_pool.strategy = ProxySelectionStrategy::Priority;
        cfg.proxy.proxy_pool.proxies = vec![ProxyEntry {
            id: "proxy-1".to_string(),
            name: "proxy-1".to_string(),
            url: "http://127.0.0.1:8080".to_string(),
            auth: Some(ProxyAuth {
                username: "user".to_string(),
                password: "password-secret".to_string(),
            }),
            enabled: true,
            priority: 1,
            tags: vec![],
            max_accounts: None,
            health_check_url: None,
            last_check_time: None,
            is_healthy: true,
            latency: None,
        }];
        let config_path = data_dir.join("config.json");
        let config_content = serde_json::to_string_pretty(&cfg).expect("serialize config");
        std::fs::write(&config_path, config_content).expect("save config");

        let account_v2 = build_test_account("acct-v2", "v2@example.com");
        let account_legacy = build_test_account("acct-legacy", "legacy@example.com");
        let accounts_dir = data_dir.join("accounts");
        std::fs::create_dir_all(&accounts_dir).expect("create accounts dir");
        std::fs::write(
            accounts_dir.join("acct-v2.json"),
            serde_json::to_string_pretty(&account_v2).expect("serialize v2 account"),
        )
        .expect("save v2 account");
        std::fs::write(
            accounts_dir.join("acct-legacy.json"),
            serde_json::to_string_pretty(&account_legacy).expect("serialize legacy account"),
        )
        .expect("save legacy account");

        let mut config_content = std::fs::read_to_string(&config_path).expect("read config");
        config_content = config_content.replacen("v2:", "", 1);
        std::fs::write(&config_path, config_content).expect("write legacy config");

        let legacy_account_path = accounts_dir.join("acct-legacy.json");
        let legacy_account_content =
            std::fs::read_to_string(&legacy_account_path).expect("read legacy account file");
        std::fs::write(
            &legacy_account_path,
            legacy_account_content.replace("v2:", ""),
        )
        .expect("write legacy account file");

        let report =
            reencrypt_all_secrets_from_data_dir(&data_dir).expect("reencrypt should succeed");
        assert!(report.config_rewritten);
        assert_eq!(report.accounts_total, 2);
        assert_eq!(report.accounts_rewritten, 2);
        assert_eq!(report.accounts_failed, 0);

        let rewritten_config =
            std::fs::read_to_string(&config_path).expect("read rewritten config");
        assert!(
            rewritten_config.contains("v2:"),
            "config secrets should be stored in v2 format"
        );

        let rewritten_account =
            std::fs::read_to_string(&legacy_account_path).expect("read rewritten legacy account");
        assert!(
            rewritten_account.contains("v2:"),
            "account secrets should be stored in v2 format"
        );

        let loaded_account: Account = serde_json::from_str(
            &std::fs::read_to_string(&legacy_account_path).expect("read rewritten account"),
        )
        .expect("deserialize rewritten account");
        assert_eq!(loaded_account.email, "legacy@example.com");

        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
