use std::fs;

#[derive(Debug, Clone)]
pub struct ReencryptReport {
    pub config_rewritten: bool,
    pub accounts_total: usize,
    pub accounts_rewritten: usize,
    pub accounts_failed: usize,
    pub failed_accounts: Vec<String>,
}

pub fn reencrypt_all_secrets() -> Result<ReencryptReport, String> {
    let config = crate::modules::system::config::load_app_config()?;
    crate::modules::system::config::save_app_config(&config)?;

    let accounts_dir = crate::modules::auth::account::get_accounts_dir()?;
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
        let rewrite_result =
            crate::modules::auth::account::load_account(&account_id).and_then(|account| {
                crate::modules::auth::account::save_account(&account)?;
                Ok(())
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

#[cfg(test)]
mod tests {
    use super::reencrypt_all_secrets;
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
        let _guard = REENCRYPT_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("reencrypt test lock");

        let data_dir = std::env::temp_dir().join(format!(
            ".gephyr-reencrypt-command-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&data_dir).expect("create temp dir");
        let _data_dir_env = ScopedEnvVar::set("ABV_DATA_DIR", data_dir.to_string_lossy().as_ref());
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
        crate::modules::system::config::save_app_config(&cfg).expect("save config");

        let account_v2 = build_test_account("acct-v2", "v2@example.com");
        crate::modules::auth::account::save_account(&account_v2).expect("save v2 account");

        let account_legacy = build_test_account("acct-legacy", "legacy@example.com");
        crate::modules::auth::account::save_account(&account_legacy).expect("save legacy account");

        let config_path = data_dir.join("config.json");
        let mut config_content = std::fs::read_to_string(&config_path).expect("read config");
        config_content = config_content.replacen("v2:", "", 1);
        std::fs::write(&config_path, config_content).expect("write legacy config");

        let legacy_account_path = data_dir.join("accounts").join("acct-legacy.json");
        let legacy_account_content =
            std::fs::read_to_string(&legacy_account_path).expect("read legacy account file");
        std::fs::write(
            &legacy_account_path,
            legacy_account_content.replace("v2:", ""),
        )
        .expect("write legacy account file");

        let report = reencrypt_all_secrets().expect("reencrypt should succeed");
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

        let loaded_account =
            crate::modules::auth::account::load_account("acct-legacy").expect("load account");
        assert_eq!(loaded_account.email, "legacy@example.com");

        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
