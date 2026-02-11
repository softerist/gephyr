use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::proxy::token::types::ProxyToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnDiskAccountState {
    Enabled,
    Disabled,
    Unknown,
}
pub(crate) async fn get_account_state_on_disk(account_path: &PathBuf) -> OnDiskAccountState {
    const MAX_RETRIES: usize = 2;
    const RETRY_DELAY_MS: u64 = 5;

    for attempt in 0..=MAX_RETRIES {
        let content = match tokio::fs::read_to_string(account_path).await {
            Ok(c) => c,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return OnDiskAccountState::Disabled;
                }
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                    continue;
                }
                tracing::debug!(
                    "Failed to read account file on disk {:?}: {}",
                    account_path,
                    e
                );
                return OnDiskAccountState::Unknown;
            }
        };

        let account = match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(v) => v,
            Err(e) => {
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                    continue;
                }
                tracing::debug!(
                    "Failed to parse account JSON on disk {:?}: {}",
                    account_path,
                    e
                );
                return OnDiskAccountState::Unknown;
            }
        };

        let disabled = account
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || account
                .get("proxy_disabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            || account
                .get("quota")
                .and_then(|q| q.get("is_forbidden"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

        return if disabled {
            OnDiskAccountState::Disabled
        } else {
            OnDiskAccountState::Enabled
        };
    }

    OnDiskAccountState::Unknown
}
pub(crate) fn extract_earliest_reset_time(account: &serde_json::Value) -> Option<i64> {
    let models = account
        .get("quota")
        .and_then(|q| q.get("models"))
        .and_then(|m| m.as_array())?;

    let mut earliest_ts: Option<i64> = None;

    for model in models {
        let model_name = model.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if !model_name.contains("claude") {
            continue;
        }

        if let Some(reset_time_str) = model.get("reset_time").and_then(|r| r.as_str()) {
            if reset_time_str.is_empty() {
                continue;
            }
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(reset_time_str) {
                let ts = dt.timestamp();
                if earliest_ts.is_none_or(|v| ts < v) {
                    earliest_ts = Some(ts);
                }
            }
        }
    }

    if earliest_ts.is_none() {
        for model in models {
            if let Some(reset_time_str) = model.get("reset_time").and_then(|r| r.as_str()) {
                if reset_time_str.is_empty() {
                    continue;
                }
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(reset_time_str) {
                    let ts = dt.timestamp();
                    if earliest_ts.is_none_or(|v| ts < v) {
                        earliest_ts = Some(ts);
                    }
                }
            }
        }
    }

    earliest_ts
}
pub(crate) async fn load_single_account(
    path: &PathBuf,
    health_scores: &dashmap::DashMap<String, f32>,
) -> Result<Option<ProxyToken>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;

    let mut account: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse JSON: {}", e))?;
    let is_proxy_disabled = account
        .get("proxy_disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let disabled_reason = account
        .get("proxy_disabled_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if is_proxy_disabled && disabled_reason != "quota_protection" {
        tracing::debug!(
            "Account skipped due to manual disable: {:?} (email={}, reason={})",
            path,
            account
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>"),
            disabled_reason
        );
        return Ok(None);
    }
    if account
        .get("validation_blocked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let block_until = account
            .get("validation_blocked_until")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        let now = chrono::Utc::now().timestamp();

        if now < block_until {
            tracing::debug!(
                "Skipping validation-blocked account: {:?} (email={}, blocked until {})",
                path,
                account
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unknown>"),
                chrono::DateTime::from_timestamp(block_until, 0)
                    .map(|dt| dt.format("%H:%M:%S").to_string())
                    .unwrap_or_else(|| block_until.to_string())
            );
            return Ok(None);
        } else {
            account["validation_blocked"] = serde_json::json!(false);
            account["validation_blocked_until"] = serde_json::json!(0);
            account["validation_blocked_reason"] = serde_json::Value::Null;

            let updated_json = serde_json::to_string_pretty(&account).map_err(|e| e.to_string())?;
            std::fs::write(path, updated_json).map_err(|e| e.to_string())?;
            tracing::info!(
                "Validation block expired and cleared for account: {}",
                account
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unknown>")
            );
        }
    }

    if account
        .get("disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        tracing::debug!(
            "Skipping disabled account file: {:?} (email={})",
            path,
            account
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>")
        );
        return Ok(None);
    }

    if get_account_state_on_disk(path).await == OnDiskAccountState::Disabled {
        tracing::debug!("Account file {:?} is disabled on disk, skipping.", path);
        return Ok(None);
    }

    if crate::proxy::token::quota::check_and_protect_quota(&mut account, path).await {
        tracing::debug!(
            "Account skipped due to quota protection: {:?} (email={})",
            path,
            account
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>")
        );
        return Ok(None);
    }

    if account
        .get("proxy_disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        tracing::debug!(
            "Skipping proxy-disabled account file: {:?} (email={})",
            path,
            account
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>")
        );
        return Ok(None);
    }

    let account_id = account["id"]
        .as_str()
        .ok_or("Missing id field")?
        .to_string();
    let email = account["email"]
        .as_str()
        .ok_or("Missing email field")?
        .to_string();

    let token_obj = account["token"].as_object().ok_or("Missing token field")?;

    let access_token_raw = token_obj["access_token"]
        .as_str()
        .ok_or("Missing access_token")?;
    let access_token = match crate::utils::crypto::decrypt_secret_or_plaintext(access_token_raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "Failed to decrypt access_token for account file {:?}: {}",
                path,
                e
            );
            return Err(format!("Failed to decrypt access_token: {}", e));
        }
    };

    let refresh_token_raw = token_obj["refresh_token"]
        .as_str()
        .ok_or("Missing refresh_token")?;
    let refresh_token = match crate::utils::crypto::decrypt_secret_or_plaintext(refresh_token_raw)
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "Failed to decrypt refresh_token for account file {:?}: {}",
                path,
                e
            );
            return Err(format!("Failed to decrypt refresh_token: {}", e));
        }
    };

    let expires_in = token_obj["expires_in"]
        .as_i64()
        .ok_or("Missing expires_in")?;
    let timestamp = token_obj["expiry_timestamp"]
        .as_i64()
        .ok_or("Missing expiry_timestamp")?;

    let project_id = token_obj
        .get("project_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let subscription_tier = account
        .get("quota")
        .and_then(|q| q.get("subscription_tier"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let remaining_quota = account
        .get("quota")
        .and_then(crate::proxy::token::quota::calculate_quota_stats);

    let protected_models: HashSet<String> = account
        .get("protected_models")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let health_score = health_scores.get(&account_id).map(|v| *v).unwrap_or(1.0);
    let reset_time = extract_earliest_reset_time(&account);

    let mut model_quotas = HashMap::new();
    if let Some(models) = account
        .get("quota")
        .and_then(|q| q.get("models"))
        .and_then(|m| m.as_array())
    {
        for model in models {
            if let (Some(name), Some(pct)) = (
                model.get("name").and_then(|v| v.as_str()),
                model.get("percentage").and_then(|v| v.as_i64()),
            ) {
                let standard_id =
                    crate::proxy::common::model_mapping::normalize_to_standard_id(name)
                        .unwrap_or_else(|| name.to_string());
                model_quotas.insert(standard_id, pct as i32);
            }
        }
    }

    Ok(Some(ProxyToken {
        account_id,
        access_token,
        refresh_token,
        expires_in,
        timestamp,
        email,
        account_path: path.clone(),
        project_id,
        subscription_tier,
        remaining_quota,
        protected_models,
        health_score,
        reset_time,
        validation_blocked: account
            .get("validation_blocked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        validation_blocked_until: account
            .get("validation_blocked_until")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        model_quotas,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;

    fn write_account_fixture(access_token: &str, refresh_token: &str) -> std::path::PathBuf {
        let temp_dir = std::env::temp_dir().join(format!(
            ".gephyr-loader-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");
        let account_path = temp_dir.join("acct-1.json");

        let account = serde_json::json!({
            "id": "acct-1",
            "email": "acct@example.com",
            "token": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 3600,
                "expiry_timestamp": chrono::Utc::now().timestamp() + 3600
            }
        });
        std::fs::write(
            &account_path,
            serde_json::to_string_pretty(&account).expect("serialize fixture account"),
        )
        .expect("write fixture account");

        account_path
    }

    #[tokio::test]
    async fn load_single_account_accepts_plaintext_tokens() {
        let account_path = write_account_fixture("plain-access-token", "plain-refresh-token");
        let health_scores: DashMap<String, f32> = DashMap::new();

        let loaded = load_single_account(&account_path, &health_scores)
            .await
            .expect("load account")
            .expect("account should be enabled");
        assert_eq!(loaded.access_token, "plain-access-token");
        assert_eq!(loaded.refresh_token, "plain-refresh-token");

        let parent = account_path.parent().expect("parent dir").to_path_buf();
        let _ = std::fs::remove_dir_all(parent);
    }

    #[tokio::test]
    async fn load_single_account_rejects_invalid_v2_prefixed_token() {
        let account_path = write_account_fixture("v2:abc", "plain-refresh-token");
        let health_scores: DashMap<String, f32> = DashMap::new();

        let err = load_single_account(&account_path, &health_scores)
            .await
            .expect_err("invalid v2 token should fail");
        assert!(err.contains("Failed to decrypt access_token"));

        let parent = account_path.parent().expect("parent dir").to_path_buf();
        let _ = std::fs::remove_dir_all(parent);
    }
}
