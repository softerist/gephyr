use std::path::Path;

fn truncate_reason(reason: &str, max_len: usize) -> String {
    if reason.len() <= max_len {
        reason.to_string()
    } else {
        format!("{}...", &reason[..max_len - 3])
    }
}

fn read_account_json(path: &Path) -> Result<serde_json::Value, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read account file: {}", e))?;
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse account JSON: {}", e))
}

fn write_account_json(path: &Path, account: &serde_json::Value) -> Result<(), String> {
    let json_str = serde_json::to_string_pretty(account)
        .map_err(|e| format!("Failed to serialize account JSON: {}", e))?;
    std::fs::write(path, json_str).map_err(|e| format!("Failed to write account file: {}", e))
}

pub(crate) fn disable_account(path: &Path, reason: &str) -> Result<(), String> {
    let mut content = read_account_json(path)?;

    let now = chrono::Utc::now().timestamp();
    content["disabled"] = serde_json::Value::Bool(true);
    content["disabled_at"] = serde_json::Value::Number(now.into());
    content["disabled_reason"] = serde_json::Value::String(truncate_reason(reason, 800));

    write_account_json(path, &content)
}

pub(crate) fn save_project_id(path: &Path, project_id: &str) -> Result<(), String> {
    let mut content = read_account_json(path)?;
    content["token"]["project_id"] = serde_json::Value::String(project_id.to_string());
    write_account_json(path, &content)
}

pub(crate) fn save_refreshed_token(
    path: &Path,
    token_response: &crate::modules::auth::oauth::TokenResponse,
) -> Result<(), String> {
    let mut content = read_account_json(path)?;

    let now = chrono::Utc::now().timestamp();
    let encrypted_access = crate::utils::crypto::encrypt_string(&token_response.access_token)
        .map_err(|e| format!("Failed to encrypt refreshed access token: {}", e))?;

    content["token"]["access_token"] = serde_json::Value::String(encrypted_access);
    content["token"]["expires_in"] = serde_json::Value::Number(token_response.expires_in.into());
    content["token"]["expiry_timestamp"] =
        serde_json::Value::Number((now + token_response.expires_in).into());

    write_account_json(path, &content)
}

pub(crate) fn set_validation_block(
    data_dir: &Path,
    account_id: &str,
    block_until: i64,
    reason: &str,
) -> Result<(), String> {
    let path = data_dir
        .join("accounts")
        .join(format!("{}.json", account_id));
    if !path.exists() {
        return Err(format!("Account file not found: {:?}", path));
    }

    let mut account = read_account_json(&path)?;
    account["validation_blocked"] = serde_json::Value::Bool(true);
    account["validation_blocked_until"] =
        serde_json::Value::Number(serde_json::Number::from(block_until));
    account["validation_blocked_reason"] = serde_json::Value::String(reason.to_string());

    write_account_json(&path, &account)
}

pub(crate) fn set_forbidden(data_dir: &Path, account_id: &str) -> Result<(), String> {
    let path = data_dir
        .join("accounts")
        .join(format!("{}.json", account_id));
    if !path.exists() {
        return Err(format!("Account file not found: {:?}", path));
    }

    let mut account = read_account_json(&path)?;

    if let Some(quota) = account.get_mut("quota") {
        quota["is_forbidden"] = serde_json::Value::Bool(true);
    } else {
        account["quota"] = serde_json::json!({
            "models": [],
            "last_updated": chrono::Utc::now().timestamp(),
            "is_forbidden": true
        });
    }

    write_account_json(&path, &account)
}

pub(crate) fn get_quota_reset_time(data_dir: &Path, account_id: &str) -> Option<String> {
    let account_path = data_dir
        .join("accounts")
        .join(format!("{}.json", account_id));
    let content = std::fs::read_to_string(&account_path).ok()?;
    let account: serde_json::Value = serde_json::from_str(&content).ok()?;

    account
        .get("quota")
        .and_then(|q| q.get("models"))
        .and_then(|m| m.as_array())
        .and_then(|models| {
            models
                .iter()
                .filter_map(|m| m.get("reset_time").and_then(|r| r.as_str()))
                .filter(|s| !s.is_empty())
                .min()
                .map(|s| s.to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ScopedEnvVar;
    use std::sync::{Mutex, OnceLock};

    static TOKEN_PERSIST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn save_refreshed_token_persists_encrypted_access_token() {
        let _guard = TOKEN_PERSIST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("token persist env lock");
        let _key = ScopedEnvVar::set("ENCRYPTION_KEY", "token-persistence-test-key");

        let temp_dir = std::env::temp_dir().join(format!(
            ".gephyr-save-refreshed-token-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");
        let account_path = temp_dir.join("account.json");

        let account = serde_json::json!({
            "id": "acct-1",
            "email": "acct@example.com",
            "token": {
                "access_token": "old-access-token",
                "refresh_token": "refresh-token",
                "expires_in": 3600,
                "expiry_timestamp": chrono::Utc::now().timestamp() + 3600
            }
        });
        std::fs::write(
            &account_path,
            serde_json::to_string_pretty(&account).expect("serialize account"),
        )
        .expect("write account");

        let token_response = crate::modules::auth::oauth::TokenResponse {
            access_token: "new-access-token".to_string(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
            refresh_token: None,
            id_token: None,
        };

        save_refreshed_token(&account_path, &token_response).expect("save refreshed token");

        let saved: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&account_path).expect("read saved account"),
        )
        .expect("parse saved account");
        let saved_access = saved["token"]["access_token"]
            .as_str()
            .expect("saved access token string");
        assert_ne!(
            saved_access, "new-access-token",
            "access token should not be stored in plaintext"
        );
        assert!(
            saved_access.starts_with("v2:"),
            "access token should be saved in v2 ciphertext format"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}