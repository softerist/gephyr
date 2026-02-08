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
        .unwrap_or_else(|_| token_response.access_token.clone());

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
