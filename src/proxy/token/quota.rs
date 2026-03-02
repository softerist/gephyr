use std::path::PathBuf;
pub(crate) fn calculate_quota_stats(quota: &serde_json::Value) -> Option<i32> {
    let models = quota.get("models").and_then(|m| m.as_array())?;

    let mut max_percentage = 0;
    let mut has_data = false;

    for model in models {
        if let Some(pct) = model.get("percentage").and_then(|v| v.as_i64()) {
            let pct_i32 = pct as i32;
            if pct_i32 > max_percentage {
                max_percentage = pct_i32;
            }
            has_data = true;
        }
    }

    if has_data {
        Some(max_percentage)
    } else {
        None
    }
}
pub(crate) async fn check_and_protect_quota(
    account_json: &mut serde_json::Value,
    account_path: &PathBuf,
) -> bool {
    let config = match crate::modules::system::config::load_app_config() {
        Ok(cfg) => cfg.quota_protection,
        Err(_) => return false,
    };

    if !config.enabled {
        return false;
    }
    let quota = match account_json.get("quota") {
        Some(q) => q.clone(),
        None => return false,
    };
    let is_proxy_disabled = account_json
        .get("proxy_disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let reason = account_json
        .get("proxy_disabled_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if is_proxy_disabled && reason == "quota_protection" {
        return check_and_restore_quota(account_json, account_path, &quota, &config).await;
    }
    let models = match quota.get("models").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => return false,
    };
    let threshold = config.threshold_percentage as i32;
    let mut changed = false;

    for model in models {
        let name = model.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let standard_id = crate::proxy::common::model_mapping::normalize_to_standard_id(name)
            .unwrap_or_else(|| name.to_string());

        if !config.monitored_models.iter().any(|m| m == &standard_id) {
            continue;
        }

        let percentage = model
            .get("percentage")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        let account_id = account_json
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        if percentage <= threshold {
            if trigger_quota_protection(
                account_json,
                &account_id,
                account_path,
                percentage,
                threshold,
                &standard_id,
            )
            .await
            .unwrap_or(false)
            {
                changed = true;
            }
        } else {
            let protected_models = account_json
                .get("protected_models")
                .and_then(|v| v.as_array());
            let is_protected = protected_models
                .is_some_and(|arr| arr.iter().any(|m| m.as_str() == Some(&standard_id as &str)));

            if is_protected
                && restore_quota_protection(account_json, &account_id, account_path, &standard_id)
                    .await
                    .unwrap_or(false)
            {
                changed = true;
            }
        }
    }

    let _ = changed;
    false
}
#[cfg(test)]
pub(crate) fn get_model_quota_from_json(account_path: &PathBuf, model_name: &str) -> Option<i32> {
    let content = std::fs::read_to_string(account_path).ok()?;
    let account: serde_json::Value = serde_json::from_str(&content).ok()?;
    let models = account.get("quota")?.get("models")?.as_array()?;

    for model in models {
        if let Some(name) = model.get("name").and_then(|v| v.as_str()) {
            if crate::proxy::common::model_mapping::normalize_to_standard_id(name)
                .unwrap_or_else(|| name.to_string())
                == model_name
            {
                return model
                    .get("percentage")
                    .and_then(|v| v.as_i64())
                    .map(|p| p as i32);
            }
        }
    }
    None
}
pub(crate) async fn trigger_quota_protection(
    account_json: &mut serde_json::Value,
    account_id: &str,
    account_path: &PathBuf,
    current_val: i32,
    threshold: i32,
    model_name: &str,
) -> Result<bool, String> {
    if account_json.get("protected_models").is_none() {
        account_json["protected_models"] = serde_json::Value::Array(Vec::new());
    }

    let protected_models = account_json["protected_models"].as_array_mut().unwrap();
    if !protected_models
        .iter()
        .any(|m| m.as_str() == Some(model_name))
    {
        protected_models.push(serde_json::Value::String(model_name.to_string()));

        tracing::info!(
            "Model {} of account {} has been added to the protection list due to quota limit ({}% <= {}%)",
            account_id,
            model_name,
            current_val,
            threshold
        );
        std::fs::write(
            account_path,
            serde_json::to_string_pretty(account_json).unwrap(),
        )
        .map_err(|e| format!("Failed to write file: {}", e))?;

        return Ok(true);
    }

    Ok(false)
}
pub(crate) async fn check_and_restore_quota(
    account_json: &mut serde_json::Value,
    account_path: &PathBuf,
    quota: &serde_json::Value,
    config: &crate::models::QuotaProtectionConfig,
) -> bool {
    tracing::info!(
        "Migrating account {} from global quota protection mode to model-level protection mode",
        account_json
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    );

    account_json["proxy_disabled"] = serde_json::Value::Bool(false);
    account_json["proxy_disabled_reason"] = serde_json::Value::Null;
    account_json["proxy_disabled_at"] = serde_json::Value::Null;

    let threshold = config.threshold_percentage as i32;
    let mut protected_list = Vec::new();

    if let Some(models) = quota.get("models").and_then(|m| m.as_array()) {
        for model in models {
            let name = model.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if !config.monitored_models.iter().any(|m| m == name) {
                continue;
            }

            let percentage = model
                .get("percentage")
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as i32;
            if percentage <= threshold {
                protected_list.push(serde_json::Value::String(name.to_string()));
            }
        }
    }

    account_json["protected_models"] = serde_json::Value::Array(protected_list);

    let _ = std::fs::write(
        account_path,
        serde_json::to_string_pretty(account_json).unwrap(),
    );

    false
}
pub(crate) async fn restore_quota_protection(
    account_json: &mut serde_json::Value,
    account_id: &str,
    account_path: &PathBuf,
    model_name: &str,
) -> Result<bool, String> {
    if let Some(arr) = account_json
        .get_mut("protected_models")
        .and_then(|v| v.as_array_mut())
    {
        let original_len = arr.len();
        arr.retain(|m| m.as_str() != Some(model_name));

        if arr.len() < original_len {
            tracing::info!(
                "Quota for model {} of account {} has been restored, removing from protection list",
                account_id,
                model_name
            );
            std::fs::write(
                account_path,
                serde_json::to_string_pretty(account_json).unwrap(),
            )
            .map_err(|e| format!("Failed to write file: {}", e))?;
            return Ok(true);
        }
    }

    Ok(false)
}
