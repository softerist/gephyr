use serde_json;
use std::fs;

use crate::models::AppConfig;
use crate::modules::auth::account::get_data_dir;

const CONFIG_FILE: &str = "config.json";
pub fn load_app_config() -> Result<AppConfig, String> {
    let data_dir = get_data_dir()?;

    let config_path = data_dir.join(CONFIG_FILE);

    if !config_path.exists() {
        let config = AppConfig::new();
        let _ = save_app_config(&config);
        return Ok(config);
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("failed_to_read_config_file: {}", e))?;

    let mut v: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("failed_to_parse_config_file: {}", e))?;

    let mut modified = false;
    if let Some(proxy) = v.get_mut("proxy") {
        let mut custom_mapping = proxy
            .get("custom_mapping")
            .and_then(|m| m.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(anthropic) = proxy
            .get_mut("anthropic_mapping")
            .and_then(|m| m.as_object_mut())
        {
            for (k, v) in anthropic.iter() {
                if !k.ends_with("-series") && !custom_mapping.contains_key(k) {
                    custom_mapping.insert(k.clone(), v.clone());
                }
            }
            proxy.as_object_mut().unwrap().remove("anthropic_mapping");
            modified = true;
        }
        if let Some(openai) = proxy
            .get_mut("openai_mapping")
            .and_then(|m| m.as_object_mut())
        {
            for (k, v) in openai.iter() {
                if !k.ends_with("-series") && !custom_mapping.contains_key(k) {
                    custom_mapping.insert(k.clone(), v.clone());
                }
            }
            proxy.as_object_mut().unwrap().remove("openai_mapping");
            modified = true;
        }

        if modified {
            proxy.as_object_mut().unwrap().insert(
                "custom_mapping".to_string(),
                serde_json::Value::Object(custom_mapping),
            );
        }
    }

    let config: AppConfig = serde_json::from_value(v)
        .map_err(|e| format!("failed_to_convert_config_after_migration: {}", e))?;
    if modified {
        let _ = save_app_config(&config);
    }

    Ok(config)
}
pub fn save_app_config(config: &AppConfig) -> Result<(), String> {
    let data_dir = get_data_dir()?;
    let config_path = data_dir.join(CONFIG_FILE);

    let content = serde_json::to_string_pretty(config)
        .map_err(|e| format!("failed_to_serialize_config: {}", e))?;

    fs::write(&config_path, content).map_err(|e| format!("failed_to_save_config: {}", e))
}
