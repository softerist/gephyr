use crate::models::DeviceProfile;
use crate::modules::system::process;
use rand::{distributions::Alphanumeric, Rng};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const DATA_DIR: &str = ".gephyr";
const GLOBAL_BASELINE: &str = "device_original.json";
const STORAGE_JSON_PATH_ENV: &str = "ANTIGRAVITY_STORAGE_JSON_PATH";

fn get_data_dir() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("failed_to_get_home_dir")?;
    let data_dir = home.join(DATA_DIR);
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir).map_err(|e| format!("failed_to_create_data_dir: {}", e))?;
    }
    Ok(data_dir)
}
pub fn get_storage_path() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var(STORAGE_JSON_PATH_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let storage = PathBuf::from(trimmed);
            if storage.exists() {
                return Ok(storage);
            }
            return Err("storage_json_override_not_found".to_string());
        }
    }

    if let Some(user_data_dir) = process::get_user_data_dir_from_process() {
        let path = user_data_dir
            .join("User")
            .join("globalStorage")
            .join("storage.json");
        if path.exists() {
            return Ok(path);
        }
    }
    if let Some(exe_path) = process::get_antigravity_executable_path() {
        if let Some(parent) = exe_path.parent() {
            let portable = parent
                .join("data")
                .join("user-data")
                .join("User")
                .join("globalStorage")
                .join("storage.json");
            if portable.exists() {
                return Ok(portable);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().ok_or("failed_to_get_home_dir")?;
        let path =
            home.join("Library/Application Support/Antigravity/User/globalStorage/storage.json");
        if path.exists() {
            return Ok(path);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let appdata =
            std::env::var("APPDATA").map_err(|_| "failed_to_get_appdata_env".to_string())?;
        let path = PathBuf::from(appdata).join("Antigravity\\User\\globalStorage\\storage.json");
        if path.exists() {
            return Ok(path);
        }
    }

    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir().ok_or("failed_to_get_home_dir")?;
        let path = home.join(".config/Antigravity/User/globalStorage/storage.json");
        if path.exists() {
            return Ok(path);
        }
    }

    Err("storage_json_not_found".to_string())
}
pub fn read_profile(storage_path: &Path) -> Result<DeviceProfile, String> {
    let content = fs::read_to_string(storage_path)
        .map_err(|e| format!("read_failed ({:?}): {}", storage_path, e))?;
    let json: Value = serde_json::from_str(&content)
        .map_err(|e| format!("parse_failed ({:?}): {}", storage_path, e))?;
    let get_field = |key: &str| -> Option<String> {
        if let Some(obj) = json.get("telemetry").and_then(|v| v.as_object()) {
            if let Some(v) = obj.get(key).and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
        }
        if let Some(v) = json
            .get(format!("telemetry.{key}"))
            .and_then(|v| v.as_str())
        {
            return Some(v.to_string());
        }
        None
    };

    let machine_id = get_field("machineId").ok_or("missing_machine_id")?;
    Ok(DeviceProfile {
        machine_id: Some(machine_id),
        mac_machine_id: get_field("macMachineId"),
        dev_device_id: get_field("devDeviceId"),
        sqm_id: get_field("sqmId"),
    })
}
pub fn load_global_original() -> Option<DeviceProfile> {
    if let Ok(dir) = get_data_dir() {
        let path = dir.join(GLOBAL_BASELINE);
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(profile) = serde_json::from_str::<DeviceProfile>(&content) {
                    return Some(profile);
                }
            }
        }
    }
    None
}

pub fn save_global_original(profile: &DeviceProfile) -> Result<(), String> {
    let dir = get_data_dir()?;
    let path = dir.join(GLOBAL_BASELINE);
    if path.exists() {
        return Ok(());
    }
    let content =
        serde_json::to_string_pretty(profile).map_err(|e| format!("serialize_failed: {}", e))?;
    fs::write(&path, content).map_err(|e| format!("write_failed: {}", e))
}
pub fn generate_profile() -> DeviceProfile {
    DeviceProfile {
        machine_id: Some(format!("auth0|user_{}", random_hex(32))),
        mac_machine_id: Some(new_standard_machine_id()),
        dev_device_id: Some(Uuid::new_v4().to_string()),
        sqm_id: Some(format!("{{{}}}", Uuid::new_v4().to_string().to_uppercase())),
    }
}

fn random_hex(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect::<String>()
        .to_lowercase()
}

fn new_standard_machine_id() -> String {
    let mut rng = rand::thread_rng();
    let mut id = String::with_capacity(36);
    for ch in "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".chars() {
        if ch == '-' || ch == '4' {
            id.push(ch);
        } else if ch == 'x' {
            id.push_str(&format!("{:x}", rng.gen_range(0..16)));
        } else if ch == 'y' {
            id.push_str(&format!("{:x}", rng.gen_range(8..12)));
        }
    }
    id
}
