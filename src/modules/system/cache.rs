use crate::modules::system::logger;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearResult {
    pub cleared_paths: Vec<String>,
    pub total_size_freed: u64,
    pub errors: Vec<String>,
}
pub fn get_antigravity_cache_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            paths.push(home.join("Library/HTTPStorages/com.google.antigravity"));
            paths.push(home.join("Library/Caches/com.google.antigravity"));
            paths.push(home.join(".antigravity"));
            paths.push(home.join(".config/antigravity"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let local_path = PathBuf::from(&local_app_data);
            paths.push(local_path.join("Google\\Antigravity"));
            paths.push(local_path.join("Antigravity\\Cache"));
        }
        if let Ok(app_data) = std::env::var("APPDATA") {
            let app_path = PathBuf::from(&app_data);
            paths.push(app_path.join("Antigravity\\Cache"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = dirs::home_dir() {
            paths.push(home.join(".cache/Antigravity"));
            paths.push(home.join(".cache/google-antigravity"));
            paths.push(home.join(".antigravity"));
        }
        if let Ok(xdg_cache) = std::env::var("XDG_CACHE_HOME") {
            let cache_path = PathBuf::from(&xdg_cache);
            paths.push(cache_path.join("Antigravity"));
            paths.push(cache_path.join("google-antigravity"));
        }
    }

    paths
}
pub fn get_existing_cache_paths() -> Vec<PathBuf> {
    get_antigravity_cache_paths()
        .into_iter()
        .filter(|p| p.exists())
        .collect()
}
fn get_dir_size(path: &PathBuf) -> u64 {
    let mut size = 0u64;

    if path.is_file() {
        if let Ok(metadata) = fs::metadata(path) {
            return metadata.len();
        }
        return 0;
    }

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() {
                if let Ok(metadata) = fs::metadata(&entry_path) {
                    size += metadata.len();
                }
            } else if entry_path.is_dir() {
                size += get_dir_size(&entry_path);
            }
        }
    }

    size
}
fn clear_directory(path: &PathBuf) -> Result<u64, String> {
    if !path.exists() {
        return Ok(0);
    }

    let size = get_dir_size(path);
    fs::remove_dir_all(path).map_err(|e| format!("Failed to remove {}: {}", path.display(), e))?;

    Ok(size)
}
pub fn clear_antigravity_cache(custom_paths: Option<Vec<String>>) -> Result<ClearResult, String> {
    let paths: Vec<PathBuf> = match custom_paths {
        Some(custom) => custom.into_iter().map(PathBuf::from).collect(),
        None => get_antigravity_cache_paths(),
    };

    logger::log_info(&format!(
        "Starting Antigravity cache clearing, {} potential paths",
        paths.len()
    ));

    let mut result = ClearResult {
        cleared_paths: Vec::new(),
        total_size_freed: 0,
        errors: Vec::new(),
    };

    for path in paths {
        if !path.exists() {
            logger::log_info(&format!(
                "Cache path does not exist, skipping: {}",
                path.display()
            ));
            continue;
        }

        logger::log_info(&format!("Clearing cache: {}", path.display()));

        match clear_directory(&path) {
            Ok(size) => {
                result
                    .cleared_paths
                    .push(path.to_string_lossy().to_string());
                result.total_size_freed += size;
                logger::log_info(&format!(
                    "Cleared {}: {:.2} MB freed",
                    path.display(),
                    size as f64 / 1024.0 / 1024.0
                ));
            }
            Err(e) => {
                logger::log_warn(&format!("Failed to clear {}: {}", path.display(), e));
                result.errors.push(e);
            }
        }
    }

    let total_mb = result.total_size_freed as f64 / 1024.0 / 1024.0;
    logger::log_info(&format!(
        "Antigravity cache clearing completed: {} paths cleared, {:.2} MB freed, {} errors",
        result.cleared_paths.len(),
        total_mb,
        result.errors.len()
    ));

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cache_paths_not_empty() {
        let paths = get_antigravity_cache_paths();
        assert!(!paths.is_empty(), "Should return at least one cache path");
    }

    #[test]
    fn test_clear_result_serialization() {
        let result = ClearResult {
            cleared_paths: vec!["/test/path".to_string()],
            total_size_freed: 1024,
            errors: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("cleared_paths"));
        assert!(json.contains("total_size_freed"));
    }
}