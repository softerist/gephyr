use crate::proxy::ProxyConfig;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub language: String,
    pub theme: String,
    pub auto_refresh: bool,
    pub refresh_interval: i32,
    pub auto_sync: bool,
    pub sync_interval: i32,
    pub default_export_path: Option<String>,
    #[serde(default)]
    pub proxy: ProxyConfig,
    pub antigravity_executable: Option<String>,
    pub antigravity_args: Option<Vec<String>>,
    #[serde(default)]
    pub auto_launch: bool,
    #[serde(default)]
    pub scheduled_warmup: ScheduledWarmupConfig,
    #[serde(default)]
    pub quota_protection: QuotaProtectionConfig,
    #[serde(default)]
    pub pinned_quota_models: PinnedQuotaModelsConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub hidden_menu_items: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledWarmupConfig {
    pub enabled: bool,
    #[serde(default = "default_warmup_models")]
    pub monitored_models: Vec<String>,
}

fn default_warmup_models() -> Vec<String> {
    crate::proxy::common::model_mapping::default_warmup_models()
}

impl ScheduledWarmupConfig {
    pub fn new() -> Self {
        Self {
            enabled: false,
            monitored_models: default_warmup_models(),
        }
    }
}

impl Default for ScheduledWarmupConfig {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaProtectionConfig {
    pub enabled: bool,
    pub threshold_percentage: u32,
    #[serde(default = "default_monitored_models")]
    pub monitored_models: Vec<String>,
}

fn default_monitored_models() -> Vec<String> {
    crate::proxy::common::model_mapping::default_quota_monitored_models()
}

impl QuotaProtectionConfig {
    pub fn new() -> Self {
        Self {
            enabled: false,
            threshold_percentage: 10,
            monitored_models: default_monitored_models(),
        }
    }
}

impl Default for QuotaProtectionConfig {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedQuotaModelsConfig {
    #[serde(default = "default_pinned_models")]
    pub models: Vec<String>,
}

fn default_pinned_models() -> Vec<String> {
    crate::proxy::common::model_mapping::default_pinned_quota_models()
}

impl PinnedQuotaModelsConfig {
    pub fn new() -> Self {
        Self {
            models: default_pinned_models(),
        }
    }
}

impl Default for PinnedQuotaModelsConfig {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    #[serde(default = "default_backoff_steps")]
    pub backoff_steps: Vec<u64>,
}

fn default_backoff_steps() -> Vec<u64> {
    vec![60, 300, 1800, 7200]
}

impl CircuitBreakerConfig {
    pub fn new() -> Self {
        Self {
            enabled: true,
            backoff_steps: default_backoff_steps(),
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl AppConfig {
    pub fn new() -> Self {
        Self {
            language: "en".to_string(),
            theme: "system".to_string(),
            auto_refresh: true,
            refresh_interval: 15,
            auto_sync: false,
            sync_interval: 5,
            default_export_path: None,
            proxy: ProxyConfig::default(),
            antigravity_executable: None,
            antigravity_args: None,
            auto_launch: false,
            scheduled_warmup: ScheduledWarmupConfig::default(),
            quota_protection: QuotaProtectionConfig::default(),
            pinned_quota_models: PinnedQuotaModelsConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            hidden_menu_items: Vec::new(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self::new()
    }
}
