use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
static GLOBAL_THINKING_BUDGET_CONFIG: OnceLock<RwLock<ThinkingBudgetConfig>> = OnceLock::new();

#[cfg(test)]
static THINKING_BUDGET_TEST_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

#[cfg(test)]
pub struct ThinkingBudgetTestGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    original: ThinkingBudgetConfig,
}

#[cfg(test)]
impl Drop for ThinkingBudgetTestGuard {
    fn drop(&mut self) {
        update_thinking_budget_config(self.original.clone());
    }
}

#[cfg(test)]
pub fn lock_thinking_budget_for_test() -> ThinkingBudgetTestGuard {
    let lock = THINKING_BUDGET_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("thinking budget test lock poisoned");
    let original = get_thinking_budget_config();
    ThinkingBudgetTestGuard {
        _lock: lock,
        original,
    }
}
pub fn get_thinking_budget_config() -> ThinkingBudgetConfig {
    GLOBAL_THINKING_BUDGET_CONFIG
        .get()
        .and_then(|lock| lock.read().ok())
        .map(|cfg| cfg.clone())
        .unwrap_or_default()
}
pub fn update_thinking_budget_config(config: ThinkingBudgetConfig) {
    if let Some(lock) = GLOBAL_THINKING_BUDGET_CONFIG.get() {
        if let Ok(mut cfg) = lock.write() {
            *cfg = config.clone();
            tracing::info!(
                "[Thinking-Budget] Global config updated: mode={:?}, custom_value={}",
                config.mode,
                config.custom_value
            );
        }
    } else {
        let _ = GLOBAL_THINKING_BUDGET_CONFIG.set(RwLock::new(config.clone()));
        tracing::info!(
            "[Thinking-Budget] Global config initialized: mode={:?}, custom_value={}",
            config.mode,
            config.custom_value
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ProxyAuthMode {
    Off,
    #[default]
    Strict,
    AllExceptHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ZaiDispatchMode {
    #[default]
    Off,
    Exclusive,
    Pooled,
    Fallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZaiModelDefaults {
    #[serde(default = "default_zai_opus_model")]
    pub opus: String,
    #[serde(default = "default_zai_sonnet_model")]
    pub sonnet: String,
    #[serde(default = "default_zai_haiku_model")]
    pub haiku: String,
}

impl Default for ZaiModelDefaults {
    fn default() -> Self {
        Self {
            opus: default_zai_opus_model(),
            sonnet: default_zai_sonnet_model(),
            haiku: default_zai_haiku_model(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZaiMcpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub web_search_enabled: bool,
    #[serde(default)]
    pub web_reader_enabled: bool,
    #[serde(default)]
    pub vision_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZaiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_zai_base_url")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub dispatch_mode: ZaiDispatchMode,
    #[serde(default)]
    pub model_mapping: HashMap<String, String>,
    #[serde(default)]
    pub models: ZaiModelDefaults,
    #[serde(default)]
    pub mcp: ZaiMcpConfig,
}

impl Default for ZaiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: default_zai_base_url(),
            api_key: String::new(),
            dispatch_mode: ZaiDispatchMode::Off,
            model_mapping: HashMap::new(),
            models: ZaiModelDefaults::default(),
            mcp: ZaiMcpConfig::default(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentalConfig {
    #[serde(default = "default_true")]
    pub enable_signature_cache: bool,
    #[serde(default = "default_true")]
    pub enable_tool_loop_recovery: bool,
    #[serde(default = "default_true")]
    pub enable_cross_model_checks: bool,
    #[serde(default = "default_false")]
    pub enable_usage_scaling: bool,
    #[serde(default = "default_threshold_l1")]
    pub context_compression_threshold_l1: f32,
    #[serde(default = "default_threshold_l2")]
    pub context_compression_threshold_l2: f32,
    #[serde(default = "default_threshold_l3")]
    pub context_compression_threshold_l3: f32,
}

impl Default for ExperimentalConfig {
    fn default() -> Self {
        Self {
            enable_signature_cache: true,
            enable_tool_loop_recovery: true,
            enable_cross_model_checks: true,
            enable_usage_scaling: false,
            context_compression_threshold_l1: 0.4,
            context_compression_threshold_l2: 0.55,
            context_compression_threshold_l3: 0.7,
        }
    }
}

fn default_threshold_l1() -> f32 {
    0.4
}
fn default_threshold_l2() -> f32 {
    0.55
}
fn default_threshold_l3() -> f32 {
    0.7
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ThinkingBudgetMode {
    #[default]
    Auto,
    Passthrough,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinkingBudgetConfig {
    #[serde(default)]
    pub mode: ThinkingBudgetMode,
    #[serde(default = "default_thinking_budget_custom_value")]
    pub custom_value: u32,
}

impl Default for ThinkingBudgetConfig {
    fn default() -> Self {
        Self {
            mode: ThinkingBudgetMode::Auto,
            custom_value: default_thinking_budget_custom_value(),
        }
    }
}

fn default_thinking_budget_custom_value() -> u32 {
    24576
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DebugLoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub output_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlacklistConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_block_message")]
    pub block_message: String,
}

impl Default for IpBlacklistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            block_message: default_block_message(),
        }
    }
}

fn default_block_message() -> String {
    "Access denied".to_string()
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpWhitelistConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub whitelist_priority: bool,
}

impl Default for IpWhitelistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            whitelist_priority: true,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityMonitorConfig {
    #[serde(default)]
    pub blacklist: IpBlacklistConfig,
    #[serde(default)]
    pub whitelist: IpWhitelistConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_compliance_global_rpm")]
    pub max_global_requests_per_minute: u32,
    #[serde(default = "default_compliance_account_rpm")]
    pub max_account_requests_per_minute: u32,
    #[serde(default = "default_compliance_account_concurrency")]
    pub max_account_concurrency: usize,
    #[serde(default = "default_compliance_cooldown_seconds")]
    pub risk_cooldown_seconds: u64,
    #[serde(default = "default_compliance_retry_cap")]
    pub max_retry_attempts: usize,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_global_requests_per_minute: default_compliance_global_rpm(),
            max_account_requests_per_minute: default_compliance_account_rpm(),
            max_account_concurrency: default_compliance_account_concurrency(),
            risk_cooldown_seconds: default_compliance_cooldown_seconds(),
            max_retry_attempts: default_compliance_retry_cap(),
        }
    }
}

fn default_compliance_global_rpm() -> u32 {
    120
}

fn default_compliance_account_rpm() -> u32 {
    20
}

fn default_compliance_account_concurrency() -> usize {
    2
}

fn default_compliance_cooldown_seconds() -> u64 {
    300
}

fn default_compliance_retry_cap() -> usize {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CorsMode {
    #[default]
    Strict,
    Permissive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    #[serde(default)]
    pub mode: CorsMode,
    #[serde(default = "default_cors_allowed_origins")]
    pub allowed_origins: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            mode: CorsMode::Strict,
            allowed_origins: default_cors_allowed_origins(),
        }
    }
}

fn default_cors_allowed_origins() -> Vec<String> {
    vec![
        "http://localhost:3000".to_string(),
        "http://127.0.0.1:3000".to_string(),
        "http://localhost:5173".to_string(),
        "http://127.0.0.1:5173".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub enabled: bool,
    #[serde(default)]
    pub allow_lan_access: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub auth_mode: ProxyAuthMode,
    pub port: u16,
    pub api_key: String,
    pub admin_password: Option<String>,
    pub auto_start: bool,
    #[serde(default)]
    pub custom_mapping: std::collections::HashMap<String, String>,
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,
    #[serde(default)]
    pub enable_logging: bool,
    #[serde(default)]
    pub debug_logging: DebugLoggingConfig,
    #[serde(default)]
    pub upstream_proxy: UpstreamProxyConfig,
    #[serde(default)]
    pub zai: ZaiConfig,
    #[serde(default)]
    pub user_agent_override: Option<String>,
    #[serde(default)]
    pub scheduling: crate::proxy::sticky_config::StickySessionConfig,
    #[serde(default = "default_true")]
    pub persist_session_bindings: bool,
    #[serde(default)]
    pub experimental: ExperimentalConfig,
    #[serde(default)]
    pub security_monitor: SecurityMonitorConfig,
    #[serde(default)]
    pub preferred_account_id: Option<String>,
    #[serde(default)]
    pub saved_user_agent: Option<String>,
    #[serde(default)]
    pub thinking_budget: ThinkingBudgetConfig,
    #[serde(default)]
    pub proxy_pool: ProxyPoolConfig,
    #[serde(default)]
    pub compliance: ComplianceConfig,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpstreamProxyConfig {
    pub enabled: bool,
    pub url: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_lan_access: false,
            trusted_proxies: Vec::new(),
            cors: CorsConfig::default(),
            auth_mode: ProxyAuthMode::default(),
            port: 8045,
            api_key: format!("sk-{}", uuid::Uuid::new_v4().simple()),
            admin_password: None,
            auto_start: false,
            custom_mapping: std::collections::HashMap::new(),
            request_timeout: default_request_timeout(),
            enable_logging: true,
            debug_logging: DebugLoggingConfig::default(),
            upstream_proxy: UpstreamProxyConfig::default(),
            zai: ZaiConfig::default(),
            scheduling: crate::proxy::sticky_config::StickySessionConfig::default(),
            persist_session_bindings: true,
            experimental: ExperimentalConfig::default(),
            security_monitor: SecurityMonitorConfig::default(),
            preferred_account_id: None,
            user_agent_override: None,
            saved_user_agent: None,
            thinking_budget: ThinkingBudgetConfig::default(),
            proxy_pool: ProxyPoolConfig::default(),
            compliance: ComplianceConfig::default(),
        }
    }
}

fn default_request_timeout() -> u64 {
    120
}

fn default_zai_base_url() -> String {
    "https://api.z.ai/api/anthropic".to_string()
}

fn default_zai_opus_model() -> String {
    "glm-4.7".to_string()
}

fn default_zai_sonnet_model() -> String {
    "glm-4.7".to_string()
}

fn default_zai_haiku_model() -> String {
    "glm-4.5-air".to_string()
}

impl ProxyConfig {
    pub fn get_bind_address(&self) -> &str {
        if self.allow_lan_access {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    #[serde(
        serialize_with = "crate::utils::crypto::serialize_password",
        deserialize_with = "crate::utils::crypto::deserialize_password"
    )]
    pub password: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub id: String,
    pub name: String,
    pub url: String,
    pub auth: Option<ProxyAuth>,
    pub enabled: bool,
    pub priority: i32,
    pub tags: Vec<String>,
    pub max_accounts: Option<usize>,
    pub health_check_url: Option<String>,
    pub last_check_time: Option<i64>,
    pub is_healthy: bool,
    pub latency: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPoolConfig {
    pub enabled: bool,
    pub proxies: Vec<ProxyEntry>,
    pub health_check_interval: u64,
    pub auto_failover: bool,
    pub strategy: ProxySelectionStrategy,
    #[serde(default)]
    pub account_bindings: HashMap<String, String>,
}

impl Default for ProxyPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxies: Vec::new(),
            health_check_interval: 300,
            auto_failover: true,
            strategy: ProxySelectionStrategy::Priority,
            account_bindings: HashMap::new(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxySelectionStrategy {
    RoundRobin,
    Random,
    Priority,
    LeastConnections,
    WeightedRoundRobin,
}
