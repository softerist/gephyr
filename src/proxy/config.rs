use serde::{Deserialize, Serialize};
// use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

// ============================================================================
// Global Thinking Budget Configuration Storage
// Used to access configuration within request transform functions (without modifying function signatures)
// ============================================================================
static GLOBAL_THINKING_BUDGET_CONFIG: OnceLock<RwLock<ThinkingBudgetConfig>> = OnceLock::new();

// Get current Thinking Budget configuration
pub fn get_thinking_budget_config() -> ThinkingBudgetConfig {
    GLOBAL_THINKING_BUDGET_CONFIG
        .get()
        .and_then(|lock| lock.read().ok())
        .map(|cfg| cfg.clone())
        .unwrap_or_default()
}

// Update global Thinking Budget configuration
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
        // Initial initialization
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
pub enum ProxyAuthMode {
    Off,
    Strict,
    AllExceptHealth,
    Auto,
}

impl Default for ProxyAuthMode {
    fn default() -> Self {
        Self::Strict
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ZaiDispatchMode {
    // Never use z.ai.
    Off,
    // Use z.ai for all Anthropic protocol requests.
    Exclusive,
    // Treat z.ai as one additional slot in the shared pool.
    Pooled,
    // Use z.ai only when the Google pool is unavailable.
    Fallback,
}

impl Default for ZaiDispatchMode {
    fn default() -> Self {
        Self::Off
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZaiModelDefaults {
    // Default model for "opus" family (when the incoming model is a Claude id).
    #[serde(default = "default_zai_opus_model")]
    pub opus: String,
    // Default model for "sonnet" family (when the incoming model is a Claude id).
    #[serde(default = "default_zai_sonnet_model")]
    pub sonnet: String,
    // Default model for "haiku" family (when the incoming model is a Claude id).
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for ZaiMcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            web_search_enabled: false,
            web_reader_enabled: false,
            vision_enabled: false,
        }
    }
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
    // Optional per-model mapping overrides for Anthropic/Claude model ids.
    // Key: incoming `model` string, Value: upstream z.ai model id (e.g. `glm-4.7`).
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

// Experimental features configuration (Feature Flags)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentalConfig {
    // Enable dual-layer signature cache
    #[serde(default = "default_true")]
    pub enable_signature_cache: bool,

    // Enable tool loop automatic recovery
    #[serde(default = "default_true")]
    pub enable_tool_loop_recovery: bool,

    // Enable cross-model compatibility checks
    #[serde(default = "default_true")]
    pub enable_cross_model_checks: bool,

    // Enable context usage scaling
    // Aggressive mode: scales usage and activates automatic compression to break the 200k limit.
    // Disabled by default to maintain transparency, allowing clients to trigger native compression instructions.
    #[serde(default = "default_false")]
    pub enable_usage_scaling: bool,

    // Context compression threshold L1 (Tool Trimming)
    #[serde(default = "default_threshold_l1")]
    pub context_compression_threshold_l1: f32,

    // Context compression threshold L2 (Thinking Compression)
    #[serde(default = "default_threshold_l2")]
    pub context_compression_threshold_l2: f32,

    // Context compression threshold L3 (Fork + Summary)
    #[serde(default = "default_threshold_l3")]
    pub context_compression_threshold_l3: f32,
}

impl Default for ExperimentalConfig {
    fn default() -> Self {
        Self {
            enable_signature_cache: true,
            enable_tool_loop_recovery: true,
            enable_cross_model_checks: true,
            enable_usage_scaling: false, // Default off, return to transparent mode
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

// Thinking Budget mode
// Controls how to handle the thinking_budget parameter passed by the caller
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ThinkingBudgetMode {
    // Auto-limit: Apply a 24576 upper limit to specific models (Flash/Thinking)
    Auto,
    // Passthrough: Use the value passed by the caller without modification
    Passthrough,
    // Custom: Override all requests with a fixed value set by the user
    Custom,
}

impl Default for ThinkingBudgetMode {
    fn default() -> Self {
        Self::Auto
    }
}

// Thinking Budget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinkingBudgetConfig {
    // Mode selection
    #[serde(default)]
    pub mode: ThinkingBudgetMode,
    // Custom fixed value (only effective when mode=Custom)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugLoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub output_dir: Option<String>,
}

impl Default for DebugLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            output_dir: None,
        }
    }
}

// IP blacklist configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlacklistConfig {
    // Whether to enable blacklist
    #[serde(default)]
    pub enabled: bool,

    // Custom block message
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

// IP whitelist configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpWhitelistConfig {
    // Whether to enable whitelist mode (only allowed whitelist IPs can access when enabled)
    #[serde(default)]
    pub enabled: bool,

    // Whitelist priority mode (whitelist IPs skip blacklist checks)
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

// Security monitor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMonitorConfig {
    // IP blacklist configuration
    #[serde(default)]
    pub blacklist: IpBlacklistConfig,

    // IP whitelist configuration
    #[serde(default)]
    pub whitelist: IpWhitelistConfig,
}

impl Default for SecurityMonitorConfig {
    fn default() -> Self {
        Self {
            blacklist: IpBlacklistConfig::default(),
            whitelist: IpWhitelistConfig::default(),
        }
    }
}

// Reverse proxy service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    // Whether the proxy service is enabled
    pub enabled: bool,

    // Whether LAN access is allowed
    // - false: bind to 127.0.0.1 only (privacy-first default)
    // - true: bind to 0.0.0.0
    #[serde(default)]
    pub allow_lan_access: bool,

    // Authorization policy for the proxy.
    // - off: no auth required
    // - strict: auth required for all routes
    // - all_except_health: auth required for all routes except `/healthz`
    // - auto: secure defaults (currently resolves to strict)
    #[serde(default)]
    pub auth_mode: ProxyAuthMode,

    // Listening port
    pub port: u16,

    // API key used for proxy requests
    pub api_key: String,

    // Optional admin password for management APIs.
    // If empty, the API key is used.
    pub admin_password: Option<String>,

    // Whether to start automatically
    pub auto_start: bool,

    // Custom precise model mapping table (key: original model name, value: target model name)
    #[serde(default)]
    pub custom_mapping: std::collections::HashMap<String, String>,

    // API request timeout (seconds)
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,

    // Whether to enable request logging (monitoring)
    #[serde(default)]
    pub enable_logging: bool,

    // Debug logging configuration (saves full chain)
    #[serde(default)]
    pub debug_logging: DebugLoggingConfig,

    // Upstream proxy configuration
    #[serde(default)]
    pub upstream_proxy: UpstreamProxyConfig,

    // z.ai provider configuration (Anthropic-compatible).
    #[serde(default)]
    pub zai: ZaiConfig,

    // Custom User-Agent header (optional override)
    #[serde(default)]
    pub user_agent_override: Option<String>,

    // Account scheduling configuration (sticky session/rate limit retry)
    #[serde(default)]
    pub scheduling: crate::proxy::sticky_config::StickySessionConfig,

    // Experimental features configuration
    #[serde(default)]
    pub experimental: ExperimentalConfig,

    // Security monitor configuration (IP blacklist/whitelist)
    #[serde(default)]
    pub security_monitor: SecurityMonitorConfig,

    // Preferred account ID for Fixed Account Mode
    // - None: use round-robin mode
    // - Some(account_id): fixed use of specified account
    #[serde(default)]
    pub preferred_account_id: Option<String>,

    // Saved User-Agent string (persisted even when override is disabled)
    #[serde(default)]
    pub saved_user_agent: Option<String>,

    // Thinking Budget configuration
    // Controls how to handle token budget during AI deep thinking
    #[serde(default)]
    pub thinking_budget: ThinkingBudgetConfig,

    // Proxy pool configuration
    #[serde(default)]
    pub proxy_pool: ProxyPoolConfig,
}

// Upstream proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpstreamProxyConfig {
    // Whether to enable
    pub enabled: bool,
    // Proxy address (http://, https://, socks5://)
    pub url: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_lan_access: false, // Local-only by default.
            auth_mode: ProxyAuthMode::default(),
            port: 8045,
            api_key: format!("sk-{}", uuid::Uuid::new_v4().simple()),
            admin_password: None,
            auto_start: false,
            custom_mapping: std::collections::HashMap::new(),
            request_timeout: default_request_timeout(),
            enable_logging: true, // Enabled by default for token stats.
            debug_logging: DebugLoggingConfig::default(),
            upstream_proxy: UpstreamProxyConfig::default(),
            zai: ZaiConfig::default(),
            scheduling: crate::proxy::sticky_config::StickySessionConfig::default(),
            experimental: ExperimentalConfig::default(),
            security_monitor: SecurityMonitorConfig::default(),
            preferred_account_id: None, // Round-robin by default.
            user_agent_override: None,
            saved_user_agent: None,
            thinking_budget: ThinkingBudgetConfig::default(),
            proxy_pool: ProxyPoolConfig::default(),
        }
    }
}

fn default_request_timeout() -> u64 {
    120 // Default 120 seconds.
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
    // Return the bind address.
    // - allow_lan_access = false => "127.0.0.1"
    // - allow_lan_access = true  => "0.0.0.0"
    pub fn get_bind_address(&self) -> &str {
        if self.allow_lan_access {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        }
    }
}


// Proxy authentication info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    #[serde(serialize_with = "crate::utils::crypto::serialize_password", deserialize_with = "crate::utils::crypto::deserialize_password")]
    pub password: String,
}

// Single proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub id: String,                    // Unique identifier
    pub name: String,                  // Display name
    pub url: String,                   // Proxy address (http://, https://, socks5://)
    pub auth: Option<ProxyAuth>,       // Authentication info (optional)
    pub enabled: bool,                 // Whether to enable
    pub priority: i32,                 // Priority (lower value means higher priority)
    pub tags: Vec<String>,             // Tags (e.g., "US", "Residential IP")
    pub max_accounts: Option<usize>,   // Max bound accounts (0 = unlimited)
    pub health_check_url: Option<String>, // Health check URL
    pub last_check_time: Option<i64>,  // Last check time
    pub is_healthy: bool,              // Health status
    pub latency: Option<u64>,          // Latency (ms) 
}

// Proxy pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPoolConfig {
    pub enabled: bool,                 // Whether to enable proxy pool
    // pub mode: ProxyPoolMode,        // [REMOVED] Proxy pool mode, unified into Hybrid logic
    pub proxies: Vec<ProxyEntry>,      // Proxy list
    pub health_check_interval: u64,    // Health check interval (seconds)
    pub auto_failover: bool,           // Auto failover
    pub strategy: ProxySelectionStrategy, // Proxy selection strategy
    // Account-to-proxy binding relationship (account_id -> proxy_id), persistent storage
    #[serde(default)]
    pub account_bindings: HashMap<String, String>,
}

impl Default for ProxyPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            // mode: ProxyPoolMode::Global,
            proxies: Vec::new(),
            health_check_interval: 300,
            auto_failover: true,
            strategy: ProxySelectionStrategy::Priority,
            account_bindings: HashMap::new(),
        }
    }
}



// Proxy selection strategy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxySelectionStrategy {
    // Round-robin: use in turn
    RoundRobin,
    // Random: select randomly
    Random,
    // Priority: sorted by priority field
    Priority,
    // Least Connections: select proxy with fewest current connections
    LeastConnections,
    // Weighted Round-robin: based on health status and priority
    WeightedRoundRobin,
}
