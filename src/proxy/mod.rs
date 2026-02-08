// proxy module - API Reverse Proxy service

// Existing modules (Retained)
pub mod config;
pub mod project_resolver;
pub mod security;
pub mod server;
pub mod state;
pub mod token;
pub mod token_manager;

// New Architecture Modules
pub mod cli_sync; // CLI Config Sync (v3.3.35)
pub mod admin; // Admin handlers extracted from server
pub mod opencode_sync; // OpenCode Config Sync
pub mod common; // Common utilities
pub mod debug_logger;
pub mod health; // Health handlers
pub mod handlers; // API Endpoint Handlers
pub mod mappers; // Protocol Mappers
pub mod middleware; // Axum Middleware
pub mod monitor; // Monitoring
pub mod providers; // Extra upstream providers (z.ai, etc.)
pub mod routes; // Route builders
pub mod rate_limit; // Rate limit tracking
pub mod session_manager; // Session fingerprint management
pub mod signature_cache; // Signature Cache (v3.3.16)
pub mod sticky_config; // Sticky scheduling configuration
pub mod upstream; // Upstream client
pub mod proxy_pool; // Proxy Pool Manager

#[allow(unused_imports)]
pub use config::{
    get_thinking_budget_config,
    update_thinking_budget_config,
    ProxyAuthMode,
    ProxyConfig,
    ProxyPoolConfig,
    ThinkingBudgetConfig,
    ThinkingBudgetMode,
    ZaiConfig,
    ZaiDispatchMode,
};
pub use security::ProxySecurityConfig;
pub use server::AxumServer;
pub use signature_cache::SignatureCache;
pub use token::TokenManager;
#[allow(unused_imports)]
pub use proxy_pool::{ProxyPoolManager, get_global_proxy_pool, init_global_proxy_pool};

#[cfg(test)]
pub mod tests;
