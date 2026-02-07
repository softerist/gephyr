use crate::models::AppConfig;
use crate::modules::{account, config, logger, migration, proxy_db, security_db, token_stats};
use crate::proxy::TokenManager;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;
use tracing::{debug, error};

// Global pending account reload queue
// When update_account_quota updates protected_models, add account ID to this queue
// TokenManager checks and processes these accounts during get_token
static PENDING_RELOAD_ACCOUNTS: OnceLock<std::sync::RwLock<HashSet<String>>> = OnceLock::new();

// Global pending account deletion queue 
// When an account is deleted, add account ID to this queue; TokenManager will check and clean the memory cache during get_token
static PENDING_DELETE_ACCOUNTS: OnceLock<std::sync::RwLock<HashSet<String>>> = OnceLock::new();

fn get_pending_reload_accounts() -> &'static std::sync::RwLock<HashSet<String>> {
    PENDING_RELOAD_ACCOUNTS.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

fn get_pending_delete_accounts() -> &'static std::sync::RwLock<HashSet<String>> {
    PENDING_DELETE_ACCOUNTS.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

// Trigger account reload signal (for update_account_quota)
pub fn trigger_account_reload(account_id: &str) {
    if let Ok(mut pending) = get_pending_reload_accounts().write() {
        pending.insert(account_id.to_string());
        tracing::debug!(
            "[Quota] Queued account {} for TokenManager reload",
            account_id
        );
    }
}

// Trigger account deletion signal 
pub fn trigger_account_delete(account_id: &str) {
    if let Ok(mut pending) = get_pending_delete_accounts().write() {
        pending.insert(account_id.to_string());
        tracing::debug!(
            "[Proxy] Queued account {} for cache removal",
            account_id
        );
    }
}

// Get and clear the list of pending reload accounts (for TokenManager)
pub fn take_pending_reload_accounts() -> Vec<String> {
    if let Ok(mut pending) = get_pending_reload_accounts().write() {
        let accounts: Vec<String> = pending.drain().collect();
        if !accounts.is_empty() {
            tracing::debug!(
                "[Quota] Taking {} pending accounts for reload",
                accounts.len()
            );
        }
        accounts
    } else {
        Vec::new()
    }
}

// Get and clear the list of pending delete accounts 
pub fn take_pending_delete_accounts() -> Vec<String> {
    if let Ok(mut pending) = get_pending_delete_accounts().write() {
        let accounts: Vec<String> = pending.drain().collect();
        if !accounts.is_empty() {
            tracing::debug!(
                "[Proxy] Taking {} pending accounts for cache removal",
                accounts.len()
            );
        }
        accounts
    } else {
        Vec::new()
    }
}

// Axum application state
#[derive(Clone)]
pub struct AppState {
    pub token_manager: Arc<TokenManager>,
    pub custom_mapping: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    #[allow(dead_code)]
    pub request_timeout: u64, // API request timeout (seconds)
    #[allow(dead_code)]
    pub thought_signature_map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>, // Thinking signature mapping (ID -> Signature)
    #[allow(dead_code)]
    pub upstream_proxy: Arc<tokio::sync::RwLock<crate::proxy::config::UpstreamProxyConfig>>,
    pub upstream: Arc<crate::proxy::upstream::client::UpstreamClient>,
    pub zai: Arc<RwLock<crate::proxy::ZaiConfig>>,
    pub provider_rr: Arc<AtomicUsize>,
    pub monitor: Arc<crate::proxy::monitor::ProxyMonitor>,
    pub experimental: Arc<RwLock<crate::proxy::config::ExperimentalConfig>>,
    pub debug_logging: Arc<RwLock<crate::proxy::config::DebugLoggingConfig>>,
    pub switching: Arc<RwLock<bool>>, // Account switching state, used to prevent concurrent switching
    pub integration: crate::modules::integration::SystemManager, // System integration layer implementation
    pub account_service: Arc<crate::modules::account_service::AccountService>, // Account management service layer
    pub security: Arc<RwLock<crate::proxy::ProxySecurityConfig>>,              // Security configuration state
    pub is_running: Arc<RwLock<bool>>, // Running state flag
    pub port: u16,                     // Local listening port
    pub proxy_pool_state: Arc<tokio::sync::RwLock<crate::proxy::config::ProxyPoolConfig>>, //
    pub proxy_pool_manager: Arc<crate::proxy::proxy_pool::ProxyPoolManager>, //
}

// Implement FromRef for AppState to allow middleware to extract security state
impl axum::extract::FromRef<AppState> for Arc<RwLock<crate::proxy::ProxySecurityConfig>> {
    fn from_ref(state: &AppState) -> Self {
        state.security.clone()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct AccountResponse {
    id: String,
    email: String,
    name: Option<String>,
    is_current: bool,
    disabled: bool,
    disabled_reason: Option<String>,
    disabled_at: Option<i64>,
    proxy_disabled: bool,
    proxy_disabled_reason: Option<String>,
    proxy_disabled_at: Option<i64>,
    protected_models: Vec<String>,
    // 403 validation blocking status
    validation_blocked: bool,
    validation_blocked_until: Option<i64>,
    validation_blocked_reason: Option<String>,
    quota: Option<QuotaResponse>,
    device_bound: bool,
    last_used: i64,
}

#[derive(Serialize)]
struct QuotaResponse {
    models: Vec<ModelQuota>,
    last_updated: i64,
    subscription_tier: Option<String>,
    is_forbidden: bool,
}

#[derive(Serialize)]
struct ModelQuota {
    name: String,
    percentage: i32,
    reset_time: String,
}

#[derive(Serialize)]
struct AccountListResponse {
    accounts: Vec<AccountResponse>,
    current_account_id: Option<String>,
}

fn to_account_response(
    account: &crate::models::account::Account,
    current_id: &Option<String>,
) -> AccountResponse {
    AccountResponse {
        id: account.id.clone(),
        email: account.email.clone(),
        name: account.name.clone(),
        is_current: current_id.as_ref() == Some(&account.id),
        disabled: account.disabled,
        disabled_reason: account.disabled_reason.clone(),
        disabled_at: account.disabled_at,
        proxy_disabled: account.proxy_disabled,
        proxy_disabled_reason: account.proxy_disabled_reason.clone(),
        proxy_disabled_at: account.proxy_disabled_at,
        protected_models: account.protected_models.iter().cloned().collect(),
        quota: account.quota.as_ref().map(|q| QuotaResponse {
            models: q
                .models
                .iter()
                .map(|m| ModelQuota {
                    name: m.name.clone(),
                    percentage: m.percentage,
                    reset_time: m.reset_time.clone(),
                })
                .collect(),
            last_updated: q.last_updated,
            subscription_tier: q.subscription_tier.clone(),
            is_forbidden: q.is_forbidden,
        }),
        device_bound: account.device_profile.is_some(),
        last_used: account.last_used,
        validation_blocked: account.validation_blocked,
        validation_blocked_until: account.validation_blocked_until,
        validation_blocked_reason: account.validation_blocked_reason.clone(),
    }
}

// Axum server instance
#[derive(Clone)]
pub struct AxumServer {
    pub is_running: Arc<RwLock<bool>>,
    pub token_manager: Arc<TokenManager>,
}

impl AxumServer {
    pub async fn set_running(&self, running: bool) {
        let mut r = self.is_running.write().await;
        *r = running;
        tracing::info!("Proxy service running status updated to: {}", running);
    }

    // Start Axum server
    pub async fn start(
        host: String,
        port: u16,
        token_manager: Arc<TokenManager>,
        custom_mapping: std::collections::HashMap<String, String>,
        _request_timeout: u64,
        upstream_proxy: crate::proxy::config::UpstreamProxyConfig,
        user_agent_override: Option<String>,
        security_config: crate::proxy::ProxySecurityConfig,
        zai_config: crate::proxy::ZaiConfig,
        monitor: Arc<crate::proxy::monitor::ProxyMonitor>,
        experimental_config: crate::proxy::config::ExperimentalConfig,
        debug_logging: crate::proxy::config::DebugLoggingConfig,

        integration: crate::modules::integration::SystemManager,
        proxy_pool_config: crate::proxy::config::ProxyPoolConfig, // 
    ) -> Result<(Self, tokio::task::JoinHandle<()>), String> {
        let custom_mapping_state = Arc::new(tokio::sync::RwLock::new(custom_mapping));
        let proxy_state = Arc::new(tokio::sync::RwLock::new(upstream_proxy.clone()));
        let proxy_pool_state = Arc::new(tokio::sync::RwLock::new(proxy_pool_config));
        let proxy_pool_manager = crate::proxy::proxy_pool::init_global_proxy_pool(proxy_pool_state.clone());
    
    // Start health check loop
    proxy_pool_manager.clone().start_health_check_loop();
        let security_state = Arc::new(RwLock::new(security_config));
        let zai_state = Arc::new(RwLock::new(zai_config));
        let provider_rr = Arc::new(AtomicUsize::new(0));
        let experimental_state = Arc::new(RwLock::new(experimental_config));
        let debug_logging_state = Arc::new(RwLock::new(debug_logging));
        let is_running_state = Arc::new(RwLock::new(true));

        let state = AppState {
            token_manager: token_manager.clone(),
            custom_mapping: custom_mapping_state.clone(),
            request_timeout: 300, // 5 minutes timeout
            thought_signature_map: Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            upstream_proxy: proxy_state.clone(),
            upstream: {
                let u = Arc::new(crate::proxy::upstream::client::UpstreamClient::new(
                    Some(upstream_proxy.clone()),
                    Some(proxy_pool_manager.clone()),
                ));
                // Initialize User-Agent override
                if user_agent_override.is_some() {
                    u.set_user_agent_override(user_agent_override).await;
                }
                u
            },
            zai: zai_state.clone(),
            provider_rr: provider_rr.clone(),
            monitor: monitor.clone(),
            experimental: experimental_state.clone(),
            debug_logging: debug_logging_state.clone(),
            switching: Arc::new(RwLock::new(false)),
            integration: integration.clone(),
            account_service: Arc::new(crate::modules::account_service::AccountService::new(
                integration.clone(),
            )),
            security: security_state.clone(),
            is_running: is_running_state.clone(),
            port,
            proxy_pool_state: proxy_pool_state.clone(),
            proxy_pool_manager: proxy_pool_manager.clone(),
        };

        // Build routes - using the new architecture handlers!
        use crate::proxy::handlers;
        use crate::proxy::middleware::{
            admin_auth_middleware, auth_middleware, cors_layer, ip_filter_middleware,
            monitor_middleware, service_status_middleware,
        };

        // 1. Build main AI proxy routes (following auth_mode configuration)
        let proxy_routes = Router::new()
            .route("/health", get(health_check_handler))
            .route("/healthz", get(health_check_handler))
            // OpenAI Protocol
            .route("/v1/models", get(handlers::openai::handle_list_models))
            .route(
                "/v1/chat/completions",
                post(handlers::openai::handle_chat_completions),
            )
            .route(
                "/v1/completions",
                post(handlers::openai::handle_completions),
            )
            .route("/v1/responses", post(handlers::openai::handle_completions)) // Compatible with Codex CLI
            // Claude Protocol
            .route("/v1/messages", post(handlers::claude::handle_messages))
            .route(
                "/v1/messages/count_tokens",
                post(handlers::claude::handle_count_tokens),
            )
            .route(
                "/v1/models/claude",
                get(handlers::claude::handle_list_models),
            )
            // Gemini Protocol (Native)
            .route("/v1beta/models", get(handlers::gemini::handle_list_models))
            // Handle both GET (get info) and POST (generateContent with colon) at the same route
            .route(
                "/v1beta/models/:model",
                get(handlers::gemini::handle_get_model).post(handlers::gemini::handle_generate),
            )
            .route(
                "/v1beta/models/:model/countTokens",
                post(handlers::gemini::handle_count_tokens),
            ) // Specific route priority
            .route(
                "/v1/models/detect",
                post(handlers::common::handle_detect_model),
            )
            // Apply AI service specific layers
            // Note: Axum layer execution order is bottom-up (onion model)
            // Request: ip_filter -> auth -> monitor -> handler
            // Response: handler -> monitor -> auth -> ip_filter
            // monitor needs to execute after auth to obtain UserTokenIdentity
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                monitor_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                ip_filter_middleware,
            ));

        // 2. Build Admin API (Mandatory authentication)
        let admin_routes = Router::new()
            .route("/health", get(health_check_handler))
            .route(
                "/accounts",
                get(admin_list_accounts).post(admin_add_account),
            )
            .route("/accounts/current", get(admin_get_current_account))
            .route("/accounts/switch", post(admin_switch_account))
            .route("/accounts/refresh", post(admin_refresh_all_quotas))
            .route("/accounts/:accountId", delete(admin_delete_account))
            .route("/accounts/:accountId/bind-device", post(admin_bind_device))
            .route(
                "/accounts/:accountId/device-profiles",
                get(admin_get_device_profiles),
            )
            .route(
                "/accounts/:accountId/device-versions",
                get(admin_list_device_versions),
            )
            .route(
                "/accounts/device-preview",
                post(admin_preview_generate_profile),
            )
            .route(
                "/accounts/:accountId/bind-device-profile",
                post(admin_bind_device_profile_with_profile),
            )
            .route(
                "/accounts/restore-original",
                post(admin_restore_original_device),
            )
            .route(
                "/accounts/:accountId/device-versions/:versionId/restore",
                post(admin_restore_device_version),
            )
            .route(
                "/accounts/:accountId/device-versions/:versionId",
                delete(admin_delete_device_version),
            )
            .route("/accounts/import/v1", post(admin_import_v1_accounts))
            .route("/accounts/import/db", post(admin_import_from_db))
            .route("/accounts/import/db-custom", post(admin_import_custom_db))
            .route("/accounts/sync/db", post(admin_sync_account_from_db))
            .route("/stats/summary", get(admin_get_token_stats_summary))
            .route("/stats/hourly", get(admin_get_token_stats_hourly))
            .route("/stats/daily", get(admin_get_token_stats_daily))
            .route("/stats/weekly", get(admin_get_token_stats_weekly))
            .route("/stats/accounts", get(admin_get_token_stats_by_account))
            .route("/stats/models", get(admin_get_token_stats_by_model))
            .route("/config", get(admin_get_config).post(admin_save_config))
            .route("/proxy/cli/status", post(admin_get_cli_sync_status))
            .route("/proxy/cli/sync", post(admin_execute_cli_sync))
            .route("/proxy/cli/restore", post(admin_execute_cli_restore))
            .route("/proxy/cli/config", post(admin_get_cli_config_content))
            .route("/proxy/opencode/status", post(admin_get_opencode_sync_status))
            .route("/proxy/opencode/sync", post(admin_execute_opencode_sync))
            .route("/proxy/opencode/restore", post(admin_execute_opencode_restore))
            .route("/proxy/opencode/config", post(admin_get_opencode_config_content))
            .route("/proxy/status", get(admin_get_proxy_status))
            .route("/proxy/pool/config", get(admin_get_proxy_pool_config))
            .route("/proxy/pool/bindings", get(admin_get_all_account_bindings))
            .route("/proxy/pool/bind", post(admin_bind_account_proxy))
            .route("/proxy/pool/unbind", post(admin_unbind_account_proxy))
            .route("/proxy/pool/binding/:accountId", get(admin_get_account_proxy_binding))
            .route("/proxy/health-check/trigger", post(admin_trigger_proxy_health_check))
            .route("/proxy/start", post(admin_start_proxy_service))
            .route("/proxy/stop", post(admin_stop_proxy_service))
            .route("/proxy/mapping", post(admin_update_model_mapping))
            .route("/proxy/api-key/generate", post(admin_generate_api_key))
            .route(
                "/proxy/session-bindings/clear",
                post(admin_clear_proxy_session_bindings),
            )
            .route("/proxy/rate-limits", delete(admin_clear_all_rate_limits))
            .route(
                "/proxy/rate-limits/:accountId",
                delete(admin_clear_rate_limit),
            )
            .route(
                "/proxy/preferred-account",
                get(admin_get_preferred_account).post(admin_set_preferred_account),
            )
            .route("/accounts/oauth/prepare", post(admin_prepare_oauth_url))
            .route("/accounts/oauth/start", post(admin_start_oauth_login))
            .route("/accounts/oauth/complete", post(admin_complete_oauth_login))
            .route("/accounts/oauth/cancel", post(admin_cancel_oauth_login))
            .route("/accounts/oauth/submit-code", post(admin_submit_oauth_code))
            .route("/zai/models/fetch", post(admin_fetch_zai_models))
            .route(
                "/proxy/monitor/toggle",
                post(admin_set_proxy_monitor_enabled),
            )
            .route("/system/open-folder", post(admin_open_folder))
            .route("/proxy/stats", get(admin_get_proxy_stats))
            .route("/logs", get(admin_get_proxy_logs_filtered))
            .route("/logs/count", get(admin_get_proxy_logs_count_filtered))
            .route("/logs/clear", post(admin_clear_proxy_logs))
            .route("/logs/:logId", get(admin_get_proxy_log_detail))
            // Debug Console (Log Bridge)
            .route("/debug/enable", post(admin_enable_debug_console))
            .route("/debug/disable", post(admin_disable_debug_console))
            .route("/debug/enabled", get(admin_is_debug_console_enabled))
            .route("/debug/logs", get(admin_get_debug_console_logs))
            .route("/debug/logs/clear", post(admin_clear_debug_console_logs))
            .route("/stats/token/clear", post(admin_clear_token_stats))
            .route("/stats/token/hourly", get(admin_get_token_stats_hourly))
            .route("/stats/token/daily", get(admin_get_token_stats_daily))
            .route("/stats/token/weekly", get(admin_get_token_stats_weekly))
            .route(
                "/stats/token/by-account",
                get(admin_get_token_stats_by_account),
            )
            .route("/stats/token/summary", get(admin_get_token_stats_summary))
            .route("/stats/token/by-model", get(admin_get_token_stats_by_model))
            .route(
                "/stats/token/model-trend/hourly",
                get(admin_get_token_stats_model_trend_hourly),
            )
            .route(
                "/stats/token/model-trend/daily",
                get(admin_get_token_stats_model_trend_daily),
            )
            .route(
                "/stats/token/account-trend/hourly",
                get(admin_get_token_stats_account_trend_hourly),
            )
            .route(
                "/stats/token/account-trend/daily",
                get(admin_get_token_stats_account_trend_daily),
            )
            .route("/accounts/bulk-delete", post(admin_delete_accounts))
            .route("/accounts/export", post(admin_export_accounts))
            .route("/accounts/reorder", post(admin_reorder_accounts))
            .route("/accounts/:accountId/quota", get(admin_fetch_account_quota))
            .route(
                "/accounts/:accountId/toggle-proxy",
                post(admin_toggle_proxy_status),
            )
            .route("/system/data-dir", get(admin_get_data_dir_path))
            .route("/system/updates/settings", get(admin_get_update_settings))
            .route(
                "/system/updates/check-status",
                get(admin_should_check_updates),
            )
            .route("/system/updates/check", post(admin_check_for_updates))
            .route("/system/updates/touch", post(admin_update_last_check_time))
            .route("/system/updates/save", post(admin_save_update_settings))
            .route("/system/gephyr/path", get(admin_get_antigravity_path))
            .route("/system/gephyr/args", get(admin_get_antigravity_args))
            // Legacy aliases for backward compatibility
            .route("/system/antigravity/path", get(admin_get_antigravity_path))
            .route("/system/antigravity/args", get(admin_get_antigravity_args))
            .route("/system/cache/clear", post(admin_clear_antigravity_cache))
            .route(
                "/system/cache/paths",
                get(admin_get_antigravity_cache_paths),
            )
            .route("/system/logs/clear-cache", post(admin_clear_log_cache))
            // Security / IP Monitoring
            .route("/security/logs", get(admin_get_ip_access_logs))
            .route("/security/logs/clear", post(admin_clear_ip_access_logs))
            .route("/security/stats", get(admin_get_ip_stats))
            .route("/security/token-stats", get(admin_get_ip_token_stats)) // For IP Token usage
            .route("/security/blacklist", get(admin_get_ip_blacklist).post(admin_add_ip_to_blacklist).delete(admin_remove_ip_from_blacklist))
            .route("/security/blacklist/clear", post(admin_clear_ip_blacklist))
            .route("/security/blacklist/check", get(admin_check_ip_in_blacklist))
            .route("/security/whitelist", get(admin_get_ip_whitelist).post(admin_add_ip_to_whitelist).delete(admin_remove_ip_from_whitelist))
            .route("/security/whitelist/clear", post(admin_clear_ip_whitelist))
            .route("/security/whitelist/check", get(admin_check_ip_in_whitelist))
            .route("/security/config", get(admin_get_security_config).post(admin_update_security_config))
            // User Tokens
            .route("/user-tokens", get(admin_list_user_tokens).post(admin_create_user_token))
            .route("/user-tokens/summary", get(admin_get_user_token_summary))
            .route("/user-tokens/:id/renew", post(admin_renew_user_token))
            .route("/user-tokens/:id", delete(admin_delete_user_token).patch(admin_update_user_token))
            // OAuth (Web) - Admin endpoints
            .route("/auth/url", get(admin_prepare_oauth_url_web))
            // App-management specific auth layer (strict validation)
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                admin_auth_middleware,
            ));

        // 3. Integrate and apply global layers
        // Read body size limit from environment variables, default 100MB
        let max_body_size: usize = std::env::var("ABV_MAX_BODY_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100 * 1024 * 1024); // Default 100MB
        tracing::info!("Request body size limit: {} MB", max_body_size / 1024 / 1024);

        let enable_admin_api = std::env::var("ABV_ENABLE_ADMIN_API")
            .ok()
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);

        let app = {
            let base = Router::new().merge(proxy_routes);
            let base = if enable_admin_api {
                tracing::warn!("Admin API enabled at /api");
                base
                    .nest("/api", admin_routes)
                    .route("/auth/callback", get(handle_oauth_callback))
            } else {
                tracing::info!(
                    "Admin API disabled (set ABV_ENABLE_ADMIN_API=true to expose /api routes)"
                );
                base
            };

            base
                // Apply global monitoring and status layer (outer layer)
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    service_status_middleware,
                ))
                .layer(cors_layer())
                .layer(DefaultBodyLimit::max(max_body_size)) // Relax body size limit
                .with_state(state.clone())
        };

        // Bind address
        let addr = format!("{}:{}", host, port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Address {} binding failed: {}", addr, e))?;

        tracing::info!("Proxy server started at http://{}", addr);

        let server_instance = Self {
            is_running: is_running_state,
            token_manager: token_manager.clone(),
        };

        // Start server in a new task
        let handle = tokio::spawn(async move {
            use hyper::server::conn::http1;
            use hyper_util::rt::TokioIo;
            use hyper_util::service::TowerToHyperService;

            loop {
                match listener.accept().await {
                    Ok((stream, remote_addr)) => {
                        let io = TokioIo::new(stream);

                        // Inject ConnectInfo (for obtaining real IP)
                        use tower::ServiceExt;
                        use hyper::body::Incoming;
                        let app_with_info =
                            app.clone().map_request(move |mut req: axum::http::Request<Incoming>| {
                                req.extensions_mut().insert(axum::extract::ConnectInfo(remote_addr));
                                req
                            });

                        let service = TowerToHyperService::new(app_with_info);

                        tokio::task::spawn(async move {
                            if let Err(err) = http1::Builder::new()
                                .serve_connection(io, service)
                                .with_upgrades()
                                .await
                            {
                                debug!("Connection handling ended or failed: {:?}", err);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {:?}", e);
                    }
                }
            }
        });

        Ok((server_instance, handle))
    }
}

// ===== API Handlers (Old code removed, taken over by src/proxy/handlers/*) =====

// Health check handler
async fn health_check_handler() -> Response {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
    .into_response()
}

// ============================================================================
// Integrated Admin Handlers
// ============================================================================

// [Integration Cleanup] Old model definitions and mappers moved up

async fn admin_list_accounts(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let accounts = state.account_service.list_accounts().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let current_id = state.account_service.get_current_id().ok().flatten();

    let account_responses: Vec<AccountResponse> = accounts
        .into_iter()
        .map(|acc| {
            let is_current = current_id.as_ref().map(|id| id == &acc.id).unwrap_or(false);
            let quota = acc.quota.map(|q| QuotaResponse {
                models: q
                    .models
                    .into_iter()
                    .map(|m| ModelQuota {
                        name: m.name,
                        percentage: m.percentage,
                        reset_time: m.reset_time,
                    })
                    .collect(),
                last_updated: q.last_updated,
                subscription_tier: q.subscription_tier,
                is_forbidden: q.is_forbidden,
            });

            AccountResponse {
                id: acc.id,
                email: acc.email,
                name: acc.name,
                is_current,
                disabled: acc.disabled,
                disabled_reason: acc.disabled_reason,
                disabled_at: acc.disabled_at,
                proxy_disabled: acc.proxy_disabled,
                proxy_disabled_reason: acc.proxy_disabled_reason,
                proxy_disabled_at: acc.proxy_disabled_at,
                protected_models: acc.protected_models.into_iter().collect(),
                validation_blocked: acc.validation_blocked,
                validation_blocked_until: acc.validation_blocked_until,
                validation_blocked_reason: acc.validation_blocked_reason,
                quota,
                device_bound: acc.device_profile.is_some(),
                last_used: acc.last_used,
            }
        })
        .collect();

    Ok(Json(AccountListResponse {
        current_account_id: current_id,
        accounts: account_responses,
    }))
}

// Export accounts with refresh tokens (for backup/migration)
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportAccountsRequest {
    account_ids: Vec<String>,
}

async fn admin_export_accounts(
    State(_state): State<AppState>,
    Json(payload): Json<ExportAccountsRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let response = account::export_accounts_by_ids(&payload.account_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(response))
}

async fn admin_get_current_account(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let response = if let Some(id) = current_id {
        let acc = account::load_account(&id).ok();
        acc.map(|acc| {
            let quota = acc.quota.map(|q| QuotaResponse {
                models: q
                    .models
                    .into_iter()
                    .map(|m| ModelQuota {
                        name: m.name,
                        percentage: m.percentage,
                        reset_time: m.reset_time,
                    })
                    .collect(),
                last_updated: q.last_updated,
                subscription_tier: q.subscription_tier,
                is_forbidden: q.is_forbidden,
            });

            AccountResponse {
                id: acc.id,
                email: acc.email,
                name: acc.name,
                is_current: true,
                disabled: acc.disabled,
                disabled_reason: acc.disabled_reason,
                disabled_at: acc.disabled_at,
                proxy_disabled: acc.proxy_disabled,
                proxy_disabled_reason: acc.proxy_disabled_reason,
                proxy_disabled_at: acc.proxy_disabled_at,
                protected_models: acc.protected_models.into_iter().collect(),
                validation_blocked: acc.validation_blocked,
                validation_blocked_until: acc.validation_blocked_until,
                validation_blocked_reason: acc.validation_blocked_reason,
                quota,
                device_bound: acc.device_profile.is_some(),
                last_used: acc.last_used,
            }
        })
    } else {
        None
    };

    Ok(Json(response))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddAccountRequest {
    refresh_token: String,
}

async fn admin_add_account(
    State(state): State<AppState>,
    Json(payload): Json<AddAccountRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let account = state
        .account_service
        .add_account(&payload.refresh_token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    // Reload TokenManager immediately after account change
    if let Err(e) = state.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to reload accounts after adding: {}",
            e
        ));
    }

    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

async fn admin_delete_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .account_service
        .delete_account(&account_id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    // Reload TokenManager immediately after account change
    if let Err(e) = state.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to reload accounts after deletion: {}",
            e
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwitchRequest {
    account_id: String,
}

async fn admin_switch_account(
    State(state): State<AppState>,
    Json(payload): Json<SwitchRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    {
        let switching = state.switching.read().await;
        if *switching {
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "Another switch operation is already in progress".to_string(),
                }),
            ));
        }
    }

    {
        let mut switching = state.switching.write().await;
        *switching = true;
    }

    let account_id = payload.account_id.clone();
    logger::log_info(&format!("[API] Starting account switch: {}", account_id));

    let result = state.account_service.switch_account(&account_id).await;

    {
        let mut switching = state.switching.write().await;
        *switching = false;
    }

    match result {
        Ok(()) => {
            logger::log_info(&format!("[API] Account switch successful: {}", account_id));

            // Sync memory status immediately after account switch
            state.token_manager.clear_all_sessions();
            if let Err(e) = state.token_manager.load_accounts().await {
                logger::log_error(&format!(
                    "[API] Failed to reload accounts after switch: {}",
                    e
                ));
            }

            Ok(StatusCode::OK)
        }
        Err(e) => {
            logger::log_error(&format!("[API] Account switch failed: {}", e));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            ))
        }
    }
}

async fn admin_refresh_all_quotas() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)>
{
    logger::log_info("[API] Starting refresh of all account quotas");
    let stats = account::refresh_all_quotas_logic().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(stats))
}

// --- OAuth Handlers ---

async fn admin_prepare_oauth_url(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let url = state
        .account_service
        .prepare_oauth_url()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(serde_json::json!({ "url": url })))
}

async fn admin_start_oauth_login(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let account = state
        .account_service
        .start_oauth_login()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

async fn admin_complete_oauth_login(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let account = state
        .account_service
        .complete_oauth_login()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

async fn admin_cancel_oauth_login(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state.account_service.cancel_oauth_login();
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct SubmitCodeRequest {
    code: String,
    state: Option<String>,
}

async fn admin_submit_oauth_code(
    State(state): State<AppState>,
    Json(payload): Json<SubmitCodeRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .account_service
        .submit_oauth_code(payload.code, payload.state)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct BindDeviceRequest {
    #[serde(default = "default_bind_mode")]
    mode: String,
}

fn default_bind_mode() -> String {
    "generate".to_string()
}

async fn admin_bind_device(
    Path(account_id): Path<String>,
    Json(payload): Json<BindDeviceRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let result = account::bind_device_profile(&account_id, &payload.mode).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Device fingerprint bound successfully",
        "device_profile": result,
    })))
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct LogsCountRequest {
    #[serde(default)]
    filter: String,
    #[serde(default)]
    errors_only: bool,
}

async fn admin_get_config() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let cfg = config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(cfg))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveConfigWrapper {
    config: AppConfig,
}

async fn admin_save_config(
    State(state): State<AppState>,
    Json(payload): Json<SaveConfigWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let new_config = payload.config;
    // 1. Persistence
    config::save_app_config(&new_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // 2. Hot-update memory state
    // Reuse the internal component update methods directly here.
    // Note: AppState already holds Arc<RwLock> handles (or direct refs) to components.

    // We need a way to access the current AxumServer instance for hot updates.
    // Or directly operate on various states in AppState.
    // In this refactoring, each state is already in AppState.

    // Update model mapping
    {
        let mut mapping = state.custom_mapping.write().await;
        *mapping = new_config.clone().proxy.custom_mapping;
    }

    // Update upstream proxy
    {
        let mut proxy = state.upstream_proxy.write().await;
        *proxy = new_config.clone().proxy.upstream_proxy;
    }

    // Update security policy
    {
        let mut security = state.security.write().await;
        *security = crate::proxy::ProxySecurityConfig::from_proxy_config(&new_config.proxy);
    }

    // Update Z.ai configuration
    {
        let mut zai = state.zai.write().await;
        *zai = new_config.clone().proxy.zai;
    }

    // Update experimental configuration
    {
        let mut exp = state.experimental.write().await;
        *exp = new_config.clone().proxy.experimental;
    }

    Ok(StatusCode::OK)
}

// Get proxy pool config
async fn admin_get_proxy_pool_config(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = state.proxy_pool_state.read().await;
    Ok(Json(config.clone()))
}

// Get all account proxy bindings
async fn admin_get_all_account_bindings(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let bindings = state.proxy_pool_manager.get_all_bindings_snapshot();
    Ok(Json(bindings))
}

// Bind account to proxy
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BindAccountProxyRequest {
    account_id: String,
    proxy_id: String,
}

async fn admin_bind_account_proxy(
    State(state): State<AppState>,
    Json(payload): Json<BindAccountProxyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state.proxy_pool_manager
        .bind_account_to_proxy(payload.account_id, payload.proxy_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(StatusCode::OK)
}

// Unbind account from proxy
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnbindAccountProxyRequest {
    account_id: String,
}

async fn admin_unbind_account_proxy(
    State(state): State<AppState>,
    Json(payload): Json<UnbindAccountProxyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state.proxy_pool_manager.unbind_account_proxy(payload.account_id).await;
    Ok(StatusCode::OK)
}

// Get account proxy binding
async fn admin_get_account_proxy_binding(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let binding = state.proxy_pool_manager.get_account_binding(&account_id);
    Ok(Json(binding))
}

// Trigger proxy pool health check
async fn admin_trigger_proxy_health_check(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state.proxy_pool_manager.health_check().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // Return updated proxy pool configuration (including health status)
    let config = state.proxy_pool_state.read().await;
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Health check completed",
        "proxies": config.proxies,
    })))
}

async fn admin_get_proxy_status(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // In Headless/Axum mode, since AxumServer is running, it's typically "running"
    let active_accounts = state.token_manager.len();

    let is_running = { *state.is_running.read().await };
    Ok(Json(serde_json::json!({
        "running": is_running,
        "port": state.port,
        "base_url": format!("http://127.0.0.1:{}", state.port),
        "active_accounts": active_accounts,
    })))
}

async fn admin_start_proxy_service(State(state): State<AppState>) -> impl IntoResponse {
    // 1. Persist configuration
    if let Ok(mut config) = crate::modules::config::load_app_config() {
        config.proxy.auto_start = true;
        let _ = crate::modules::config::save_app_config(&config);
    }

    // 2. Ensure accounts are loaded (if first start)
    if let Err(e) = state.token_manager.load_accounts().await {
        logger::log_error(&format!("[API] Failed to enable service and load accounts: {}", e));
    }

    let mut running = state.is_running.write().await;
    *running = true;
    logger::log_info("[API] Proxy service enabled (Persistence synced)");
    StatusCode::OK
}

async fn admin_stop_proxy_service(State(state): State<AppState>) -> impl IntoResponse {
    // 1. Persist configuration
    if let Ok(mut config) = crate::modules::config::load_app_config() {
        config.proxy.auto_start = false;
        let _ = crate::modules::config::save_app_config(&config);
    }

    let mut running = state.is_running.write().await;
    *running = false;
    logger::log_info("[API] Proxy service disabled (Axum mode / Persistence synced)");
    StatusCode::OK
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateMappingWrapper {
    config: crate::proxy::config::ProxyConfig,
}

async fn admin_update_model_mapping(
    State(state): State<AppState>,
    Json(payload): Json<UpdateMappingWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = payload.config;

    // 1. Update memory state (Hot-reload)
    {
        let mut mapping = state.custom_mapping.write().await;
        *mapping = config.custom_mapping.clone();
    }

    // 2. Persist to disk
    // Load current config, update mapping, then save
    let mut app_config = crate::modules::config::load_app_config().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    app_config.proxy.custom_mapping = config.custom_mapping;

    crate::modules::config::save_app_config(&app_config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    logger::log_info("[API] Model mapping hot-reloaded via API and saved");
    Ok(StatusCode::OK)
}

async fn admin_generate_api_key() -> impl IntoResponse {
    let new_key = format!("sk-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
    Json(new_key)
}

async fn admin_clear_proxy_session_bindings(State(state): State<AppState>) -> impl IntoResponse {
    state.token_manager.clear_all_sessions();
    logger::log_info("[API] All session bindings cleared");
    StatusCode::OK
}

async fn admin_clear_all_rate_limits(State(state): State<AppState>) -> impl IntoResponse {
    state.token_manager.clear_all_rate_limits();
    logger::log_info("[API] All rate limit records cleared");
    StatusCode::OK
}

async fn admin_clear_rate_limit(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> impl IntoResponse {
    let cleared = state.token_manager.clear_rate_limit(&account_id);
    if cleared {
        logger::log_info(&format!("[API] Rate limit record for account {} cleared", account_id));
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn admin_get_preferred_account(State(state): State<AppState>) -> impl IntoResponse {
    let pref = state.token_manager.get_preferred_account().await;
    Json(pref)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetPreferredAccountRequest {
    account_id: Option<String>,
}

async fn admin_set_preferred_account(
    State(state): State<AppState>,
    Json(payload): Json<SetPreferredAccountRequest>,
) -> impl IntoResponse {
    state
        .token_manager
        .set_preferred_account(payload.account_id)
        .await;
    StatusCode::OK
}

async fn admin_fetch_zai_models(
    Path(_id): Path<String>,
    Json(payload): Json<serde_json::Value>, // Reuse parameters sent from the frontend
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Simple implementation here; for more complex fetching logic, the zai module can be called
    // Currently, frontend fetch_zai_models is essentially a utility function,
    // we can fetch it via reqwest proxy on the backend.
    let zai_config = payload.get("zai").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing zai config".to_string(),
            }),
        )
    })?;

    let api_key = zai_config
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let base_url = zai_config
        .get("base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("https://api.z.ai");

    // Attempt to get models from z.ai
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/v1/models", base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    let data: serde_json::Value = resp.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    // Extract model ID list
    let models = data
        .get("data")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    m.get("id")
                        .and_then(|id| id.as_str().map(|s| s.to_string()))
                })
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    Ok(Json(models))
}

async fn admin_set_proxy_monitor_enabled(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let enabled = payload
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Only log and set when the state actually changes, to avoid the "reboot" illusion caused by repeated triggers
    if state.monitor.is_enabled() != enabled {
        state.monitor.set_enabled(enabled);
        logger::log_info(&format!("[API] Monitor status set to: {}", enabled));
    }

    StatusCode::OK
}

async fn admin_get_proxy_logs_count_filtered(
    Query(params): Query<LogsCountRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(move || {
        proxy_db::get_logs_count_filtered(&params.filter, params.errors_only)
    })
    .await;

    match res {
        Ok(Ok(count)) => Ok(Json(count)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_clear_proxy_logs() -> impl IntoResponse {
    let _ = tokio::task::spawn_blocking(|| {
        if let Err(e) = proxy_db::clear_logs() {
            logger::log_error(&format!("[API] Failed to clear proxy logs: {}", e));
        }
    })
    .await;
    logger::log_info("[API] All proxy logs cleared");
    StatusCode::OK
}

async fn admin_get_proxy_log_detail(
    Path(log_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res =
        tokio::task::spawn_blocking(move || crate::modules::proxy_db::get_log_detail(&log_id))
            .await;

    match res {
        Ok(Ok(log)) => Ok(Json(log)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct LogsFilterQuery {
    #[serde(default)]
    filter: String,
    #[serde(default)]
    errors_only: bool,
    #[serde(default)]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

async fn admin_get_proxy_logs_filtered(
    Query(params): Query<LogsFilterQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(move || {
        crate::modules::proxy_db::get_logs_filtered(
            &params.filter,
            params.errors_only,
            params.limit,
            params.offset,
        )
    })
    .await;

    match res {
        Ok(Ok(logs)) => Ok(Json(logs)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_proxy_stats(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let stats = state.monitor.get_stats().await;
    Ok(Json(stats))
}

async fn admin_get_data_dir_path() -> impl IntoResponse {
    match crate::modules::account::get_data_dir() {
        Ok(p) => Json(p.to_string_lossy().to_string()),
        Err(e) => Json(format!("Error: {}", e)),
    }
}

// --- User Token Handlers ---

async fn admin_list_user_tokens() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let tokens = crate::commands::user_token::list_user_tokens().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(tokens))
}

async fn admin_get_user_token_summary() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let summary = crate::commands::user_token::get_user_token_summary().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(summary))
}

async fn admin_create_user_token(
    Json(payload): Json<crate::commands::user_token::CreateTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let token = crate::commands::user_token::create_user_token(payload).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(token))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenewTokenRequest {
    expires_type: String,
}

async fn admin_renew_user_token(
    Path(id): Path<String>,
    Json(payload): Json<RenewTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::user_token::renew_user_token(id, payload.expires_type).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

async fn admin_delete_user_token(
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::user_token::delete_user_token(id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_update_user_token(
    Path(id): Path<String>,
    Json(payload): Json<crate::commands::user_token::UpdateTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::user_token::update_user_token(id, payload).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

async fn admin_should_check_updates() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)>
{
    let settings = crate::modules::update_checker::load_update_settings().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let should = crate::modules::update_checker::should_check_for_updates(&settings);
    Ok(Json(should))
}

async fn admin_get_antigravity_path() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)>
{
    let path = crate::commands::get_antigravity_path(Some(true))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(path))
}

async fn admin_get_antigravity_args() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)>
{
    let args = crate::commands::get_antigravity_args().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(args))
}

async fn admin_clear_antigravity_cache(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = crate::commands::clear_antigravity_cache().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(res))
}

async fn admin_get_antigravity_cache_paths(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = crate::commands::get_antigravity_cache_paths()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(res))
}

async fn admin_clear_log_cache() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::clear_log_cache().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

// Token Stats Handlers
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct StatsPeriodQuery {
    hours: Option<i64>,
    days: Option<i64>,
    weeks: Option<i64>,
}

async fn admin_get_token_stats_hourly(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let hours = p.hours.unwrap_or(24);
    let res = tokio::task::spawn_blocking(move || token_stats::get_hourly_stats(hours)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_daily(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let days = p.days.unwrap_or(7);
    let res = tokio::task::spawn_blocking(move || token_stats::get_daily_stats(days)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_weekly(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let weeks = p.weeks.unwrap_or(4);
    let res = tokio::task::spawn_blocking(move || token_stats::get_weekly_stats(weeks)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_by_account(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let hours = p.hours.unwrap_or(168);
    let res = tokio::task::spawn_blocking(move || token_stats::get_account_stats(hours)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_summary(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let hours = p.hours.unwrap_or(168);
    let res = tokio::task::spawn_blocking(move || token_stats::get_summary_stats(hours)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_by_model(
    Query(p): Query<StatsPeriodQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let hours = p.hours.unwrap_or(168);
    let res = tokio::task::spawn_blocking(move || token_stats::get_model_stats(hours)).await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_model_trend_hourly(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(|| {
        token_stats::get_model_trend_hourly(24) // Default 24 hours
    })
    .await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_model_trend_daily(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(|| {
        token_stats::get_model_trend_daily(7) // Default 7 days
    })
    .await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_account_trend_hourly(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(|| {
        token_stats::get_account_trend_hourly(24) // Default 24 hours
    })
    .await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_get_token_stats_account_trend_daily(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let res = tokio::task::spawn_blocking(|| {
        token_stats::get_account_trend_daily(7) // Default 7 days
    })
    .await;

    match res {
        Ok(Ok(stats)) => Ok(Json(stats)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn admin_clear_token_stats() -> impl IntoResponse {
    let res = tokio::task::spawn_blocking(|| {
        // Clear databases (brute force)
        if let Ok(path) = token_stats::get_db_path() {
            let _ = std::fs::remove_file(path);
        }
        let _ = token_stats::init_db();
    })
    .await;

    match res {
        Ok(_) => {
            logger::log_info("[API] All Token statistics cleared");
            StatusCode::OK
        }
        Err(e) => {
            logger::log_error(&format!("[API] Failed to clear Token statistics: {}", e));
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn admin_get_update_settings() -> impl IntoResponse {
    // Load settings from true module
    match crate::modules::update_checker::load_update_settings() {
        Ok(s) => Json(serde_json::to_value(s).unwrap_or_default()),
        Err(_) => Json(serde_json::json!({
            "auto_check": true,
            "last_check_time": 0,
            "check_interval_hours": 24
        })),
    }
}

async fn admin_check_for_updates() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let info = crate::modules::update_checker::check_for_updates()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(info))
}

async fn admin_update_last_check_time(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::update_checker::update_last_check_time().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

async fn admin_save_update_settings(Json(settings): Json<serde_json::Value>) -> impl IntoResponse {
    if let Ok(s) =
        serde_json::from_value::<crate::modules::update_checker::UpdateSettings>(settings)
    {
        let _ = crate::modules::update_checker::save_update_settings(&s);
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    }
}

// [Integration Cleanup] Redundant imports removed

#[derive(Deserialize)]
struct BulkDeleteRequest {
    #[serde(rename = "accountIds")]
    account_ids: Vec<String>,
}

async fn admin_delete_accounts(
    Json(payload): Json<BulkDeleteRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::account::delete_accounts(&payload.account_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReorderRequest {
    account_ids: Vec<String>,
}

async fn admin_reorder_accounts(
    State(state): State<AppState>,
    Json(payload): Json<ReorderRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::account::reorder_accounts(&payload.account_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // Reload TokenManager immediately after order change
    if let Err(e) = state.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to reload accounts after reorder: {}",
            e
        ));
    }

    Ok(StatusCode::OK)
}

async fn admin_fetch_account_quota(
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut account = crate::modules::load_account(&account_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let quota = crate::modules::account::fetch_quota_with_retry(&mut account)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    crate::modules::update_account_quota(&account_id, quota.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(quota))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToggleProxyRequest {
    enable: bool,
    reason: Option<String>,
}

async fn admin_toggle_proxy_status(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(payload): Json<ToggleProxyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::account::toggle_proxy_status(
        &account_id,
        payload.enable,
        payload.reason.as_deref(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // Sync to the running proxy service
    let _ = state.token_manager.reload_account(&account_id).await;

    Ok(StatusCode::OK)
}

// --- Supplementary Account Handlers ---

async fn admin_get_device_profiles(
    State(_state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let profiles = account::get_device_profiles(&account_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(profiles))
}

async fn admin_list_device_versions(
    State(_state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let profiles = account::get_device_profiles(&account_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(profiles))
}

async fn admin_preview_generate_profile(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let profile = crate::modules::device::generate_profile();
    Ok(Json(profile))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BindDeviceProfileWrapper {
    #[serde(default)]
    account_id: String,
    #[serde(alias = "profile")]
    profile_wrapper: DeviceProfileApiWrapper,
}

// DeviceProfile wrapper for API, supports camelCase input
#[derive(Deserialize)]
struct DeviceProfileApiWrapper {
    #[serde(alias = "machineId")]
    machine_id: String,
    #[serde(alias = "macMachineId")]
    mac_machine_id: String,
    #[serde(alias = "devDeviceId")]
    dev_device_id: String,
    #[serde(alias = "sqmId")]
    sqm_id: String,
}

impl From<DeviceProfileApiWrapper> for crate::models::account::DeviceProfile {
    fn from(wrapper: DeviceProfileApiWrapper) -> Self {
        Self {
            machine_id: wrapper.machine_id,
            mac_machine_id: wrapper.mac_machine_id,
            dev_device_id: wrapper.dev_device_id,
            sqm_id: wrapper.sqm_id,
        }
    }
}

async fn admin_bind_device_profile_with_profile(
    State(_state): State<AppState>,
    Path(account_id): Path<String>,
    Json(payload): Json<BindDeviceProfileWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Prioritize account_id in the payload (sent by frontend); if none, use path parameter
    let target_account_id = if !payload.account_id.is_empty() {
        &payload.account_id
    } else {
        &account_id
    };
    
    let profile: crate::models::account::DeviceProfile = payload.profile_wrapper.into();
    
    let result =
        account::bind_device_profile_with_profile(target_account_id, profile, None).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(result))
}

async fn admin_restore_original_device(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let msg = account::restore_original_device().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(msg))
}

async fn admin_restore_device_version(
    State(_state): State<AppState>,
    Path((account_id, version_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let profile = account::restore_device_version(&account_id, &version_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(profile))
}

async fn admin_delete_device_version(
    State(_state): State<AppState>,
    Path((account_id, version_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    account::delete_device_version(&account_id, &version_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_open_folder() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Note: In Web mode, this may not actually open a local folder unless the backend handles it.
    // For ABV_Refactor, the backend should use opener to open it on the server (the desktop).
    crate::commands::open_data_folder().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

// --- Import Handlers ---

async fn admin_import_v1_accounts(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let accounts = migration::import_from_v1().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // Load immediately after import
    let _ = state.token_manager.load_accounts().await;

    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let responses: Vec<AccountResponse> = accounts
        .iter()
        .map(|a| to_account_response(a, &current_id))
        .collect();
    Ok(Json(responses))
}

async fn admin_import_from_db(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let account = migration::import_from_db().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // Load immediately after import
    let _ = state.token_manager.load_accounts().await;

    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

#[derive(Deserialize)]
struct CustomDbRequest {
    path: String,
}

async fn admin_import_custom_db(
    State(state): State<AppState>,
    Json(payload): Json<CustomDbRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // [SECURITY] Directory traversal forbidden
    if payload.path.contains("..") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Illegal path: Directory traversal not allowed".to_string(),
            }),
        ));
    }

    let account = migration::import_from_custom_db_path(payload.path)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    // Load immediately after import
    let _ = state.token_manager.load_accounts().await;

    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

async fn admin_sync_account_from_db(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Logic referenced from sync_account_from_db command
    let db_refresh_token = match migration::get_refresh_token_from_db() {
        Ok(token) => token,
        Err(_e) => {
            return Ok(Json(None));
        }
    };
    let curr_account = account::get_current_account().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    if let Some(acc) = curr_account {
        if acc.token.refresh_token == db_refresh_token {
            return Ok(Json(None));
        }
    }

    let account = migration::import_from_db().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // Reload TokenManager immediately after sync
    let _ = state.token_manager.load_accounts().await;

    let current_id = state.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(Some(to_account_response(&account, &current_id))))
}

// --- CLI Sync Handlers ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CliSyncStatusRequest {
    app_type: crate::proxy::cli_sync::CliApp,
    proxy_url: String,
}

async fn admin_get_cli_sync_status(
    Json(payload): Json<CliSyncStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::cli_sync::get_cli_sync_status(payload.app_type, payload.proxy_url)
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CliSyncRequest {
    app_type: crate::proxy::cli_sync::CliApp,
    proxy_url: String,
    api_key: String,
}

async fn admin_execute_cli_sync(
    Json(payload): Json<CliSyncRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::cli_sync::execute_cli_sync(payload.app_type, payload.proxy_url, payload.api_key)
        .await
        .map(|_| StatusCode::OK)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CliRestoreRequest {
    app_type: crate::proxy::cli_sync::CliApp,
}

async fn admin_execute_cli_restore(
    Json(payload): Json<CliRestoreRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::cli_sync::execute_cli_restore(payload.app_type)
        .await
        .map(|_| StatusCode::OK)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CliConfigContentRequest {
    app_type: crate::proxy::cli_sync::CliApp,
    file_name: Option<String>,
}

async fn admin_get_cli_config_content(
    Json(payload): Json<CliConfigContentRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::cli_sync::get_cli_config_content(payload.app_type, payload.file_name)
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
struct OAuthParams {
    code: String,
    #[allow(dead_code)]
    scope: Option<String>,
    state: Option<String>,
}

async fn handle_oauth_callback(
    Query(params): Query<OAuthParams>,
    _headers: HeaderMap,
    State(_state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    let code = params.code;
    let state_param = params.state;

    // Validate CSRF state and submit code into the prepared flow.
    // This avoids completing OAuth without verifying state and keeps the callback route unauthenticated.
    match crate::modules::oauth_server::submit_oauth_code(code, state_param).await {
        Ok(()) => Ok(Html(format!(
            r#"
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Authorization Successful</title>
                    <style>
                        body {{ font-family: system-ui, -apple-system, sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background-color: #f9fafb; padding: 20px; box-sizing: border-box; }}
                        .card {{ background: white; padding: 2rem; border-radius: 1.5rem; box-shadow: 0 10px 25px -5px rgb(0 0 0 / 0.1); text-align: center; max-width: 500px; width: 100%; }}
                        .icon {{ font-size: 3rem; margin-bottom: 1rem; }}
                        h1 {{ color: #059669; margin: 0 0 1rem 0; font-size: 1.5rem; }}
                        p {{ color: #4b5563; line-height: 1.5; margin-bottom: 1.5rem; }}
                        .fallback-box {{ background-color: #f3f4f6; padding: 1.25rem; border-radius: 1rem; border: 1px dashed #d1d5db; text-align: left; margin-top: 1.5rem; }}
                        .fallback-title {{ font-weight: 600; font-size: 0.875rem; color: #1f2937; margin-bottom: 0.5rem; display: block; }}
                        .fallback-text {{ font-size: 0.75rem; color: #6b7280; margin-bottom: 1rem; display: block; }}
                        .copy-btn {{ width: 100%; padding: 0.75rem; background-color: #3b82f6; color: white; border: none; border-radius: 0.75rem; font-weight: 500; cursor: pointer; transition: background-color 0.2s; }}
                        .copy-btn:hover {{ background-color: #2563eb; }}
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="icon">✅</div>
                        <h1>Authorization Successful</h1>
                        <p>You can close this window now. The application should refresh automatically.</p>
                        
                        <div class="fallback-box">
                            <span class="fallback-title">💡 Did it not refresh?</span>
                            <span class="fallback-text">If the application is running in a container or remote environment, you may need to manually copy the link below:</span>
                            <button onclick="copyUrl()" class="copy-btn" id="copyBtn">Copy Completion Link</button>
                        </div>
                    </div>
                    <script>
                        // 1. Notify opener if exists
                        if (window.opener) {{
                            window.opener.postMessage({{
                                type: 'oauth-success',
                                message: 'login success'
                            }}, '*');
                        }}

                        // 2. Copy URL functionality
                        function copyUrl() {{
                            navigator.clipboard.writeText(window.location.href).then(() => {{
                                const btn = document.getElementById('copyBtn');
                                const originalText = btn.innerText;
                                btn.innerText = '✅ Link Copied!';
                                btn.style.backgroundColor = '#059669';
                                setTimeout(() => {{
                                    btn.innerText = originalText;
                                    btn.style.backgroundColor = '#3b82f6';
                                }}, 2000);
                            }});
                        }}
                    </script>
                </body>
                </html>
            "#
        ))),
        Err(e) => {
            error!("OAuth callback submission failed: {}", e);
            Ok(Html(format!(
                r#"<html><body><h1>Authorization Failed</h1><p>Error: {}</p></body></html>"#,
                e
            )))
        }
    }
}

async fn admin_prepare_oauth_url_web(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let port = state.security.read().await.port;
    let host = headers.get("host").and_then(|h| h.to_str().ok());
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok());
    let redirect_uri = get_oauth_redirect_uri(port, host, proto);

    let state_str = uuid::Uuid::new_v4().to_string();

    // Initialize authorization flow status and background handler
    let (auth_url, code_verifier, mut code_rx) = crate::modules::oauth_server::prepare_oauth_flow_manually(
        redirect_uri.clone(),
        state_str.clone(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // Start background task to handle callback/manual submission code
    let token_manager = state.token_manager.clone();
    let redirect_uri_clone = redirect_uri.clone();
    let code_verifier_clone = code_verifier.clone();
    tokio::spawn(async move {
        match code_rx.recv().await {
            Some(Ok(code)) => {
                crate::modules::logger::log_info(
                    "Consuming manually submitted OAuth code in background",
                );
                // Provide simplified backend processing for Web callbacks
                match crate::modules::oauth::exchange_code(&code, &redirect_uri_clone, &code_verifier_clone).await {
                    Ok(token_resp) => {
                        // Success! Now add/upsert account
                        if let Some(refresh_token) = &token_resp.refresh_token {
                            match token_manager.get_user_info(refresh_token).await {
                                Ok(user_info) => {
                                    if let Err(e) = token_manager
                                        .add_account(&user_info.email, refresh_token)
                                        .await
                                    {
                                        crate::modules::logger::log_error(&format!(
                                            "Failed to save account in background OAuth: {}",
                                            e
                                        ));
                                    } else {
                                        crate::modules::logger::log_info(&format!(
                                            "Successfully added account {} via background OAuth",
                                            user_info.email
                                        ));
                                    }
                                }
                                Err(e) => {
                                    crate::modules::logger::log_error(&format!(
                                        "Failed to fetch user info in background OAuth: {}",
                                        e
                                    ));
                                }
                            }
                        } else {
                            crate::modules::logger::log_error(
                                "Background OAuth error: Google did not return a refresh_token.",
                            );
                        }
                    }
                    Err(e) => {
                        crate::modules::logger::log_error(&format!(
                            "Background OAuth exchange failed: {}",
                            e
                        ));
                    }
                }
            }
            Some(Err(e)) => {
                crate::modules::logger::log_error(&format!("Background OAuth flow error: {}", e));
            }
            None => {
                crate::modules::logger::log_info("Background OAuth flow channel closed");
            }
        }
    });

    Ok(Json(serde_json::json!({
        "url": auth_url,
        "state": state_str
    })))
}

// Helper function: Get OAuth redirect URI
// Force use of localhost to bypass Google 2.0 policy restrictions on IP addresses and non-HTTPS environments.
// External addresses are only used when ABV_PUBLIC_URL is explicitly set (e.g., if the user configured an HTTPS domain).
fn get_oauth_redirect_uri(port: u16, _host: Option<&str>, _proto: Option<&str>) -> String {
    if let Ok(public_url) = std::env::var("ABV_PUBLIC_URL") {
        let base = public_url.trim_end_matches('/');
        format!("{}/auth/callback", base)
    } else {
        // Force return of localhost. For remote deployments, users can complete authorization via the manual submission feature.
        format!("http://localhost:{}/auth/callback", port)
    }
}

// ============================================================================
// Security / IP Management Handlers
// ============================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpAccessLogQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_page_size")]
    page_size: usize,
    search: Option<String>,
    #[serde(default)]
    blocked_only: bool,
}

fn default_page() -> usize { 1 }
fn default_page_size() -> usize { 50 }

#[derive(Serialize)]
struct IpAccessLogResponse {
    logs: Vec<crate::modules::security_db::IpAccessLog>,
    total: usize,
}

async fn admin_get_ip_access_logs(
    Query(q): Query<IpAccessLogQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let offset = (q.page.max(1) - 1) * q.page_size;
    let logs = security_db::get_ip_access_logs(
        q.page_size,
        offset,
        q.search.as_deref(),
        q.blocked_only,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;

    let total = logs.len(); // Simple total
    
    Ok(Json(IpAccessLogResponse { logs, total }))
}

async fn admin_clear_ip_access_logs() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    security_db::clear_ip_access_logs()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(StatusCode::OK)
}

#[derive(Serialize)]
struct IpStatsResponse {
    total_requests: usize,
    unique_ips: usize,
    blocked_requests: usize,
    top_ips: Vec<crate::modules::security_db::IpRanking>,
}

async fn admin_get_ip_stats() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let stats = security_db::get_ip_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    let top_ips = security_db::get_top_ips(10, 24)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;

    let response = IpStatsResponse {
        total_requests: stats.total_requests as usize,
        unique_ips: stats.unique_ips as usize,
        blocked_requests: stats.blocked_count as usize,
        top_ips,
    };
    Ok(Json(response))
}

#[derive(Deserialize)]
struct IpTokenStatsQuery {
    limit: Option<usize>,
    hours: Option<i64>,
}

async fn admin_get_ip_token_stats(
    Query(q): Query<IpTokenStatsQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let stats = proxy_db::get_token_usage_by_ip(
        q.limit.unwrap_or(100),
        q.hours.unwrap_or(720)
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(stats))
}

async fn admin_get_ip_blacklist() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let list = security_db::get_blacklist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(list))
}

#[derive(Deserialize)]
struct AddBlacklistRequest {
    ip_pattern: String,
    reason: Option<String>,
    expires_at: Option<i64>,
}

async fn admin_add_ip_to_blacklist(
    Json(req): Json<AddBlacklistRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    security_db::add_to_blacklist(
        &req.ip_pattern,
        req.reason.as_deref(),
        req.expires_at,
        "manual",
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;

    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveIpRequest {
    ip_pattern: String,
}

async fn admin_remove_ip_from_blacklist(
    Query(q): Query<RemoveIpRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_blacklist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    
    if let Some(entry) = entries.iter().find(|e| e.ip_pattern == q.ip_pattern) {
        security_db::remove_from_blacklist(&entry.id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    } else {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: format!("IP pattern {} not found", q.ip_pattern) })));
    }
    
    Ok(StatusCode::OK)
}

async fn admin_clear_ip_blacklist() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_blacklist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    for entry in entries {
        security_db::remove_from_blacklist(&entry.ip_pattern)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    }
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckIpQuery {
    ip: String,
}

async fn admin_check_ip_in_blacklist(
    Query(q): Query<CheckIpQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let result = security_db::is_ip_in_blacklist(&q.ip)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(serde_json::json!({ "result": result })))
}

async fn admin_get_ip_whitelist() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let list = security_db::get_whitelist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(list))
}

#[derive(Deserialize)]
struct AddWhitelistRequest {
    ip_pattern: String,
    description: Option<String>,
}

async fn admin_add_ip_to_whitelist(
    Json(req): Json<AddWhitelistRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    security_db::add_to_whitelist(
        &req.ip_pattern,
        req.description.as_deref(),
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(StatusCode::CREATED)
}

async fn admin_remove_ip_from_whitelist(
    Query(q): Query<RemoveIpRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_whitelist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    
    if let Some(entry) = entries.iter().find(|e| e.ip_pattern == q.ip_pattern) {
        security_db::remove_from_whitelist(&entry.id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    } else {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: format!("IP pattern {} not found", q.ip_pattern) })));
    }
    Ok(StatusCode::OK)
}

async fn admin_clear_ip_whitelist() -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let entries = security_db::get_whitelist()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    for entry in entries {
        security_db::remove_from_whitelist(&entry.ip_pattern)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    }
    Ok(StatusCode::OK)
}

async fn admin_check_ip_in_whitelist(
    Query(q): Query<CheckIpQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let result = security_db::is_ip_in_whitelist(&q.ip)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e })))?;
    Ok(Json(serde_json::json!({ "result": result })))
}

async fn admin_get_security_config(
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let app_config = crate::modules::config::load_app_config()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
    
    Ok(Json(app_config.proxy.security_monitor))
}

#[derive(Deserialize)]
struct UpdateSecurityConfigWrapper {
    config: crate::proxy::config::SecurityMonitorConfig,
}

async fn admin_update_security_config(
    State(state): State<AppState>,
    Json(payload): Json<UpdateSecurityConfigWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let config = payload.config;
    let mut app_config = crate::modules::config::load_app_config()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
        
    app_config.proxy.security_monitor = config.clone();
    
    crate::modules::config::save_app_config(&app_config)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

    {
        let mut sec = state.security.write().await;
        *sec = crate::proxy::ProxySecurityConfig::from_proxy_config(&app_config.proxy);
        tracing::info!("[Security] Runtime security config hot-reloaded via Web API");
    }

    Ok(StatusCode::OK)
}

// --- Debug Console Handlers ---

async fn admin_enable_debug_console() -> impl IntoResponse {
    crate::modules::log_bridge::enable_log_bridge();
    StatusCode::OK
}

async fn admin_disable_debug_console() -> impl IntoResponse {
    crate::modules::log_bridge::disable_log_bridge();
    StatusCode::OK
}

async fn admin_is_debug_console_enabled() -> impl IntoResponse {
    Json(crate::modules::log_bridge::is_log_bridge_enabled())
}

async fn admin_get_debug_console_logs() -> impl IntoResponse {
    let logs = crate::modules::log_bridge::get_buffered_logs();
    Json(logs)
}

async fn admin_clear_debug_console_logs() -> impl IntoResponse {
    crate::modules::log_bridge::clear_log_buffer();
    StatusCode::OK
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpencodeSyncStatusRequest {
    proxy_url: String,
}

async fn admin_get_opencode_sync_status(
    Json(payload): Json<OpencodeSyncStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::opencode_sync::get_opencode_sync_status(payload.proxy_url)
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpencodeSyncRequest {
    proxy_url: String,
    api_key: String,
    #[serde(default)]
    sync_accounts: bool,
}

async fn admin_execute_opencode_sync(
    Json(payload): Json<OpencodeSyncRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::opencode_sync::execute_opencode_sync(
        payload.proxy_url,
        payload.api_key,
        Some(payload.sync_accounts),
    )
    .await
    .map(|_| StatusCode::OK)
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })
}

async fn admin_execute_opencode_restore(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::proxy::opencode_sync::execute_opencode_restore()
        .await
        .map(|_| StatusCode::OK)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetOpencodeConfigRequest {
    file_name: Option<String>,
}

async fn admin_get_opencode_config_content(
    Json(payload): Json<GetOpencodeConfigRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let file_name = payload.file_name;
    tokio::task::spawn_blocking(move || crate::proxy::opencode_sync::read_opencode_config_content(file_name))
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e.to_string() }),
        ))?
        .map(Json)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        ))
}
