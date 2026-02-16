use axum::{
    routing::{delete, get, post},
    Router,
};

use crate::proxy::admin;
use crate::proxy::state::AppState;

pub(super) fn add_account_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/accounts",
            get(admin::admin_list_accounts).post(admin::admin_add_account),
        )
        .route("/accounts/current", get(admin::admin_get_current_account))
        .route("/accounts/switch", post(admin::admin_switch_account))
        .route("/accounts/refresh", post(admin::admin_refresh_all_quotas))
        .route(
            "/accounts/health-check",
            post(admin::admin_run_health_check),
        )
        .route("/accounts/:accountId", delete(admin::admin_delete_account))
        .route(
            "/accounts/:accountId/bind-device",
            post(admin::admin_bind_device),
        )
        .route(
            "/accounts/:accountId/device-profile",
            delete(admin::admin_clear_device_profile),
        )
        .route(
            "/accounts/:accountId/logout",
            post(admin::admin_logout_account),
        )
        .route(
            "/accounts/logout-all",
            post(admin::admin_logout_all_accounts),
        )
        .route(
            "/accounts/:accountId/device-profiles",
            get(admin::admin_get_device_profiles),
        )
        .route(
            "/accounts/:accountId/device-versions",
            get(admin::admin_list_device_versions),
        )
        .route(
            "/accounts/device-preview",
            post(admin::admin_preview_generate_profile),
        )
        .route(
            "/accounts/:accountId/bind-device-profile",
            post(admin::admin_bind_device_profile_with_profile),
        )
        .route(
            "/accounts/restore-original",
            post(admin::admin_restore_original_device),
        )
        .route(
            "/accounts/:accountId/device-versions/:versionId/restore",
            post(admin::admin_restore_device_version),
        )
        .route(
            "/accounts/:accountId/device-versions/:versionId",
            delete(admin::admin_delete_device_version),
        )
        .route("/accounts/import/v1", post(admin::admin_import_v1_accounts))
        .route("/accounts/import/db", post(admin::admin_import_from_db))
        .route(
            "/accounts/import/db-custom",
            post(admin::admin_import_custom_db),
        )
        .route("/accounts/sync/db", post(admin::admin_sync_account_from_db))
        .route(
            "/accounts/oauth/prepare",
            post(admin::admin_prepare_oauth_url),
        )
        .route(
            "/accounts/oauth/start",
            post(admin::admin_start_oauth_login),
        )
        .route(
            "/accounts/oauth/complete",
            post(admin::admin_complete_oauth_login),
        )
        .route(
            "/accounts/oauth/cancel",
            post(admin::admin_cancel_oauth_login),
        )
        .route(
            "/accounts/oauth/submit-code",
            post(admin::admin_submit_oauth_code),
        )
        .route("/accounts/bulk-delete", post(admin::admin_delete_accounts))
        .route("/accounts/export", post(admin::admin_export_accounts))
        .route("/accounts/reorder", post(admin::admin_reorder_accounts))
        .route(
            "/accounts/:accountId/quota",
            get(admin::admin_fetch_account_quota),
        )
        .route(
            "/accounts/:accountId/toggle-proxy",
            post(admin::admin_toggle_proxy_status),
        )
        .route("/auth/url", get(admin::admin_prepare_oauth_url_web))
        .route("/auth/status", get(admin::admin_get_oauth_flow_status))
}

pub(super) fn add_proxy_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/config",
            get(admin::admin_get_config).post(admin::admin_save_config),
        )
        .route("/proxy/cli/status", post(admin::admin_get_cli_sync_status))
        .route("/proxy/cli/sync", post(admin::admin_execute_cli_sync))
        .route("/proxy/cli/restore", post(admin::admin_execute_cli_restore))
        .route(
            "/proxy/cli/config",
            post(admin::admin_get_cli_config_content),
        )
        .route(
            "/proxy/opencode/status",
            post(admin::admin_get_opencode_sync_status),
        )
        .route(
            "/proxy/opencode/sync",
            post(admin::admin_execute_opencode_sync),
        )
        .route(
            "/proxy/opencode/restore",
            post(admin::admin_execute_opencode_restore),
        )
        .route(
            "/proxy/opencode/config",
            post(admin::admin_get_opencode_config_content),
        )
        .route("/proxy/status", get(admin::admin_get_proxy_status))
        .route(
            "/proxy/request-timeout",
            get(admin::admin_get_proxy_request_timeout)
                .post(admin::admin_update_proxy_request_timeout),
        )
        .route(
            "/proxy/pool/config",
            get(admin::admin_get_proxy_pool_config),
        )
        .route(
            "/proxy/pool/runtime",
            get(admin::admin_get_proxy_pool_runtime).post(admin::admin_update_proxy_pool_runtime),
        )
        .route(
            "/proxy/pool/strategy",
            get(admin::admin_get_proxy_pool_strategy).post(admin::admin_update_proxy_pool_strategy),
        )
        .route(
            "/proxy/pool/bindings",
            get(admin::admin_get_all_account_bindings),
        )
        .route("/proxy/pool/bind", post(admin::admin_bind_account_proxy))
        .route(
            "/proxy/pool/unbind",
            post(admin::admin_unbind_account_proxy),
        )
        .route(
            "/proxy/pool/binding/:accountId",
            get(admin::admin_get_account_proxy_binding),
        )
        .route(
            "/proxy/health-check/trigger",
            post(admin::admin_trigger_proxy_health_check),
        )
        .route("/proxy/start", post(admin::admin_start_proxy_service))
        .route("/proxy/stop", post(admin::admin_stop_proxy_service))
        .route("/proxy/mapping", post(admin::admin_update_model_mapping))
        .route(
            "/proxy/api-key/generate",
            post(admin::admin_generate_api_key),
        )
        .route(
            "/proxy/session-bindings/clear",
            post(admin::admin_clear_proxy_session_bindings),
        )
        .route(
            "/proxy/session-bindings",
            get(admin::admin_get_proxy_session_bindings),
        )
        .route(
            "/proxy/sticky",
            get(admin::admin_get_proxy_sticky_config).post(admin::admin_update_proxy_sticky_config),
        )
        .route(
            "/proxy/compliance",
            get(admin::admin_get_proxy_compliance_debug).post(admin::admin_update_proxy_compliance),
        )
        .route(
            "/proxy/google/outbound-policy",
            get(admin::admin_get_google_outbound_policy),
        )
        .route("/proxy/tls-canary", get(admin::admin_get_tls_canary_status))
        .route(
            "/proxy/tls-canary/run",
            post(admin::admin_run_tls_canary_probe),
        )
        .route(
            "/proxy/operator-status",
            get(admin::admin_get_operator_status),
        )
        .route("/proxy/metrics", get(admin::admin_get_proxy_metrics))
        .route(
            "/proxy/rate-limits",
            delete(admin::admin_clear_all_rate_limits),
        )
        .route(
            "/proxy/rate-limits/:accountId",
            delete(admin::admin_clear_rate_limit),
        )
        .route(
            "/proxy/preferred-account",
            get(admin::admin_get_preferred_account).post(admin::admin_set_preferred_account),
        )
        .route("/zai/models/fetch", post(admin::admin_fetch_zai_models))
        .route(
            "/proxy/monitor/toggle",
            post(admin::admin_set_proxy_monitor_enabled),
        )
}

pub(super) fn add_logs_stats_debug_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/proxy/stats", get(admin::admin_get_proxy_stats))
        .route("/logs", get(admin::admin_get_proxy_logs_filtered))
        .route(
            "/logs/count",
            get(admin::admin_get_proxy_logs_count_filtered),
        )
        .route("/logs/clear", post(admin::admin_clear_proxy_logs))
        .route("/logs/:logId", get(admin::admin_get_proxy_log_detail))
        .route("/debug/enable", post(admin::admin_enable_debug_console))
        .route("/debug/disable", post(admin::admin_disable_debug_console))
        .route("/debug/enabled", get(admin::admin_is_debug_console_enabled))
        .route("/debug/logs", get(admin::admin_get_debug_console_logs))
        .route(
            "/debug/logs/clear",
            post(admin::admin_clear_debug_console_logs),
        )
        .route("/stats/token/clear", post(admin::admin_clear_token_stats))
        .route(
            "/stats/token/hourly",
            get(admin::admin_get_token_stats_hourly),
        )
        .route(
            "/stats/token/daily",
            get(admin::admin_get_token_stats_daily),
        )
        .route(
            "/stats/token/weekly",
            get(admin::admin_get_token_stats_weekly),
        )
        .route(
            "/stats/token/by-account",
            get(admin::admin_get_token_stats_by_account),
        )
        .route(
            "/stats/token/summary",
            get(admin::admin_get_token_stats_summary),
        )
        .route(
            "/stats/token/by-model",
            get(admin::admin_get_token_stats_by_model),
        )
        .route(
            "/stats/token/model-trend/hourly",
            get(admin::admin_get_token_stats_model_trend_hourly),
        )
        .route(
            "/stats/token/model-trend/daily",
            get(admin::admin_get_token_stats_model_trend_daily),
        )
        .route(
            "/stats/token/account-trend/hourly",
            get(admin::admin_get_token_stats_account_trend_hourly),
        )
        .route(
            "/stats/token/account-trend/daily",
            get(admin::admin_get_token_stats_account_trend_daily),
        )
}

pub(super) fn add_system_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/system/data-dir", get(admin::admin_get_data_dir_path))
        .route(
            "/system/logs/clear-cache",
            post(admin::admin_clear_log_cache),
        )
}

pub(super) fn add_security_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/security/logs", get(admin::admin_get_ip_access_logs))
        .route(
            "/security/logs/clear",
            post(admin::admin_clear_ip_access_logs),
        )
        .route("/security/stats", get(admin::admin_get_ip_stats))
        .route(
            "/security/token-stats",
            get(admin::admin_get_ip_token_stats),
        )
        .route(
            "/security/blacklist",
            get(admin::admin_get_ip_blacklist)
                .post(admin::admin_add_ip_to_blacklist)
                .delete(admin::admin_remove_ip_from_blacklist),
        )
        .route(
            "/security/blacklist/clear",
            post(admin::admin_clear_ip_blacklist),
        )
        .route(
            "/security/blacklist/check",
            get(admin::admin_check_ip_in_blacklist),
        )
        .route(
            "/security/whitelist",
            get(admin::admin_get_ip_whitelist)
                .post(admin::admin_add_ip_to_whitelist)
                .delete(admin::admin_remove_ip_from_whitelist),
        )
        .route(
            "/security/whitelist/clear",
            post(admin::admin_clear_ip_whitelist),
        )
        .route(
            "/security/whitelist/check",
            get(admin::admin_check_ip_in_whitelist),
        )
        .route(
            "/security/config",
            get(admin::admin_get_security_config).post(admin::admin_update_security_config),
        )
}

pub(super) fn add_user_token_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/user-tokens",
            get(admin::admin_list_user_tokens).post(admin::admin_create_user_token),
        )
        .route(
            "/user-tokens/summary",
            get(admin::admin_get_user_token_summary),
        )
        .route(
            "/user-tokens/:id/renew",
            post(admin::admin_renew_user_token),
        )
        .route(
            "/user-tokens/:id",
            delete(admin::admin_delete_user_token).patch(admin::admin_update_user_token),
        )
}
