use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct ErrorResponse {
    error: String,
}

mod accounts;
mod runtime;
mod security;
mod stats;
mod system;

pub(crate) use accounts::{
    admin_add_account, admin_bind_device, admin_bind_device_profile_with_profile,
    admin_cancel_oauth_login, admin_complete_oauth_login, admin_delete_account,
    admin_delete_accounts, admin_delete_device_version, admin_execute_cli_restore,
    admin_execute_cli_sync, admin_export_accounts, admin_fetch_account_quota,
    admin_get_cli_config_content, admin_get_cli_sync_status, admin_get_current_account,
    admin_get_device_profiles, admin_import_custom_db, admin_import_from_db,
    admin_import_v1_accounts, admin_list_accounts, admin_list_device_versions, admin_open_folder,
    admin_prepare_oauth_url, admin_prepare_oauth_url_web, admin_preview_generate_profile,
    admin_refresh_all_quotas, admin_reorder_accounts, admin_restore_device_version,
    admin_restore_original_device, admin_start_oauth_login, admin_submit_oauth_code,
    admin_switch_account, admin_sync_account_from_db, admin_toggle_proxy_status,
    handle_oauth_callback,
};

pub(crate) use runtime::{
    admin_bind_account_proxy, admin_clear_all_rate_limits, admin_clear_antigravity_cache,
    admin_clear_log_cache, admin_clear_proxy_logs, admin_clear_proxy_session_bindings,
    admin_clear_rate_limit, admin_create_user_token, admin_delete_user_token,
    admin_fetch_zai_models, admin_generate_api_key, admin_get_account_proxy_binding,
    admin_get_all_account_bindings, admin_get_antigravity_args, admin_get_antigravity_cache_paths,
    admin_get_antigravity_path, admin_get_config, admin_get_data_dir_path,
    admin_get_preferred_account, admin_get_proxy_compliance_debug, admin_get_proxy_log_detail,
    admin_get_proxy_logs_count_filtered, admin_get_proxy_logs_filtered,
    admin_get_proxy_pool_config, admin_get_proxy_pool_runtime, admin_get_proxy_pool_strategy,
    admin_get_proxy_request_timeout, admin_get_proxy_session_bindings, admin_get_proxy_stats,
    admin_get_proxy_status, admin_get_proxy_sticky_config, admin_get_user_token_summary,
    admin_get_version_routes, admin_list_user_tokens, admin_renew_user_token, admin_save_config,
    admin_set_preferred_account, admin_set_proxy_monitor_enabled, admin_should_check_updates,
    admin_start_proxy_service, admin_stop_proxy_service, admin_trigger_proxy_health_check,
    admin_unbind_account_proxy, admin_update_model_mapping, admin_update_proxy_compliance,
    admin_update_proxy_pool_runtime, admin_update_proxy_pool_strategy,
    admin_update_proxy_request_timeout, admin_update_proxy_sticky_config, admin_update_user_token,
};

pub(crate) use security::{
    admin_add_ip_to_blacklist, admin_add_ip_to_whitelist, admin_check_ip_in_blacklist,
    admin_check_ip_in_whitelist, admin_clear_ip_access_logs, admin_clear_ip_blacklist,
    admin_clear_ip_whitelist, admin_get_ip_access_logs, admin_get_ip_blacklist, admin_get_ip_stats,
    admin_get_ip_token_stats, admin_get_ip_whitelist, admin_get_security_config,
    admin_remove_ip_from_blacklist, admin_remove_ip_from_whitelist, admin_update_security_config,
};

pub(crate) use stats::{
    admin_check_for_updates, admin_clear_token_stats, admin_get_token_stats_account_trend_daily,
    admin_get_token_stats_account_trend_hourly, admin_get_token_stats_by_account,
    admin_get_token_stats_by_model, admin_get_token_stats_daily, admin_get_token_stats_hourly,
    admin_get_token_stats_model_trend_daily, admin_get_token_stats_model_trend_hourly,
    admin_get_token_stats_summary, admin_get_token_stats_weekly, admin_get_update_settings,
    admin_save_update_settings, admin_update_last_check_time,
};

pub(crate) use system::{
    admin_clear_debug_console_logs, admin_disable_debug_console, admin_enable_debug_console,
    admin_execute_opencode_restore, admin_execute_opencode_sync, admin_get_debug_console_logs,
    admin_get_opencode_config_content, admin_get_opencode_sync_status,
    admin_is_debug_console_enabled,
};
