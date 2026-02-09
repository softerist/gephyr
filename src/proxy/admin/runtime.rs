mod audit;
mod config_pool;
mod logs;
mod maintenance;
mod service_control;
mod user_tokens;

pub(crate) use config_pool::{
    admin_bind_account_proxy, admin_get_account_proxy_binding, admin_get_all_account_bindings,
    admin_get_config, admin_get_proxy_pool_config, admin_get_proxy_pool_strategy,
    admin_save_config, admin_trigger_proxy_health_check, admin_unbind_account_proxy,
    admin_update_proxy_pool_strategy,
};
pub(crate) use logs::{
    admin_clear_proxy_logs, admin_get_proxy_log_detail, admin_get_proxy_logs_count_filtered,
    admin_get_proxy_logs_filtered, admin_get_proxy_stats,
};
pub(crate) use maintenance::{
    admin_clear_antigravity_cache, admin_clear_log_cache, admin_get_antigravity_args,
    admin_get_antigravity_cache_paths, admin_get_antigravity_path, admin_get_data_dir_path,
    admin_should_check_updates,
};
pub(crate) use service_control::{
    admin_clear_all_rate_limits, admin_clear_proxy_session_bindings, admin_clear_rate_limit,
    admin_fetch_zai_models, admin_generate_api_key, admin_get_preferred_account,
    admin_get_proxy_compliance_debug, admin_get_proxy_request_timeout,
    admin_get_proxy_session_bindings, admin_get_proxy_status, admin_get_proxy_sticky_config,
    admin_get_version_routes, admin_set_preferred_account, admin_set_proxy_monitor_enabled,
    admin_start_proxy_service, admin_stop_proxy_service, admin_update_model_mapping,
    admin_update_proxy_compliance, admin_update_proxy_request_timeout,
    admin_update_proxy_sticky_config,
};
pub(crate) use user_tokens::{
    admin_create_user_token, admin_delete_user_token, admin_get_user_token_summary,
    admin_list_user_tokens, admin_renew_user_token, admin_update_user_token,
};
