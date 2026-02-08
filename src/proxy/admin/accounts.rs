#[derive(Serialize)]
pub(crate) struct AccountResponse {
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
    validation_blocked: bool,
    validation_blocked_until: Option<i64>,
    validation_blocked_reason: Option<String>,
    quota: Option<QuotaResponse>,
    device_bound: bool,
    last_used: i64,
}

#[derive(Serialize)]
pub(crate) struct QuotaResponse {
    models: Vec<ModelQuota>,
    last_updated: i64,
    subscription_tier: Option<String>,
    is_forbidden: bool,
}

#[derive(Serialize)]
pub(crate) struct ModelQuota {
    name: String,
    percentage: i32,
    reset_time: String,
}

#[derive(Serialize)]
pub(crate) struct AccountListResponse {
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

pub(crate) async fn admin_list_accounts(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let accounts = state.core.account_service.list_accounts().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let current_id = state.core.account_service.get_current_id().ok().flatten();

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
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExportAccountsRequest {
    account_ids: Vec<String>,
}

pub(crate) async fn admin_export_accounts(
    State(_state): State<AdminState>,
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

pub(crate) async fn admin_get_current_account(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let current_id = state.core.account_service.get_current_id().map_err(|e| {
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
pub(crate) struct AddAccountRequest {
    refresh_token: String,
}

pub(crate) async fn admin_add_account(
    State(state): State<AdminState>,
    Json(payload): Json<AddAccountRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let account = state
        .core
        .account_service
        .add_account(&payload.refresh_token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    if let Err(e) = state.core.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to reload accounts after adding: {}",
            e
        ));
    }

    let current_id = state.core.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

pub(crate) async fn admin_delete_account(
    State(state): State<AdminState>,
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .core
        .account_service
        .delete_account(&account_id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    if let Err(e) = state.core.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to reload accounts after deletion: {}",
            e
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SwitchRequest {
    account_id: String,
}

pub(crate) async fn admin_switch_account(
    State(state): State<AdminState>,
    Json(payload): Json<SwitchRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    {
        let switching = state.runtime.switching.read().await;
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
        let mut switching = state.runtime.switching.write().await;
        *switching = true;
    }

    let account_id = payload.account_id.clone();
    logger::log_info(&format!("[API] Starting account switch: {}", account_id));

    let result = state.core.account_service.switch_account(&account_id).await;

    {
        let mut switching = state.runtime.switching.write().await;
        *switching = false;
    }

    match result {
        Ok(()) => {
            logger::log_info(&format!("[API] Account switch successful: {}", account_id));
            state.core.token_manager.clear_all_sessions();
            if let Err(e) = state.core.token_manager.load_accounts().await {
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

pub(crate) async fn admin_refresh_all_quotas(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    logger::log_info("[API] Starting refresh of all account quotas");
    let stats = account::refresh_all_quotas_logic().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(stats))
}

pub(crate) async fn admin_prepare_oauth_url(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let url = state
        .core
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

pub(crate) async fn admin_start_oauth_login(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let account = state
        .core
        .account_service
        .start_oauth_login()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    let current_id = state.core.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

pub(crate) async fn admin_complete_oauth_login(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let account = state
        .core
        .account_service
        .complete_oauth_login()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    let current_id = state.core.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

pub(crate) async fn admin_cancel_oauth_login(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state.core.account_service.cancel_oauth_login();
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub(crate) struct SubmitCodeRequest {
    code: String,
    state: Option<String>,
}

pub(crate) async fn admin_submit_oauth_code(
    State(state): State<AdminState>,
    Json(payload): Json<SubmitCodeRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    state
        .core
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
pub(crate) struct BindDeviceRequest {
    #[serde(default = "default_bind_mode")]
    mode: String,
}

fn default_bind_mode() -> String {
    "generate".to_string()
}

pub(crate) async fn admin_bind_device(
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


#[derive(Deserialize)]
pub(crate) struct BulkDeleteRequest {
    #[serde(rename = "accountIds")]
    account_ids: Vec<String>,
}

pub(crate) async fn admin_delete_accounts(
    Json(payload): Json<BulkDeleteRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::auth::account::delete_accounts(&payload.account_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReorderRequest {
    account_ids: Vec<String>,
}

pub(crate) async fn admin_reorder_accounts(
    State(state): State<AdminState>,
    Json(payload): Json<ReorderRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::auth::account::reorder_accounts(&payload.account_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    if let Err(e) = state.core.token_manager.load_accounts().await {
        logger::log_error(&format!(
            "[API] Failed to reload accounts after reorder: {}",
            e
        ));
    }

    Ok(StatusCode::OK)
}

pub(crate) async fn admin_fetch_account_quota(
    Path(account_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut account = crate::modules::auth::account::load_account(&account_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let quota = crate::modules::auth::account::fetch_quota_with_retry(&mut account)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    crate::modules::auth::account::update_account_quota(&account_id, quota.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(quota))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToggleProxyRequest {
    enable: bool,
    reason: Option<String>,
}

pub(crate) async fn admin_toggle_proxy_status(
    State(state): State<AdminState>,
    Path(account_id): Path<String>,
    Json(payload): Json<ToggleProxyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::modules::auth::account::toggle_proxy_status(
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
    let _ = state.core.token_manager.reload_account(&account_id).await;

    Ok(StatusCode::OK)
}

pub(crate) async fn admin_get_device_profiles(
    State(_state): State<AdminState>,
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

pub(crate) async fn admin_list_device_versions(
    State(_state): State<AdminState>,
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

pub(crate) async fn admin_preview_generate_profile(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let profile = crate::modules::system::device::generate_profile();
    Ok(Json(profile))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BindDeviceProfileWrapper {
    #[serde(default)]
    account_id: String,
    #[serde(alias = "profile")]
    profile_wrapper: DeviceProfileApiWrapper,
}
#[derive(Deserialize)]
pub(crate) struct DeviceProfileApiWrapper {
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

pub(crate) async fn admin_bind_device_profile_with_profile(
    State(_state): State<AdminState>,
    Path(account_id): Path<String>,
    Json(payload): Json<BindDeviceProfileWrapper>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let target_account_id = if !payload.account_id.is_empty() {
        &payload.account_id
    } else {
        &account_id
    };

    let profile: crate::models::account::DeviceProfile = payload.profile_wrapper.into();

    let result = account::bind_device_profile_with_profile(target_account_id, profile, None)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    Ok(Json(result))
}

pub(crate) async fn admin_restore_original_device(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let msg = account::restore_original_device().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(msg))
}

pub(crate) async fn admin_restore_device_version(
    State(_state): State<AdminState>,
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

pub(crate) async fn admin_delete_device_version(
    State(_state): State<AdminState>,
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

pub(crate) async fn admin_open_folder(
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    crate::commands::open_data_folder().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(StatusCode::OK)
}

pub(crate) async fn admin_import_v1_accounts(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let accounts = migration::import_from_v1().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let _ = state.core.token_manager.load_accounts().await;

    let current_id = state.core.account_service.get_current_id().map_err(|e| {
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

pub(crate) async fn admin_import_from_db(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let account = migration::import_from_db().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let _ = state.core.token_manager.load_accounts().await;

    let current_id = state.core.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

#[derive(Deserialize)]
pub(crate) struct CustomDbRequest {
    path: String,
}

pub(crate) async fn admin_import_custom_db(
    State(state): State<AdminState>,
    Json(payload): Json<CustomDbRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
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
    let _ = state.core.token_manager.load_accounts().await;

    let current_id = state.core.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(to_account_response(&account, &current_id)))
}

pub(crate) async fn admin_sync_account_from_db(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
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
    let _ = state.core.token_manager.load_accounts().await;

    let current_id = state.core.account_service.get_current_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    Ok(Json(Some(to_account_response(&account, &current_id))))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CliSyncStatusRequest {
    app_type: crate::proxy::cli_sync::CliApp,
    proxy_url: String,
}

pub(crate) async fn admin_get_cli_sync_status(
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
pub(crate) struct CliSyncRequest {
    app_type: crate::proxy::cli_sync::CliApp,
    proxy_url: String,
    api_key: String,
}

pub(crate) async fn admin_execute_cli_sync(
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
pub(crate) struct CliRestoreRequest {
    app_type: crate::proxy::cli_sync::CliApp,
}

pub(crate) async fn admin_execute_cli_restore(
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
pub(crate) struct CliConfigContentRequest {
    app_type: crate::proxy::cli_sync::CliApp,
    file_name: Option<String>,
}

pub(crate) async fn admin_get_cli_config_content(
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
pub(crate) struct OAuthParams {
    code: String,
    #[allow(dead_code)]
    scope: Option<String>,
    state: Option<String>,
}

#[allow(clippy::useless_format)]
pub(crate) async fn handle_oauth_callback(
    Query(params): Query<OAuthParams>,
    _headers: HeaderMap,
    State(_state): State<AdminState>,
) -> Result<Html<String>, StatusCode> {
    let code = params.code;
    let state_param = params.state;
    match crate::modules::auth::oauth_server::submit_oauth_code(code, state_param).await {
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
                        if (window.opener) {{
                            window.opener.postMessage({{
                                type: 'oauth-success',
                                message: 'login success'
                            }}, '*');
                        }}
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

pub(crate) async fn admin_prepare_oauth_url_web(
    headers: HeaderMap,
    State(state): State<AdminState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let port = state.config.security.read().await.port;
    let host = headers.get("host").and_then(|h| h.to_str().ok());
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok());
    let redirect_uri = get_oauth_redirect_uri(port, host, proto);

    let state_str = uuid::Uuid::new_v4().to_string();
    let (auth_url, code_verifier, mut code_rx) =
        crate::modules::auth::oauth_server::prepare_oauth_flow_manually(
            redirect_uri.clone(),
            state_str.clone(),
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
    let token_manager = state.core.token_manager.clone();
    let redirect_uri_clone = redirect_uri.clone();
    let code_verifier_clone = code_verifier.clone();
    tokio::spawn(async move {
        match code_rx.recv().await {
            Some(Ok(code)) => {
                crate::modules::system::logger::log_info(
                    "Consuming manually submitted OAuth code in background",
                );
                match crate::modules::auth::oauth::exchange_code(
                    &code,
                    &redirect_uri_clone,
                    &code_verifier_clone,
                )
                .await
                {
                    Ok(token_resp) => {
                        if let Some(refresh_token) = &token_resp.refresh_token {
                            match token_manager.get_user_info(refresh_token).await {
                                Ok(user_info) => {
                                    if let Err(e) = token_manager
                                        .add_account(&user_info.email, refresh_token)
                                        .await
                                    {
                                        crate::modules::system::logger::log_error(&format!(
                                            "Failed to save account in background OAuth: {}",
                                            e
                                        ));
                                    } else {
                                        crate::modules::system::logger::log_info(&format!(
                                            "Successfully added account {} via background OAuth",
                                            user_info.email
                                        ));
                                    }
                                }
                                Err(e) => {
                                    crate::modules::system::logger::log_error(&format!(
                                        "Failed to fetch user info in background OAuth: {}",
                                        e
                                    ));
                                }
                            }
                        } else {
                            crate::modules::system::logger::log_error(
                                "Background OAuth error: Google did not return a refresh_token.",
                            );
                        }
                    }
                    Err(e) => {
                        crate::modules::system::logger::log_error(&format!(
                            "Background OAuth exchange failed: {}",
                            e
                        ));
                    }
                }
            }
            Some(Err(e)) => {
                crate::modules::system::logger::log_error(&format!("Background OAuth flow error: {}", e));
            }
            None => {
                crate::modules::system::logger::log_info("Background OAuth flow channel closed");
            }
        }
    });

    Ok(Json(serde_json::json!({
        "url": auth_url,
        "state": state_str
    })))
}
fn get_oauth_redirect_uri(port: u16, _host: Option<&str>, _proto: Option<&str>) -> String {
    if let Ok(public_url) = std::env::var("ABV_PUBLIC_URL") {
        let base = public_url.trim_end_matches('/');
        format!("{}/auth/callback", base)
    } else {
        format!("http://localhost:{}/auth/callback", port)
    }
}

