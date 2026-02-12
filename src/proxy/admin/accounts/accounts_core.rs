use crate::modules::{auth::account, system::logger};
use crate::proxy::admin::runtime::audit;
use crate::proxy::admin::ErrorResponse;
use crate::proxy::state::AdminState;
use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

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
    token_expiry: i64,
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

pub(crate) fn to_account_response(
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
        token_expiry: account.token.expiry_timestamp,
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
            let token_expiry = acc.token.expiry_timestamp;
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
                token_expiry,
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
            let token_expiry = acc.token.expiry_timestamp;
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
                token_expiry,
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
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let confirmed = headers
        .get("x-gephyr-confirm-bulk-refresh")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "confirm"
            )
        })
        .unwrap_or(false);

    if !confirmed {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Bulk quota refresh touches every active account. Re-send this request with header `x-gephyr-confirm-bulk-refresh: true` only when you explicitly want to run a full refresh.".to_string(),
            }),
        ));
    }

    logger::log_info("[API] Starting refresh of all account quotas");
    let stats = account::refresh_all_quotas_logic().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(stats))
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

    crate::modules::auth::account::update_account_quota(&account_id, quota.clone()).map_err(
        |e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        },
    )?;

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
    account::toggle_proxy_status(&account_id, payload.enable, payload.reason.as_deref()).map_err(
        |e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        },
    )?;
    let _ = state.core.token_manager.reload_account(&account_id).await;

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogoutAccountRequest {
    #[serde(default = "default_logout_revoke_remote")]
    revoke_remote: bool,
}

fn default_logout_revoke_remote() -> bool {
    true
}

pub(crate) async fn admin_logout_account(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(payload): Json<LogoutAccountRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let actor = audit::resolve_admin_actor(&state, &headers).await;

    state
        .core
        .account_service
        .logout_account(&account_id, payload.revoke_remote)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    let _ = state.core.token_manager.reload_account(&account_id).await;

    audit::log_admin_audit(
        "logout_account",
        &actor,
        serde_json::json!({
            "account_id": account_id,
            "revoke_remote": payload.revoke_remote,
        }),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "account_id": account_id,
        "revoked_remote": payload.revoke_remote,
        "local_cleared": true,
        "disabled": true,
    })))
}

pub(crate) async fn admin_run_health_check(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    logger::log_info("[API] Running manual account health check");
    let summary = state.core.token_manager.run_startup_health_check().await;
    Ok(Json(summary))
}
