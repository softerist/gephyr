use crate::proxy::admin::ErrorResponse;
use crate::proxy::state::AdminState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorEncryptionStatus {
    env_key_set: bool,
    machine_uid_available: bool,
    prerequisites_ok: bool,
    prerequisites_error: Option<String>,
    encrypted_secrets_seen: u64,
    decrypt_failures: u64,
    first_failure: Option<OperatorDecryptFailure>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorDecryptFailure {
    account_id: String,
    email: String,
    field: String,
    error: String,
    file: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorAccountsStatus {
    index_accounts: usize,
    current_account_id: Option<String>,
    files_seen: u64,
    parse_failures: u64,
    disabled: u64,
    proxy_disabled: u64,
    missing_device_profile: u64,
    missing_refresh_token: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorProxyPoolStatus {
    enabled: bool,
    require_proxy_for_account_requests: bool,
    proxies_total: usize,
    proxies_enabled: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorOAuthConfigStatus {
    client_id_set: bool,
    client_secret_set: bool,
    allowed_domains_set: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorStatusResponse {
    timestamp: String,
    version: String,
    data_dir: String,
    runtime_port: u16,
    runtime_running: bool,
    tls_backend: String,
    oauth: OperatorOAuthConfigStatus,
    oauth_flow: crate::modules::auth::oauth_server::OAuthFlowStatusSnapshot,
    proxy_pool: OperatorProxyPoolStatus,
    accounts: OperatorAccountsStatus,
    encryption: OperatorEncryptionStatus,
}

fn env_var_set(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

fn as_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn token_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get("token")
        .and_then(|t| t.get(field))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn bool_field(value: &serde_json::Value, key: &str) -> bool {
    value.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn has_device_profile(value: &serde_json::Value) -> bool {
    match value.get("device_profile") {
        Some(serde_json::Value::Object(obj)) => !obj.is_empty(),
        _ => false,
    }
}

async fn scan_accounts_for_operator_status(
    accounts_dir: &PathBuf,
) -> Result<(OperatorAccountsStatus, OperatorEncryptionStatus), String> {
    let mut accounts_status = OperatorAccountsStatus {
        index_accounts: 0,
        current_account_id: None,
        files_seen: 0,
        parse_failures: 0,
        disabled: 0,
        proxy_disabled: 0,
        missing_device_profile: 0,
        missing_refresh_token: 0,
    };

    let mut enc_status = OperatorEncryptionStatus {
        env_key_set: env_var_set("ENCRYPTION_KEY"),
        machine_uid_available: machine_uid::get().is_ok(),
        prerequisites_ok: true,
        prerequisites_error: None,
        encrypted_secrets_seen: 0,
        decrypt_failures: 0,
        first_failure: None,
    };

    if let Err(e) = crate::utils::crypto::validate_encryption_key_prerequisites() {
        enc_status.prerequisites_ok = false;
        enc_status.prerequisites_error = Some(e);
    }

    // Index summary is cheap and helps operators understand current routing state.
    if let Ok(index) = crate::modules::auth::account::load_account_index() {
        accounts_status.index_accounts = index.accounts.len();
        accounts_status.current_account_id = index.current_account_id;
    }

    if !accounts_dir.exists() {
        return Ok((accounts_status, enc_status));
    }

    let entries = std::fs::read_dir(accounts_dir)
        .map_err(|e| format!("failed_to_read_accounts_dir: {}", e))?;
    for entry in entries {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                accounts_status.parse_failures += 1;
                tracing::warn!("operator_status_accounts_dir_entry_read_failed: {}", e);
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        accounts_status.files_seen += 1;

        let content = match std::fs::read_to_string(&path) {
            Ok(v) => v,
            Err(e) => {
                accounts_status.parse_failures += 1;
                tracing::warn!("operator_status_account_file_read_failed {:?}: {}", path, e);
                continue;
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                accounts_status.parse_failures += 1;
                tracing::warn!(
                    "operator_status_account_file_parse_failed {:?}: {}",
                    path,
                    e
                );
                continue;
            }
        };

        if bool_field(&value, "disabled") {
            accounts_status.disabled += 1;
        }
        if bool_field(&value, "proxy_disabled") {
            accounts_status.proxy_disabled += 1;
        }
        if !has_device_profile(&value) {
            accounts_status.missing_device_profile += 1;
        }

        let refresh_token = token_field(&value, "refresh_token").unwrap_or_default();
        if refresh_token.trim().is_empty() {
            accounts_status.missing_refresh_token += 1;
        }

        // Encrypted token sanity. We avoid loading the full Account struct here because
        // serde would attempt decryption and fail fast on a mismatch; operators need a report.
        let account_id = as_string_field(&value, "id").unwrap_or_else(|| "<unknown>".to_string());
        let email = as_string_field(&value, "email").unwrap_or_else(|| "<unknown>".to_string());
        for (field, raw_opt) in [
            ("token.access_token", token_field(&value, "access_token")),
            ("token.refresh_token", token_field(&value, "refresh_token")),
        ] {
            let Some(raw) = raw_opt else {
                continue;
            };
            if crate::utils::crypto::is_probably_encrypted_secret(&raw) {
                enc_status.encrypted_secrets_seen += 1;
            }
            if let Err(e) = crate::utils::crypto::preflight_verify_decryptable_secret(&raw) {
                enc_status.decrypt_failures += 1;
                if enc_status.first_failure.is_none() {
                    enc_status.first_failure = Some(OperatorDecryptFailure {
                        account_id: account_id.clone(),
                        email: email.clone(),
                        field: field.to_string(),
                        error: e,
                        file: path.to_string_lossy().to_string(),
                    });
                }
            }
        }
    }

    Ok((accounts_status, enc_status))
}

pub(crate) async fn admin_get_operator_status(
    State(state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let data_dir = crate::modules::auth::account::get_data_dir().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;
    let accounts_dir = data_dir.join("accounts");

    let (accounts, encryption) = scan_accounts_for_operator_status(&accounts_dir)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;

    let proxy_pool_cfg = state.runtime.proxy_pool_state.read().await.clone();
    let proxy_pool = OperatorProxyPoolStatus {
        enabled: proxy_pool_cfg.enabled,
        require_proxy_for_account_requests: proxy_pool_cfg.require_proxy_for_account_requests,
        proxies_total: proxy_pool_cfg.proxies.len(),
        proxies_enabled: proxy_pool_cfg.proxies.iter().filter(|p| p.enabled).count(),
    };

    let oauth = OperatorOAuthConfigStatus {
        client_id_set: env_var_set("GOOGLE_OAUTH_CLIENT_ID"),
        client_secret_set: env_var_set("GOOGLE_OAUTH_CLIENT_SECRET"),
        allowed_domains_set: env_var_set("ALLOWED_GOOGLE_DOMAINS"),
    };
    let oauth_flow = crate::modules::auth::oauth_server::get_oauth_flow_status();

    let is_running = { *state.runtime.is_running.read().await };
    let resp = OperatorStatusResponse {
        timestamp: chrono::Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        data_dir: data_dir.to_string_lossy().to_string(),
        runtime_port: state.runtime.port,
        runtime_running: is_running,
        tls_backend: crate::utils::http::tls_backend_name().to_string(),
        oauth,
        oauth_flow,
        proxy_pool,
        accounts,
        encryption,
    };
    Ok(Json(resp))
}
