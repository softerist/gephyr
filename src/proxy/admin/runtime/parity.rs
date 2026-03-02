use std::path::PathBuf;

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use crate::proxy::admin::ErrorResponse;
use crate::proxy::parity;
use crate::proxy::state::AdminState;

fn parse_source_hint(raw: Option<&str>) -> Option<parity::types::RequestSource> {
    let raw = raw?.trim().to_ascii_lowercase();
    match raw.as_str() {
        "gephyr" => Some(parity::types::RequestSource::Gephyr),
        "known_good" => Some(parity::types::RequestSource::KnownGood),
        "antigravity_exe" | "antigravity" => Some(parity::types::RequestSource::AntigravityExe),
        "language_server_windows_x64" | "language_server_windows_x64.exe" => {
            Some(parity::types::RequestSource::LanguageServerWindowsX64)
        }
        "unknown" => Some(parity::types::RequestSource::Unknown),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ParityCaptureStartRequest {
    #[serde(default)]
    ring_limit: Option<usize>,
    #[serde(default)]
    raw_output_dir: Option<String>,
    #[serde(default)]
    redacted_output_dir: Option<String>,
}

pub(crate) async fn admin_parity_capture_start(
    State(_state): State<AdminState>,
    Json(payload): Json<ParityCaptureStartRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let status = parity::capture::start_capture(parity::capture::CaptureStartConfig {
        ring_limit: payload.ring_limit,
        raw_output_dir: payload.raw_output_dir.map(PathBuf::from),
        redacted_output_dir: payload.redacted_output_dir.map(PathBuf::from),
    });

    Ok(Json(serde_json::json!({
        "ok": true,
        "status": status,
    })))
}

pub(crate) async fn admin_parity_capture_stop(
    State(_state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let status = parity::capture::stop_capture();
    Ok(Json(serde_json::json!({
        "ok": true,
        "status": status,
    })))
}

pub(crate) async fn admin_parity_capture_status(
    State(_state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let status = parity::capture::capture_status();
    Ok(Json(status))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ParityCaptureExportRequest {
    #[serde(default)]
    raw_path: Option<String>,
    #[serde(default)]
    redacted_path: Option<String>,
    #[serde(default)]
    rules_path: Option<String>,
}

pub(crate) async fn admin_parity_capture_export(
    State(_state): State<AdminState>,
    Json(payload): Json<ParityCaptureExportRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let rules = if let Some(path) = payload.rules_path.as_deref() {
        let content = std::fs::read_to_string(path).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("failed to read rules file {}: {}", path, e),
                }),
            )
        })?;
        serde_json::from_str::<parity::types::ParityRuleSet>(&content).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid rules json in {}: {}", path, e),
                }),
            )
        })?
    } else {
        parity::types::ParityRuleSet::default()
    };

    let raw_path = payload.raw_path.as_ref().map(PathBuf::from);
    let redacted_path = payload.redacted_path.as_ref().map(PathBuf::from);

    let export = parity::capture::export_dual_artifacts(
        raw_path.as_deref(),
        redacted_path.as_deref(),
        Some(&rules),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "export": export,
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ParityMimicTriggerRequest {
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    skip_token_refresh: Option<bool>,
    #[serde(default)]
    repeat: Option<u32>,
    #[serde(default)]
    delay_ms: Option<u64>,
    #[serde(default)]
    attach_account_context: Option<bool>,
    #[serde(default)]
    cascade_nuxes_first_only: Option<bool>,
    #[serde(default)]
    play_log_enabled: Option<bool>,
    #[serde(default)]
    play_log_payload_sizes: Option<Vec<usize>>,
}

pub(crate) async fn admin_parity_mimic_trigger(
    State(_state): State<AdminState>,
    Json(payload): Json<ParityMimicTriggerRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let repeat = payload.repeat.unwrap_or(1).clamp(1, 20);
    let delay_ms = payload.delay_ms.unwrap_or(0).min(30_000);

    let resolved_account_id = if payload.account_id.is_some() {
        payload.account_id.clone()
    } else {
        crate::modules::auth::account::get_current_account_id().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("failed to resolve current account: {}", e),
                }),
            )
        })?
    };

    let skip_token_refresh = payload.skip_token_refresh.unwrap_or(false);
    let (access_token, project_id, email) = if let Some(token) = payload.access_token.clone() {
        (token, payload.project_id.clone(), None::<String>)
    } else {
        let account_id = resolved_account_id.clone().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error:
                        "missing account context: provide account_id or access_token, or select current account"
                            .to_string(),
                }),
            )
        })?;
        let account = crate::modules::auth::account::load_account(&account_id).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("failed to load account {}: {}", account_id, e),
                }),
            )
        })?;
        if skip_token_refresh {
            (
                account.token.access_token.clone(),
                payload
                    .project_id
                    .clone()
                    .or(account.token.project_id.clone()),
                Some(account.email),
            )
        } else {
            let fresh =
                crate::modules::auth::oauth::ensure_fresh_token(&account.token, Some(&account.id))
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::BAD_GATEWAY,
                            Json(ErrorResponse {
                                error: format!("failed to refresh account token: {}", e),
                            }),
                        )
                    })?;
            (
                fresh.access_token,
                payload
                    .project_id
                    .clone()
                    .or(fresh.project_id.clone())
                    .or(account.token.project_id.clone()),
                Some(account.email),
            )
        }
    };

    let mut results = Vec::new();
    let mimic_account_context = if payload.attach_account_context.unwrap_or(false) {
        resolved_account_id.as_deref()
    } else {
        None
    };
    let cascade_nuxes_first_only = payload.cascade_nuxes_first_only.unwrap_or(false);
    let play_log_enabled = payload.play_log_enabled.unwrap_or(true);
    for idx in 0..repeat {
        let include_cascade_nuxes = !(cascade_nuxes_first_only && idx > 0);
        let flow = crate::proxy::google::mimic_flow::run_manual_mimic_flow_with_options(
            &access_token,
            mimic_account_context,
            project_id.as_deref(),
            include_cascade_nuxes,
        )
        .await;
        results.push(flow);

        if idx + 1 < repeat && delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }
    }

    let default_payload_sizes = vec![132usize, 3354usize];
    let play_log_payload_sizes = payload
        .play_log_payload_sizes
        .clone()
        .filter(|v| !v.is_empty())
        .unwrap_or(default_payload_sizes);
    let play_log_result = if play_log_enabled {
        Some(
            crate::proxy::google::mimic_flow::run_play_log_sequence(
                &access_token,
                mimic_account_context,
                &play_log_payload_sizes,
            )
            .await,
        )
    } else {
        None
    };

    Ok(Json(serde_json::json!({
        "ok": true,
        "repeat": repeat,
        "delay_ms": delay_ms,
        "account_id": resolved_account_id,
        "email": email,
        "project_id": project_id,
        "skip_token_refresh": skip_token_refresh,
        "cascade_nuxes_first_only": cascade_nuxes_first_only,
        "play_log_enabled": play_log_enabled,
        "play_log_payload_sizes": play_log_payload_sizes,
        "play_log_result": play_log_result,
        "results": results
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ParityDiffRunRequest {
    #[serde(default)]
    gephyr_path: Option<String>,
    known_good_path: String,
    #[serde(default)]
    known_good_source_hint: Option<String>,
    #[serde(default)]
    rules_path: Option<String>,
    #[serde(default)]
    report_json_path: Option<String>,
    #[serde(default)]
    gate_policy: Option<parity::types::GatePolicy>,
}

pub(crate) async fn admin_parity_diff_run(
    State(_state): State<AdminState>,
    Json(payload): Json<ParityDiffRunRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let gephyr_fingerprints = if let Some(path) = payload.gephyr_path.as_deref() {
        let gephyr_path = PathBuf::from(path);
        let mut loaded = parity::ingest::load_trace(
            gephyr_path.as_path(),
            Some(parity::types::RequestSource::Gephyr),
        )
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("failed to load gephyr trace {}: {}", path, e),
                }),
            )
        })?;
        loaded = parity::ingest::filter_google_endpoints(loaded);
        loaded
    } else {
        parity::ingest::filter_google_endpoints(parity::capture::captured_snapshot())
    };

    let known_good_source = parse_source_hint(payload.known_good_source_hint.as_deref())
        .or(Some(parity::types::RequestSource::KnownGood));
    let known_good_path = PathBuf::from(&payload.known_good_path);
    let mut known_good_fingerprints =
        parity::ingest::load_trace(known_good_path.as_path(), known_good_source).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "failed to load known-good trace {}: {}",
                        payload.known_good_path, e
                    ),
                }),
            )
        })?;
    known_good_fingerprints = parity::ingest::filter_google_endpoints(known_good_fingerprints);

    if gephyr_fingerprints.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error:
                    "gephyr fingerprint set is empty (provide gephyr_path or start capture first)"
                        .to_string(),
            }),
        ));
    }
    if known_good_fingerprints.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "known-good fingerprint set is empty".to_string(),
            }),
        ));
    }

    let rules = if let Some(path) = payload.rules_path.as_deref() {
        let content = std::fs::read_to_string(path).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("failed to read rules file {}: {}", path, e),
                }),
            )
        })?;
        serde_json::from_str::<parity::types::ParityRuleSet>(&content).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid rules json in {}: {}", path, e),
                }),
            )
        })?
    } else {
        parity::types::ParityRuleSet::default()
    };

    let report = parity::diff::compare(
        &gephyr_fingerprints,
        &known_good_fingerprints,
        &rules,
        payload.gate_policy.unwrap_or_default(),
    );
    parity::capture::set_latest_diff(report.clone());

    if let Some(path) = payload.report_json_path.as_deref() {
        let path_buf = PathBuf::from(path);
        if let Some(parent) = path_buf.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(&report).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("failed to serialize report: {}", e),
                }),
            )
        })?;
        std::fs::write(&path_buf, json).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("failed to write report {}: {}", path, e),
                }),
            )
        })?;
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "report": report,
    })))
}

pub(crate) async fn admin_parity_diff_latest(
    State(_state): State<AdminState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let report = parity::capture::latest_diff().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "no parity diff report available in runtime".to_string(),
            }),
        )
    })?;

    Ok(Json(report))
}
