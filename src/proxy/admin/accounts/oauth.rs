use super::accounts_core::to_account_response;
use crate::proxy::admin::ErrorResponse;
use crate::proxy::state::AdminState;
use axum::{
    extract::{Json, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
};
use serde::Deserialize;
use tracing::error;

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
pub(crate) struct OAuthParams {
    pub(crate) code: Option<String>,
    #[serde(rename = "scope")]
    pub(crate) _scope: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

pub(crate) async fn handle_oauth_callback(
    Query(params): Query<OAuthParams>,
    _headers: HeaderMap,
    State(_state): State<AdminState>,
) -> Result<Html<String>, StatusCode> {
    if let Some(error) = params.error.as_deref() {
        if error == "access_denied" {
            crate::modules::auth::oauth_server::mark_oauth_flow_status(
                crate::modules::auth::oauth_server::OAuthFlowPhase::Rejected,
                Some("oauth_access_denied".to_string()),
                None,
            );
            return Ok(Html(
                "<html><body><h1>Authorization Rejected</h1><p>You declined the OAuth consent screen. Return to the app if you want to retry.</p></body></html>".to_string(),
            ));
        }
        let detail = if let Some(desc) = params.error_description.as_deref() {
            format!("oauth_error_{}: {}", error, desc)
        } else {
            format!("oauth_error_{}", error)
        };
        crate::modules::auth::oauth_server::mark_oauth_flow_status(
            crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
            Some(detail.clone()),
            None,
        );
        error!(
            "[E-OAUTH-CALLBACK-ERROR] oauth_callback_returned_error: {}",
            detail
        );
        return Ok(Html(format!(
            r#"<html><body><h1>Authorization Failed</h1><p>Error: {}</p></body></html>"#,
            detail
        )));
    }
    let Some(code) = params.code else {
        crate::modules::auth::oauth_server::mark_oauth_flow_status(
            crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
            Some("authorization_code_missing_in_callback".to_string()),
            None,
        );
        return Ok(Html(
            "<html><body><h1>Authorization Failed</h1><p>Error: authorization_code_missing_in_callback</p></body></html>".to_string(),
        ));
    };
    let state_param = params.state;
    match crate::modules::auth::oauth_server::submit_oauth_code(code, state_param).await {
        Ok(()) => Ok(Html(
            r#"
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Authorization Received</title>
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
                        <h1>Authorization Received</h1>
                        <p>The authorization code was received. Account linking is now completing in the background.</p>
                        <p>If your terminal does not continue within a few seconds, check server logs for the exact failure reason.</p>

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
            .to_string(),
        )),
        Err(e) => {
            error!(
                "[E-OAUTH-CALLBACK-SUBMIT] oauth_callback_submission_failed: {}",
                e
            );
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
                crate::modules::auth::oauth_server::mark_oauth_flow_status(
                    crate::modules::auth::oauth_server::OAuthFlowPhase::ExchangingToken,
                    Some("oauth_token_exchange_started".to_string()),
                    None,
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
                            crate::modules::auth::oauth_server::mark_oauth_flow_status(
                                crate::modules::auth::oauth_server::OAuthFlowPhase::FetchingUserInfo,
                                Some("oauth_fetch_user_info".to_string()),
                                None,
                            );
                            match token_manager.get_verified_identity(refresh_token).await {
                                Ok(identity) => {
                                    crate::modules::auth::oauth_server::mark_oauth_flow_status(
                                        crate::modules::auth::oauth_server::OAuthFlowPhase::SavingAccount,
                                        Some("oauth_save_account".to_string()),
                                        Some(identity.email.clone()),
                                    );
                                    if let Err(e) = token_manager.add_account(refresh_token).await {
                                        crate::modules::auth::oauth_server::mark_oauth_flow_status(
                                            crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
                                            Some(format!("oauth_save_account_failed: {}", e)),
                                            Some(identity.email.clone()),
                                        );
                                        crate::modules::system::logger::log_error(&format!(
                                            "[E-OAUTH-ACCOUNT-SAVE] oauth_background_save_account_failed: {}",
                                            e
                                        ));
                                    } else {
                                        crate::modules::auth::oauth_server::mark_oauth_flow_status(
                                            crate::modules::auth::oauth_server::OAuthFlowPhase::Linked,
                                            Some("oauth_account_linked".to_string()),
                                            Some(identity.email.clone()),
                                        );
                                        crate::modules::system::logger::log_info(&format!(
                                            "Successfully added account {} via background OAuth",
                                            identity.email
                                        ));
                                    }
                                }
                                Err(e) => {
                                    crate::modules::auth::oauth_server::mark_oauth_flow_status(
                                        crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
                                        Some(format!("oauth_user_info_failed: {}", e)),
                                        None,
                                    );
                                    crate::modules::system::logger::log_error(&format!(
                                        "[E-OAUTH-USERINFO] oauth_background_fetch_user_info_failed: {}",
                                        e
                                    ));
                                }
                            }
                        } else {
                            crate::modules::auth::oauth_server::mark_oauth_flow_status(
                                crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
                                Some("oauth_refresh_token_missing".to_string()),
                                None,
                            );
                            crate::modules::system::logger::log_error(
                                "[E-OAUTH-REFRESH-TOKEN] oauth_background_refresh_token_missing",
                            );
                        }
                    }
                    Err(e) => {
                        crate::modules::auth::oauth_server::mark_oauth_flow_status(
                            crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
                            Some(format!("oauth_exchange_failed: {}", e)),
                            None,
                        );
                        crate::modules::system::logger::log_error(&format!(
                            "[E-OAUTH-EXCHANGE] oauth_background_exchange_failed: {}",
                            e
                        ));
                    }
                }
            }
            Some(Err(e)) => {
                crate::modules::auth::oauth_server::mark_oauth_flow_status(
                    crate::modules::auth::oauth_server::OAuthFlowPhase::Failed,
                    Some(format!("oauth_background_flow_failed: {}", e)),
                    None,
                );
                crate::modules::system::logger::log_error(&format!(
                    "[E-OAUTH-BACKGROUND] oauth_background_flow_error: {}",
                    e
                ));
            }
            None => {
                crate::modules::auth::oauth_server::mark_oauth_flow_status(
                    crate::modules::auth::oauth_server::OAuthFlowPhase::Cancelled,
                    Some("oauth_background_channel_closed".to_string()),
                    None,
                );
                crate::modules::system::logger::log_info("Background OAuth flow channel closed");
            }
        }
    });

    Ok(Json(serde_json::json!({
        "url": auth_url,
        "state": state_str
    })))
}

pub(crate) async fn admin_get_oauth_flow_status() -> impl IntoResponse {
    Json(crate::modules::auth::oauth_server::get_oauth_flow_status())
}

fn get_oauth_redirect_uri(port: u16, _host: Option<&str>, _proto: Option<&str>) -> String {
    if let Ok(public_url) = std::env::var("ABV_PUBLIC_URL") {
        let base = public_url.trim_end_matches('/');
        format!("{}/auth/callback", base)
    } else {
        format!("http://localhost:{}/auth/callback", port)
    }
}
