use crate::modules::auth::oauth;
use serde::Serialize;
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::watch;
use url::Url;

struct OAuthFlowState {
    auth_url: String,
    redirect_uri: String,
    state: String,
    code_verifier: String,
    cancel_tx: watch::Sender<bool>,
    code_tx: mpsc::Sender<Result<String, String>>,
    code_rx: Option<mpsc::Receiver<Result<String, String>>>,
}

static OAUTH_FLOW_STATE: OnceLock<Mutex<Option<OAuthFlowState>>> = OnceLock::new();
static OAUTH_FLOW_STATUS: OnceLock<Mutex<OAuthFlowStatusSnapshot>> = OnceLock::new();
static OAUTH_FLOW_HISTORY: OnceLock<Mutex<Vec<OAuthFlowStatusEvent>>> = OnceLock::new();
static OAUTH_FLOW_COUNTERS: OnceLock<Mutex<OAuthFlowCounters>> = OnceLock::new();

fn get_oauth_flow_state() -> &'static Mutex<Option<OAuthFlowState>> {
    OAUTH_FLOW_STATE.get_or_init(|| Mutex::new(None))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthFlowPhase {
    Idle,
    Prepared,
    CallbackReceived,
    ExchangingToken,
    FetchingUserInfo,
    SavingAccount,
    Linked,
    Rejected,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct OAuthFlowStatusSnapshot {
    pub phase: OAuthFlowPhase,
    pub detail: Option<String>,
    pub account_email: Option<String>,
    pub updated_at_unix: i64,
    pub recent_events: Vec<OAuthFlowStatusEvent>,
    pub counters: OAuthFlowCounters,
}

#[derive(Debug, Clone, Serialize)]
pub struct OAuthFlowStatusEvent {
    pub phase: OAuthFlowPhase,
    pub detail: Option<String>,
    pub account_email: Option<String>,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct OAuthFlowCounters {
    pub prepared_total: u64,
    pub callback_received_total: u64,
    pub exchanging_token_total: u64,
    pub linked_total: u64,
    pub rejected_total: u64,
    pub cancelled_total: u64,
    pub failed_total: u64,
    pub failed_by_code: HashMap<String, u64>,
}

impl OAuthFlowStatusSnapshot {
    fn idle() -> Self {
        Self {
            phase: OAuthFlowPhase::Idle,
            detail: None,
            account_email: None,
            updated_at_unix: chrono::Utc::now().timestamp(),
            recent_events: Vec::new(),
            counters: OAuthFlowCounters::default(),
        }
    }
}

fn get_oauth_flow_status_state() -> &'static Mutex<OAuthFlowStatusSnapshot> {
    OAUTH_FLOW_STATUS.get_or_init(|| Mutex::new(OAuthFlowStatusSnapshot::idle()))
}

fn get_oauth_flow_history_state() -> &'static Mutex<Vec<OAuthFlowStatusEvent>> {
    OAUTH_FLOW_HISTORY.get_or_init(|| Mutex::new(Vec::new()))
}

fn get_oauth_flow_counters_state() -> &'static Mutex<OAuthFlowCounters> {
    OAUTH_FLOW_COUNTERS.get_or_init(|| Mutex::new(OAuthFlowCounters::default()))
}

fn classify_failure_code(detail: Option<&str>) -> String {
    let value = detail.unwrap_or_default();
    if value.contains("oauth_state_mismatch") {
        "oauth.state_mismatch".to_string()
    } else if value.contains("oauth_state_missing") {
        "oauth.state_missing".to_string()
    } else if value.contains("oauth_flow_not_active") {
        "oauth.flow_not_active".to_string()
    } else if value.contains("oauth_exchange_failed") {
        "oauth.exchange_failed".to_string()
    } else if value.contains("oauth_refresh_token_missing") {
        "oauth.refresh_token_missing".to_string()
    } else if value.contains("oauth_user_info_failed") {
        "oauth.user_info_failed".to_string()
    } else if value.contains("oauth_save_account_failed") {
        "oauth.account_save_failed".to_string()
    } else if value.contains("oauth_access_denied") {
        "oauth.access_denied".to_string()
    } else if value.contains("oauth_background_flow_failed") {
        "oauth.background_flow_failed".to_string()
    } else if value.contains("oauth_flow_channel_closed")
        || value.contains("oauth_flow_receiver_dropped")
    {
        "oauth.channel_error".to_string()
    } else if value.contains("encryption_key_unavailable")
        || value.contains("E-CRYPTO-KEY-UNAVAILABLE")
    {
        "oauth.key_unavailable".to_string()
    } else {
        "oauth.unknown_failure".to_string()
    }
}

fn update_oauth_counters(phase: &OAuthFlowPhase, detail: Option<&str>) {
    if let Ok(mut counters) = get_oauth_flow_counters_state().lock() {
        match phase {
            OAuthFlowPhase::Prepared => counters.prepared_total += 1,
            OAuthFlowPhase::CallbackReceived => counters.callback_received_total += 1,
            OAuthFlowPhase::ExchangingToken => counters.exchanging_token_total += 1,
            OAuthFlowPhase::Linked => counters.linked_total += 1,
            OAuthFlowPhase::Rejected => counters.rejected_total += 1,
            OAuthFlowPhase::Cancelled => counters.cancelled_total += 1,
            OAuthFlowPhase::Failed => {
                counters.failed_total += 1;
                let code = classify_failure_code(detail);
                let entry = counters.failed_by_code.entry(code).or_insert(0);
                *entry += 1;
            }
            _ => {}
        }
    }
}

fn set_oauth_flow_status(
    phase: OAuthFlowPhase,
    detail: Option<String>,
    account_email: Option<String>,
) {
    let updated_at_unix = chrono::Utc::now().timestamp();
    update_oauth_counters(&phase, detail.as_deref());
    if let Ok(mut history) = get_oauth_flow_history_state().lock() {
        history.push(OAuthFlowStatusEvent {
            phase: phase.clone(),
            detail: detail.clone(),
            account_email: account_email.clone(),
            updated_at_unix,
        });
        if history.len() > 20 {
            let drain = history.len() - 20;
            history.drain(0..drain);
        }
    }
    if let Ok(mut status) = get_oauth_flow_status_state().lock() {
        *status = OAuthFlowStatusSnapshot {
            phase,
            detail,
            account_email,
            updated_at_unix,
            recent_events: Vec::new(),
            counters: OAuthFlowCounters::default(),
        };
    }
}

pub fn mark_oauth_flow_status(
    phase: OAuthFlowPhase,
    detail: Option<String>,
    account_email: Option<String>,
) {
    set_oauth_flow_status(phase, detail, account_email);
}

pub fn get_oauth_flow_status() -> OAuthFlowStatusSnapshot {
    let mut snapshot = get_oauth_flow_status_state()
        .lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| OAuthFlowStatusSnapshot::idle());
    if let Ok(history) = get_oauth_flow_history_state().lock() {
        snapshot.recent_events = history.clone();
    }
    if let Ok(counters) = get_oauth_flow_counters_state().lock() {
        snapshot.counters = counters.clone();
    }
    snapshot
}

#[cfg(test)]
pub fn reset_oauth_observability_for_tests() {
    if let Ok(mut status) = get_oauth_flow_status_state().lock() {
        *status = OAuthFlowStatusSnapshot::idle();
    }
    if let Ok(mut history) = get_oauth_flow_history_state().lock() {
        history.clear();
    }
    if let Ok(mut counters) = get_oauth_flow_counters_state().lock() {
        *counters = OAuthFlowCounters::default();
    }
}

fn oauth_success_html() -> &'static str {
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
    <html>\
    <body style='font-family: sans-serif; text-align: center; padding: 50px;'>\
    <h1 style='color: green;'>✅ Authorization Received</h1>\
    <p>The authorization code was received. You can close this window and return to the application.</p>\
    <p>Account linking continues after this step and may still fail; check terminal logs if needed.</p>\
    <script>setTimeout(function() { window.close(); }, 2000);</script>\
    </body>\
    </html>"
}

fn oauth_fail_html() -> &'static str {
    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
    <html>\
    <body style='font-family: sans-serif; text-align: center; padding: 50px;'>\
    <h1 style='color: red;'>❌ Authorization Failed</h1>\
    <p>Failed to obtain Authorization Code. Please return to the app and try again.</p>\
    </body>\
    </html>"
}

fn oauth_rejected_html() -> &'static str {
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
    <html>\
    <body style='font-family: sans-serif; text-align: center; padding: 50px;'>\
    <h1 style='color: #b45309;'>Authorization Rejected</h1>\
    <p>You declined the OAuth consent screen. Return to the app if you want to retry.</p>\
    </body>\
    </html>"
}

#[cfg(target_os = "windows")]
fn open_browser_url(url: &str) -> Result<(), String> {
    Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn()
        .map_err(|e| format!("failed_to_open_browser: {}", e))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn open_browser_url(url: &str) -> Result<(), String> {
    Command::new("open")
        .arg(url)
        .spawn()
        .map_err(|e| format!("failed_to_open_browser: {}", e))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_browser_url(url: &str) -> Result<(), String> {
    Command::new("xdg-open")
        .arg(url)
        .spawn()
        .map_err(|e| format!("failed_to_open_browser: {}", e))?;
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn open_browser_url(_url: &str) -> Result<(), String> {
    Err("unsupported_platform_for_auto_browser_open".to_string())
}

async fn ensure_oauth_flow_prepared() -> Result<String, String> {
    if let Ok(mut state) = get_oauth_flow_state().lock() {
        if let Some(s) = state.as_mut() {
            if s.code_rx.is_some() {
                set_oauth_flow_status(
                    OAuthFlowPhase::Prepared,
                    Some("oauth_flow_reused".to_string()),
                    None,
                );
                return Ok(s.auth_url.clone());
            } else {
                let _ = s.cancel_tx.send(true);
                *state = None;
                set_oauth_flow_status(
                    OAuthFlowPhase::Cancelled,
                    Some("oauth_flow_superseded".to_string()),
                    None,
                );
            }
        }
    }
    let mut ipv4_listener: Option<TcpListener> = None;
    let mut ipv6_listener: Option<TcpListener> = None;
    let port: u16;
    match TcpListener::bind("[::1]:0").await {
        Ok(l6) => {
            port = l6
                .local_addr()
                .map_err(|e| format!("failed_to_get_local_port: {}", e))?
                .port();
            ipv6_listener = Some(l6);

            match TcpListener::bind(format!("127.0.0.1:{}", port)).await {
                Ok(l4) => ipv4_listener = Some(l4),
                Err(e) => {
                    crate::modules::system::logger::log_warn(&format!(
                        "[W-OAUTH-IPV4-BIND] failed_to_bind_ipv4_callback_port_127_0_0_1:{} (will only listen on IPv6): {}",
                        port, e
                    ));
                }
            }
        }
        Err(_) => {
            let l4 = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("failed_to_bind_local_port: {}", e))?;
            port = l4
                .local_addr()
                .map_err(|e| format!("failed_to_get_local_port: {}", e))?
                .port();
            ipv4_listener = Some(l4);

            match TcpListener::bind(format!("[::1]:{}", port)).await {
                Ok(l6) => ipv6_listener = Some(l6),
                Err(e) => {
                    crate::modules::system::logger::log_warn(&format!(
                        "[W-OAUTH-IPV6-BIND] failed_to_bind_ipv6_callback_port_::1:{} (will only listen on IPv4): {}",
                        port, e
                    ));
                }
            }
        }
    }

    let has_ipv4 = ipv4_listener.is_some();
    let has_ipv6 = ipv6_listener.is_some();

    let redirect_uri = if has_ipv4 && has_ipv6 {
        format!("http://localhost:{}/auth/callback", port)
    } else if has_ipv4 {
        format!("http://127.0.0.1:{}/auth/callback", port)
    } else {
        format!("http://[::1]:{}/auth/callback", port)
    };

    let state_str = uuid::Uuid::new_v4().to_string();
    let code_verifier = oauth::generate_pkce_verifier();
    let code_challenge = oauth::pkce_challenge_s256(&code_verifier);
    let auth_url = oauth::get_auth_url(&redirect_uri, &state_str, &code_challenge)?;
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (code_tx, code_rx) = mpsc::channel::<Result<String, String>>(1);
    if let Some(l4) = ipv4_listener {
        let tx = code_tx.clone();
        let mut rx = cancel_rx.clone();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = tokio::select! {
                res = l4.accept() => res.map_err(|e| format!("failed_to_accept_connection: {}", e)),
                _ = rx.changed() => Err("OAuth cancelled".to_string()),
            } {
                let mut buffer = [0u8; 4096];
                let bytes_read = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                let query_params = request
                    .lines()
                    .next()
                    .and_then(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            Some(parts[1])
                        } else {
                            None
                        }
                    })
                    .and_then(|path| Url::parse(&format!("http://localhost{}", path)).ok())
                    .map(|url| {
                        let mut code = None;
                        let mut state = None;
                        let mut error = None;
                        let mut error_description = None;
                        for (k, v) in url.query_pairs() {
                            if k == "code" {
                                code = Some(v.to_string());
                            } else if k == "state" {
                                state = Some(v.to_string());
                            } else if k == "error" {
                                error = Some(v.to_string());
                            } else if k == "error_description" {
                                error_description = Some(v.to_string());
                            }
                        }
                        (code, state, error, error_description)
                    });

                let (code, received_state, error, error_description) = match query_params {
                    Some((c, s, e, d)) => (c, s, e, d),
                    None => (None, None, None, None),
                };

                if code.is_none() && bytes_read > 0 {
                    crate::modules::system::logger::log_error(&format!(
                        "[E-OAUTH-CALLBACK-PARSE] oauth_callback_failed_to_parse_code_raw_request: {}",
                        &request.chars().take(512).collect::<String>()
                    ));
                }
                let state_valid = {
                    if let Ok(lock) = get_oauth_flow_state().lock() {
                        if let Some(s) = lock.as_ref() {
                            received_state.as_ref() == Some(&s.state)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };

                let (result, response_html) = match (code, error, state_valid) {
                    (None, Some(error), _) if error == "access_denied" => {
                        set_oauth_flow_status(
                            OAuthFlowPhase::Rejected,
                            Some("oauth_access_denied".to_string()),
                            None,
                        );
                        crate::modules::system::logger::log_warn(
                            "[W-OAUTH-ACCESS-DENIED] oauth_consent_screen_rejected_by_user",
                        );
                        (
                            Err("OAuth access denied".to_string()),
                            oauth_rejected_html(),
                        )
                    }
                    (None, Some(error), _) => {
                        let detail = if let Some(desc) = error_description {
                            format!("oauth_error_{}: {}", error, desc)
                        } else {
                            format!("oauth_error_{}", error)
                        };
                        set_oauth_flow_status(OAuthFlowPhase::Failed, Some(detail.clone()), None);
                        crate::modules::system::logger::log_error(&format!(
                            "[E-OAUTH-CALLBACK-ERROR] oauth_callback_returned_error: {}",
                            detail
                        ));
                        (Err(format!("OAuth error: {}", error)), oauth_fail_html())
                    }
                    (Some(code), _, true) => {
                        set_oauth_flow_status(
                            OAuthFlowPhase::CallbackReceived,
                            Some("authorization_code_captured_ipv4".to_string()),
                            None,
                        );
                        crate::modules::system::logger::log_info(
                            "Successfully captured OAuth code from IPv4 listener",
                        );
                        (Ok(code), oauth_success_html())
                    }
                    (Some(_), _, false) => {
                        set_oauth_flow_status(
                            OAuthFlowPhase::Failed,
                            Some("oauth_state_mismatch".to_string()),
                            None,
                        );
                        crate::modules::system::logger::log_error(
                            "[E-OAUTH-STATE-MISMATCH] oauth_callback_state_mismatch_csrf_protection",
                        );
                        (Err("OAuth state mismatch".to_string()), oauth_fail_html())
                    }
                    (None, _, _) => (
                        {
                            set_oauth_flow_status(
                                OAuthFlowPhase::Failed,
                                Some("authorization_code_missing_in_callback".to_string()),
                                None,
                            );
                            Err("Failed to get Authorization Code in callback".to_string())
                        },
                        oauth_fail_html(),
                    ),
                };

                let _ = stream.write_all(response_html.as_bytes()).await;
                let _ = stream.flush().await;

                let _ = tx.send(result).await;
            }
        });
    }

    if let Some(l6) = ipv6_listener {
        let tx = code_tx.clone();
        let mut rx = cancel_rx;
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = tokio::select! {
                res = l6.accept() => res.map_err(|e| format!("failed_to_accept_connection: {}", e)),
                _ = rx.changed() => Err("OAuth cancelled".to_string()),
            } {
                let mut buffer = [0u8; 4096];
                let bytes_read = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);

                let query_params = request
                    .lines()
                    .next()
                    .and_then(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            Some(parts[1])
                        } else {
                            None
                        }
                    })
                    .and_then(|path| Url::parse(&format!("http://localhost{}", path)).ok())
                    .map(|url| {
                        let mut code = None;
                        let mut state = None;
                        let mut error = None;
                        let mut error_description = None;
                        for (k, v) in url.query_pairs() {
                            if k == "code" {
                                code = Some(v.to_string());
                            } else if k == "state" {
                                state = Some(v.to_string());
                            } else if k == "error" {
                                error = Some(v.to_string());
                            } else if k == "error_description" {
                                error_description = Some(v.to_string());
                            }
                        }
                        (code, state, error, error_description)
                    });

                let (code, received_state, error, error_description) = match query_params {
                    Some((c, s, e, d)) => (c, s, e, d),
                    None => (None, None, None, None),
                };

                if code.is_none() && bytes_read > 0 {
                    crate::modules::system::logger::log_error(&format!(
                        "[E-OAUTH-CALLBACK-PARSE] oauth_callback_failed_to_parse_code_ipv6_raw_request: {}",
                        &request.chars().take(512).collect::<String>()
                    ));
                }
                let state_valid = {
                    if let Ok(lock) = get_oauth_flow_state().lock() {
                        if let Some(s) = lock.as_ref() {
                            received_state.as_ref() == Some(&s.state)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };

                let (result, response_html) = match (code, error, state_valid) {
                    (None, Some(error), _) if error == "access_denied" => {
                        set_oauth_flow_status(
                            OAuthFlowPhase::Rejected,
                            Some("oauth_access_denied".to_string()),
                            None,
                        );
                        crate::modules::system::logger::log_warn(
                            "[W-OAUTH-ACCESS-DENIED] oauth_consent_screen_rejected_by_user_ipv6",
                        );
                        (
                            Err("OAuth access denied".to_string()),
                            oauth_rejected_html(),
                        )
                    }
                    (None, Some(error), _) => {
                        let detail = if let Some(desc) = error_description {
                            format!("oauth_error_{}: {}", error, desc)
                        } else {
                            format!("oauth_error_{}", error)
                        };
                        set_oauth_flow_status(OAuthFlowPhase::Failed, Some(detail.clone()), None);
                        crate::modules::system::logger::log_error(&format!(
                            "[E-OAUTH-CALLBACK-ERROR] oauth_callback_returned_error_ipv6: {}",
                            detail
                        ));
                        (Err(format!("OAuth error: {}", error)), oauth_fail_html())
                    }
                    (Some(code), _, true) => {
                        set_oauth_flow_status(
                            OAuthFlowPhase::CallbackReceived,
                            Some("authorization_code_captured_ipv6".to_string()),
                            None,
                        );
                        crate::modules::system::logger::log_info(
                            "Successfully captured OAuth code from IPv6 listener",
                        );
                        (Ok(code), oauth_success_html())
                    }
                    (Some(_), _, false) => {
                        set_oauth_flow_status(
                            OAuthFlowPhase::Failed,
                            Some("oauth_state_mismatch".to_string()),
                            None,
                        );
                        crate::modules::system::logger::log_error(
                            "[E-OAUTH-STATE-MISMATCH] oauth_callback_state_mismatch_ipv6_csrf_protection",
                        );
                        (Err("OAuth state mismatch".to_string()), oauth_fail_html())
                    }
                    (None, _, _) => (
                        {
                            set_oauth_flow_status(
                                OAuthFlowPhase::Failed,
                                Some("authorization_code_missing_in_callback".to_string()),
                                None,
                            );
                            Err("Failed to get Authorization Code in callback".to_string())
                        },
                        oauth_fail_html(),
                    ),
                };

                let _ = stream.write_all(response_html.as_bytes()).await;
                let _ = stream.flush().await;

                let _ = tx.send(result).await;
            }
        });
    }
    if let Ok(mut state) = get_oauth_flow_state().lock() {
        *state = Some(OAuthFlowState {
            auth_url: auth_url.clone(),
            redirect_uri,
            state: state_str,
            code_verifier,
            cancel_tx,
            code_tx,
            code_rx: Some(code_rx),
        });
    }
    set_oauth_flow_status(
        OAuthFlowPhase::Prepared,
        Some("oauth_flow_prepared".to_string()),
        None,
    );

    Ok(auth_url)
}
pub async fn prepare_oauth_url() -> Result<String, String> {
    ensure_oauth_flow_prepared().await
}
pub fn cancel_oauth_flow() {
    if let Ok(mut state) = get_oauth_flow_state().lock() {
        if let Some(s) = state.take() {
            let _ = s.cancel_tx.send(true);
            crate::modules::system::logger::log_info("Sent OAuth cancellation signal");
            set_oauth_flow_status(
                OAuthFlowPhase::Cancelled,
                Some("oauth_flow_cancelled".to_string()),
                None,
            );
        }
    }
}
pub async fn start_oauth_flow() -> Result<oauth::TokenResponse, String> {
    let auth_url = ensure_oauth_flow_prepared().await?;
    open_browser_url(&auth_url).map_err(|e| {
        format!(
            "{}; use prepare_oauth_url + complete_oauth_flow for manual flow. auth_url={}",
            e, auth_url
        )
    })?;
    let (mut code_rx, redirect_uri, code_verifier) = {
        let mut lock = get_oauth_flow_state()
            .lock()
            .map_err(|_| "OAuth state lock corrupted".to_string())?;
        let Some(state) = lock.as_mut() else {
            return Err("OAuth state does not exist".to_string());
        };
        let rx = state
            .code_rx
            .take()
            .ok_or_else(|| "OAuth authorization already in progress".to_string())?;
        (rx, state.redirect_uri.clone(), state.code_verifier.clone())
    };
    let code = match code_rx.recv().await {
        Some(Ok(code)) => {
            set_oauth_flow_status(
                OAuthFlowPhase::CallbackReceived,
                Some("authorization_code_received".to_string()),
                None,
            );
            code
        }
        Some(Err(e)) => {
            set_oauth_flow_status(OAuthFlowPhase::Failed, Some(e.clone()), None);
            return Err(e);
        }
        None => {
            set_oauth_flow_status(
                OAuthFlowPhase::Failed,
                Some("oauth_flow_channel_closed".to_string()),
                None,
            );
            return Err("OAuth flow channel closed unexpectedly".to_string());
        }
    };
    if let Ok(mut lock) = get_oauth_flow_state().lock() {
        *lock = None;
    }
    set_oauth_flow_status(
        OAuthFlowPhase::ExchangingToken,
        Some("oauth_token_exchange_started".to_string()),
        None,
    );
    oauth::exchange_code(&code, &redirect_uri, &code_verifier)
        .await
        .inspect_err(|e| {
            set_oauth_flow_status(OAuthFlowPhase::Failed, Some(e.clone()), None);
        })
}
pub async fn complete_oauth_flow() -> Result<oauth::TokenResponse, String> {
    let _ = ensure_oauth_flow_prepared().await?;
    let (mut code_rx, redirect_uri, code_verifier) = {
        let mut lock = get_oauth_flow_state()
            .lock()
            .map_err(|_| "OAuth state lock corrupted".to_string())?;
        let Some(state) = lock.as_mut() else {
            return Err("OAuth state does not exist".to_string());
        };
        let rx = state
            .code_rx
            .take()
            .ok_or_else(|| "OAuth authorization already in progress".to_string())?;
        (rx, state.redirect_uri.clone(), state.code_verifier.clone())
    };

    let code = match code_rx.recv().await {
        Some(Ok(code)) => {
            set_oauth_flow_status(
                OAuthFlowPhase::CallbackReceived,
                Some("authorization_code_received".to_string()),
                None,
            );
            code
        }
        Some(Err(e)) => {
            set_oauth_flow_status(OAuthFlowPhase::Failed, Some(e.clone()), None);
            return Err(e);
        }
        None => {
            set_oauth_flow_status(
                OAuthFlowPhase::Failed,
                Some("oauth_flow_channel_closed".to_string()),
                None,
            );
            return Err("OAuth flow channel closed unexpectedly".to_string());
        }
    };

    if let Ok(mut lock) = get_oauth_flow_state().lock() {
        *lock = None;
    }
    set_oauth_flow_status(
        OAuthFlowPhase::ExchangingToken,
        Some("oauth_token_exchange_started".to_string()),
        None,
    );
    oauth::exchange_code(&code, &redirect_uri, &code_verifier)
        .await
        .inspect_err(|e| {
            set_oauth_flow_status(OAuthFlowPhase::Failed, Some(e.clone()), None);
        })
}
pub async fn submit_oauth_code(
    code_input: String,
    state_input: Option<String>,
) -> Result<(), String> {
    let tx = {
        let lock = get_oauth_flow_state().lock().map_err(|e| e.to_string())?;
        if let Some(state) = lock.as_ref() {
            if let Some(provided_state) = state_input {
                if provided_state != state.state {
                    set_oauth_flow_status(
                        OAuthFlowPhase::Failed,
                        Some("oauth_state_mismatch".to_string()),
                        None,
                    );
                    return Err("OAuth state mismatch (CSRF protection)".to_string());
                }
            } else {
                set_oauth_flow_status(
                    OAuthFlowPhase::Failed,
                    Some("oauth_state_missing".to_string()),
                    None,
                );
                return Err("Missing OAuth state (CSRF protection)".to_string());
            }
            state.code_tx.clone()
        } else {
            set_oauth_flow_status(
                OAuthFlowPhase::Failed,
                Some("oauth_flow_not_active".to_string()),
                None,
            );
            return Err("No active OAuth flow found".to_string());
        }
    };
    let code = if code_input.starts_with("http") {
        if let Ok(url) = Url::parse(&code_input) {
            url.query_pairs()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.to_string())
                .unwrap_or(code_input)
        } else {
            code_input
        }
    } else {
        code_input
    };

    crate::modules::system::logger::log_info("Received manual OAuth code submission");
    set_oauth_flow_status(
        OAuthFlowPhase::CallbackReceived,
        Some("authorization_code_received".to_string()),
        None,
    );
    tx.send(Ok(code)).await.map_err(|_| {
        set_oauth_flow_status(
            OAuthFlowPhase::Failed,
            Some("oauth_flow_receiver_dropped".to_string()),
            None,
        );
        "Failed to send code to OAuth flow (receiver dropped)".to_string()
    })?;
    if let Ok(mut lock) = get_oauth_flow_state().lock() {
        *lock = None;
    }

    Ok(())
}
type ManualOAuthFlowPreparation = (String, String, mpsc::Receiver<Result<String, String>>);

pub fn prepare_oauth_flow_manually(
    redirect_uri: String,
    state_str: String,
) -> Result<ManualOAuthFlowPreparation, String> {
    let code_verifier = oauth::generate_pkce_verifier();
    let code_challenge = oauth::pkce_challenge_s256(&code_verifier);
    let auth_url = oauth::get_auth_url(&redirect_uri, &state_str, &code_challenge)?;
    if let Ok(mut lock) = get_oauth_flow_state().lock() {
        if let Some(s) = lock.as_mut() {
            let _ = s.cancel_tx.send(true);
            *lock = None;
            set_oauth_flow_status(
                OAuthFlowPhase::Cancelled,
                Some("oauth_flow_superseded".to_string()),
                None,
            );
        }
    }

    let (cancel_tx, _cancel_rx) = watch::channel(false);
    let (code_tx, code_rx) = mpsc::channel(1);

    if let Ok(mut state) = get_oauth_flow_state().lock() {
        *state = Some(OAuthFlowState {
            auth_url: auth_url.clone(),
            redirect_uri: redirect_uri.clone(),
            state: state_str,
            code_verifier: code_verifier.clone(),
            cancel_tx,
            code_tx,
            code_rx: None,
        });
    }
    set_oauth_flow_status(
        OAuthFlowPhase::Prepared,
        Some("oauth_flow_prepared".to_string()),
        None,
    );

    Ok((auth_url, code_verifier, code_rx))
}
