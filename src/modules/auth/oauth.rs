use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const OAUTH_SCOPES: &str = concat!(
    "openid ",
    "https://www.googleapis.com/auth/cloud-platform ",
    "https://www.googleapis.com/auth/userinfo.email ",
    "https://www.googleapis.com/auth/userinfo.profile ",
    "https://www.googleapis.com/auth/cclog ",
    "https://www.googleapis.com/auth/experimentsandconfigs"
);

fn env_first(keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Ok(v) = std::env::var(k) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

pub(crate) fn client_id() -> Result<String, String> {
    env_first(&[
        "GEPHYR_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_ID",
    ])
    .ok_or_else(|| {
        "Missing Google OAuth client_id. Set GEPHYR_OAUTH_CLIENT_ID (or GOOGLE_OAUTH_CLIENT_ID)."
            .to_string()
    })
}

fn client_secret_optional() -> Option<String> {
    env_first(&[
        "GEPHYR_OAUTH_CLIENT_SECRET",
        "GOOGLE_OAUTH_CLIENT_SECRET",
        "GOOGLE_OAUTH_CLIENT_SECRET",
    ])
}

fn oauth_user_agent() -> String {
    env_first(&["OAUTH_USER_AGENT"])
        .unwrap_or_else(|| crate::constants::USER_AGENT.as_str().to_string())
}

pub fn generate_pkce_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn pkce_challenge_s256(verifier: &str) -> String {
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub email: String,
    #[serde(default, alias = "verified_email")]
    pub email_verified: Option<bool>,
    #[serde(default, alias = "id")]
    pub sub: Option<String>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    #[serde(default)]
    pub hd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedIdentity {
    pub email: String,
    pub name: Option<String>,
    pub google_sub: Option<String>,
    pub email_verified: bool,
    pub hd: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefreshObservabilitySnapshot {
    pub refresh_attempts_last_minute: usize,
    pub refresh_attempts_by_account_last_minute: HashMap<String, usize>,
}

#[derive(Default)]
struct RefreshObservabilityState {
    global_timestamps: VecDeque<Instant>,
    per_account_timestamps: HashMap<String, VecDeque<Instant>>,
}

impl UserInfo {
    pub fn get_display_name(&self) -> Option<String> {
        if let Some(name) = &self.name {
            if !name.trim().is_empty() {
                return Some(name.clone());
            }
        }
        match (&self.given_name, &self.family_name) {
            (Some(given), Some(family)) => Some(format!("{} {}", given, family)),
            (Some(given), None) => Some(given.clone()),
            (None, Some(family)) => Some(family.clone()),
            (None, None) => None,
        }
    }

    pub fn is_email_verified(&self) -> bool {
        self.email_verified.unwrap_or(false)
    }

    pub fn google_sub(&self) -> Option<String> {
        self.sub.clone()
    }
}

fn load_account_device_profile(account_id: Option<&str>) -> Option<crate::models::DeviceProfile> {
    let id = account_id?;
    crate::modules::auth::account::load_account(id)
        .ok()
        .and_then(|account| account.device_profile)
}

fn apply_google_identity_headers(
    mut request: reqwest::RequestBuilder,
    account_id: Option<&str>,
) -> reqwest::RequestBuilder {
    request = request.header(reqwest::header::USER_AGENT, oauth_user_agent());

    if let Some(profile) = load_account_device_profile(account_id) {
        if let Some(v) = profile.machine_id.as_deref() {
            request = request.header("x-machine-id", v);
        }
        if let Some(v) = profile.mac_machine_id.as_deref() {
            request = request.header("x-mac-machine-id", v);
        }
        if let Some(v) = profile.dev_device_id.as_deref() {
            request = request.header("x-dev-device-id", v);
        }
        if let Some(v) = profile.sqm_id.as_deref() {
            request = request.header("x-sqm-id", v);
        }
    }

    request
}

fn refresh_jitter_seconds(account_id: Option<&str>) -> i64 {
    let mut hasher = DefaultHasher::new();
    account_id.unwrap_or("generic-account").hash(&mut hasher);
    30 + (hasher.finish() % 91) as i64
}

fn refresh_observability_state() -> &'static Mutex<RefreshObservabilityState> {
    static STATE: OnceLock<Mutex<RefreshObservabilityState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(RefreshObservabilityState::default()))
}

fn cleanup_refresh_observability_locked(state: &mut RefreshObservabilityState, now: Instant) {
    let window_start = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);

    while let Some(ts) = state.global_timestamps.front() {
        if *ts < window_start {
            state.global_timestamps.pop_front();
        } else {
            break;
        }
    }

    state.per_account_timestamps.retain(|_, queue| {
        while let Some(ts) = queue.front() {
            if *ts < window_start {
                queue.pop_front();
            } else {
                break;
            }
        }
        !queue.is_empty()
    });
}

fn record_refresh_attempt(account_id: Option<&str>) {
    if let Ok(mut state) = refresh_observability_state().lock() {
        let now = Instant::now();
        cleanup_refresh_observability_locked(&mut state, now);

        state.global_timestamps.push_back(now);
        let key = account_id.unwrap_or("generic").to_string();
        state
            .per_account_timestamps
            .entry(key)
            .or_default()
            .push_back(now);
    }
}

pub fn refresh_observability_snapshot() -> RefreshObservabilitySnapshot {
    if let Ok(mut state) = refresh_observability_state().lock() {
        cleanup_refresh_observability_locked(&mut state, Instant::now());
        return RefreshObservabilitySnapshot {
            refresh_attempts_last_minute: state.global_timestamps.len(),
            refresh_attempts_by_account_last_minute: state
                .per_account_timestamps
                .iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect(),
        };
    }

    RefreshObservabilitySnapshot {
        refresh_attempts_last_minute: 0,
        refresh_attempts_by_account_last_minute: HashMap::new(),
    }
}

#[cfg(test)]
fn clear_refresh_observability_for_tests() {
    if let Ok(mut state) = refresh_observability_state().lock() {
        *state = RefreshObservabilityState::default();
    }
}

pub fn refresh_window_seconds(account_id: Option<&str>) -> i64 {
    300 + refresh_jitter_seconds(account_id)
}

pub fn should_refresh_token(
    expiry_timestamp: i64,
    now_timestamp: i64,
    account_id: Option<&str>,
) -> bool {
    expiry_timestamp <= now_timestamp + refresh_window_seconds(account_id)
}

pub fn get_auth_url(
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> Result<String, String> {
    let cid = client_id()?;

    let params = vec![
        ("client_id", cid.as_str()),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", OAUTH_SCOPES),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("include_granted_scopes", "true"),
        ("state", state),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ];

    let url = url::Url::parse_with_params(AUTH_URL, &params)
        .map_err(|e| format!("Invalid Auth URL: {}", e))?;
    Ok(url.to_string())
}
pub async fn exchange_code(
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResponse, String> {
    exchange_code_at(code, redirect_uri, code_verifier, TOKEN_URL).await
}

async fn exchange_code_at(
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    token_url: &str,
) -> Result<TokenResponse, String> {
    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(None, 60)
            .await
            .map_err(|e| format!("Failed to prepare OAuth exchange client: {}", e))?
    } else {
        crate::utils::http::get_long_client()
    };

    let cid = client_id()?;
    let secret = client_secret_optional();
    let mut params: Vec<(&str, String)> = vec![
        ("client_id", cid),
        ("code", code.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("grant_type", "authorization_code".to_string()),
        ("code_verifier", code_verifier.to_string()),
    ];
    if let Some(s) = secret {
        params.push(("client_secret", s));
    }

    let response = apply_google_identity_headers(client.post(token_url), None)
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                format!("Token exchange request failed: {}. Please check your network proxy settings to ensure a stable connection to Google services.", e)
            } else {
                format!("Token exchange request failed: {}", e)
            }
        })?;

    if response.status().is_success() {
        let token_res = response
            .json::<TokenResponse>()
            .await
            .map_err(|e| format!("Token parsing failed: {}", e))?;
        crate::modules::system::logger::log_info(&format!(
            "Token exchange successful! access_token: {}..., refresh_token: {}",
            &token_res.access_token.chars().take(20).collect::<String>(),
            if token_res.refresh_token.is_some() {
                "✓"
            } else {
                "✗ Missing"
            }
        ));
        if token_res.refresh_token.is_none() {
            crate::modules::system::logger::log_warn(
                "Warning: Google did not return a refresh_token. Potential reasons:\n\
                 1. User has previously authorized this application\n\
                 2. Need to revoke access in Google Cloud Console and retry\n\
                 3. OAuth parameter configuration issue",
            );
        }

        Ok(token_res)
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(format!("Token exchange failed: {}", error_text))
    }
}
pub async fn refresh_access_token(
    refresh_token: &str,
    account_id: Option<&str>,
) -> Result<TokenResponse, String> {
    refresh_access_token_at(refresh_token, account_id, TOKEN_URL).await
}

pub async fn revoke_refresh_token(
    refresh_token: &str,
    account_id: Option<&str>,
) -> Result<(), String> {
    revoke_refresh_token_at(refresh_token, account_id, REVOKE_URL).await
}

async fn refresh_access_token_at(
    refresh_token: &str,
    account_id: Option<&str>,
    token_url: &str,
) -> Result<TokenResponse, String> {
    record_refresh_attempt(account_id);

    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(account_id, 60)
            .await
            .map_err(|e| format!("Failed to prepare OAuth refresh client: {}", e))?
    } else {
        crate::utils::http::get_long_client()
    };

    let cid = client_id()?;
    let secret = client_secret_optional();
    let mut params: Vec<(&str, String)> = vec![
        ("client_id", cid),
        ("refresh_token", refresh_token.to_string()),
        ("grant_type", "refresh_token".to_string()),
    ];
    if let Some(s) = secret {
        params.push(("client_secret", s));
    }
    if let Some(id) = account_id {
        crate::modules::system::logger::log_info(&format!(
            "Refreshing Token for account: {}...",
            id
        ));
    } else {
        crate::modules::system::logger::log_info(
            "Refreshing Token for generic request (no account_id)...",
        );
    }

    let response = apply_google_identity_headers(client.post(token_url), account_id)
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                format!("Refresh request failed: {}. Unable to connect to the Google authorization server. Please check your proxy settings.", e)
            } else {
                format!("Refresh request failed: {}", e)
            }
        })?;

    if response.status().is_success() {
        let token_data = response
            .json::<TokenResponse>()
            .await
            .map_err(|e| format!("Refresh data parsing failed: {}", e))?;

        crate::modules::system::logger::log_info(&format!(
            "Token refreshed successfully! Expires in: {} seconds",
            token_data.expires_in
        ));
        Ok(token_data)
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(format!("Refresh failed: {}", error_text))
    }
}

async fn revoke_refresh_token_at(
    refresh_token: &str,
    account_id: Option<&str>,
    revoke_url: &str,
) -> Result<(), String> {
    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(account_id, 15)
            .await
            .map_err(|e| format!("Failed to prepare OAuth revoke client: {}", e))?
    } else {
        crate::utils::http::get_client()
    };

    let params = vec![
        ("token", refresh_token.to_string()),
        ("token_type_hint", "refresh_token".to_string()),
    ];

    let response = apply_google_identity_headers(client.post(revoke_url), account_id)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Revoke request failed: {}", e))?;

    // Google typically returns 200 even when the token is already invalid. If it doesn't,
    // we still treat 400 as a "best-effort" success to preserve idempotence.
    if response.status().is_success() || response.status() == reqwest::StatusCode::BAD_REQUEST {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(format!("Revoke failed: HTTP {} - {}", status, body))
}
pub async fn get_user_info(
    access_token: &str,
    account_id: Option<&str>,
) -> Result<UserInfo, String> {
    get_user_info_at(access_token, account_id, USERINFO_URL).await
}

async fn get_user_info_at(
    access_token: &str,
    account_id: Option<&str>,
    userinfo_url: &str,
) -> Result<UserInfo, String> {
    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(account_id, 15)
            .await
            .map_err(|e| format!("Failed to prepare userinfo client: {}", e))?
    } else {
        crate::utils::http::get_client()
    };

    let response = apply_google_identity_headers(client.get(userinfo_url), account_id)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("User info request failed: {}", e))?;

    if response.status().is_success() {
        response
            .json::<UserInfo>()
            .await
            .map_err(|e| format!("User info parsing failed: {}", e))
    } else {
        let error_text = response.text().await.unwrap_or_default();
        Err(format!("Failed to get user info: {}", error_text))
    }
}

async fn verify_identity_at(
    access_token: &str,
    raw_id_token: Option<&str>,
    account_id: Option<&str>,
    userinfo_url: &str,
) -> Result<VerifiedIdentity, String> {
    if let Some(raw) = raw_id_token {
        let claims = crate::modules::auth::id_token::validate_id_token(raw)
            .await
            .map_err(|e| format!("Invalid id_token: {}", e))?;
        return Ok(VerifiedIdentity {
            email: claims.email,
            name: claims.name,
            google_sub: Some(claims.sub),
            email_verified: claims.email_verified,
            hd: claims.hd,
        });
    }

    let user_info = get_user_info_at(access_token, account_id, userinfo_url).await?;
    if !user_info.is_email_verified() {
        return Err("Google userinfo rejected: email is not verified".to_string());
    }
    let google_sub = user_info
        .google_sub()
        .filter(|sub| !sub.trim().is_empty())
        .ok_or_else(|| "Google userinfo rejected: missing subject identifier".to_string())?;

    Ok(VerifiedIdentity {
        email: user_info.email.clone(),
        name: user_info.get_display_name(),
        google_sub: Some(google_sub),
        email_verified: true,
        hd: user_info.hd.clone(),
    })
}

pub async fn verify_identity(
    access_token: &str,
    raw_id_token: Option<&str>,
    account_id: Option<&str>,
) -> Result<VerifiedIdentity, String> {
    verify_identity_at(access_token, raw_id_token, account_id, USERINFO_URL).await
}

async fn refresh_and_verify_identity_at(
    refresh_token: &str,
    account_id: Option<&str>,
    token_url: &str,
    userinfo_url: &str,
) -> Result<(TokenResponse, VerifiedIdentity), String> {
    let token_res = refresh_access_token_at(refresh_token, account_id, token_url).await?;
    let identity = verify_identity_at(
        &token_res.access_token,
        token_res.id_token.as_deref(),
        account_id,
        userinfo_url,
    )
    .await?;
    Ok((token_res, identity))
}

pub async fn refresh_and_verify_identity(
    refresh_token: &str,
    account_id: Option<&str>,
) -> Result<(TokenResponse, VerifiedIdentity), String> {
    refresh_and_verify_identity_at(refresh_token, account_id, TOKEN_URL, USERINFO_URL).await
}

pub async fn ensure_fresh_token(
    current_token: &crate::models::TokenData,
    account_id: Option<&str>,
) -> Result<crate::models::TokenData, String> {
    let now = chrono::Local::now().timestamp();
    let refresh_window = refresh_window_seconds(account_id);
    if !should_refresh_token(current_token.expiry_timestamp, now, account_id) {
        return Ok(current_token.clone());
    }
    crate::modules::system::logger::log_info(&format!(
        "Token expiring soon for account {:?}, refreshing (window={}s)...",
        account_id, refresh_window
    ));
    let response = refresh_access_token(&current_token.refresh_token, account_id).await?;
    Ok(crate::models::TokenData::new(
        response.access_token,
        current_token.refresh_token.clone(),
        response.expires_in,
        current_token.email.clone(),
        current_token.project_id.clone(),
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ScopedEnvVar;
    use axum::{
        extract::State,
        http::HeaderMap,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::{Mutex, OnceLock};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;

    fn oauth_ua_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn oauth_ua_test_guard() -> std::sync::MutexGuard<'static, ()> {
        oauth_ua_test_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[derive(Clone)]
    struct MockOauthState {
        user_agents: Arc<AsyncMutex<Vec<String>>>,
        userinfo_response: serde_json::Value,
    }

    impl Default for MockOauthState {
        fn default() -> Self {
            Self {
                user_agents: Arc::new(AsyncMutex::new(Vec::new())),
                userinfo_response: json!({
                    "email": "ua-test@example.com",
                    "email_verified": true,
                    "sub": "sub-ua-test",
                    "name": "UA Test"
                }),
            }
        }
    }

    async fn token_capture_handler(
        State(state): State<MockOauthState>,
        headers: HeaderMap,
    ) -> Json<serde_json::Value> {
        if let Some(ua) = headers.get(reqwest::header::USER_AGENT) {
            if let Ok(ua_str) = ua.to_str() {
                state.user_agents.lock().await.push(ua_str.to_string());
            }
        }
        Json(json!({
            "access_token": "access-test-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "refresh-test-token",
            "id_token": null
        }))
    }

    async fn userinfo_capture_handler(
        State(state): State<MockOauthState>,
        headers: HeaderMap,
    ) -> Json<serde_json::Value> {
        if let Some(ua) = headers.get(reqwest::header::USER_AGENT) {
            if let Ok(ua_str) = ua.to_str() {
                state.user_agents.lock().await.push(ua_str.to_string());
            }
        }
        Json(state.userinfo_response.clone())
    }

    async fn start_mock_oauth_server_with_userinfo(
        userinfo_response: serde_json::Value,
    ) -> (String, MockOauthState, tokio::task::JoinHandle<()>) {
        let state = MockOauthState {
            userinfo_response,
            ..MockOauthState::default()
        };
        let app = Router::new()
            .route("/token", post(token_capture_handler))
            .route("/userinfo", get(userinfo_capture_handler))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test oauth listener");
        let addr = listener.local_addr().expect("test oauth local addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock oauth server should run");
        });

        (format!("http://{}", addr), state, handle)
    }

    async fn start_mock_oauth_server() -> (String, MockOauthState, tokio::task::JoinHandle<()>) {
        start_mock_oauth_server_with_userinfo(json!({
            "email": "ua-test@example.com",
            "email_verified": true,
            "sub": "sub-ua-test",
            "name": "UA Test"
        }))
        .await
    }

    #[test]
    fn test_get_auth_url_contains_state() {
        let _guard = oauth_ua_test_guard();
        std::env::set_var(
            "GEPHYR_OAUTH_CLIENT_ID",
            "test-client.apps.googleusercontent.com",
        );
        let redirect_uri = "http://localhost:8080/callback";
        let state = "test-state-123456";
        let verifier = generate_pkce_verifier();
        let challenge = pkce_challenge_s256(&verifier);
        let url = get_auth_url(redirect_uri, state, &challenge).expect("auth url");

        assert!(url.contains("state=test-state-123456"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn refresh_jitter_is_deterministic_and_in_range() {
        let a = refresh_jitter_seconds(Some("acct-1"));
        let b = refresh_jitter_seconds(Some("acct-1"));
        let c = refresh_jitter_seconds(Some("acct-2"));

        assert_eq!(a, b);
        assert!((30..=120).contains(&a));
        assert!((30..=120).contains(&c));
    }

    #[test]
    fn should_refresh_token_respects_account_window() {
        let now = 1_700_000_000_i64;
        let window = refresh_window_seconds(Some("acct-1"));

        assert!(should_refresh_token(now + window - 1, now, Some("acct-1")));
        assert!(!should_refresh_token(now + window + 1, now, Some("acct-1")));
    }

    #[test]
    fn oauth_user_agent_uses_default_when_override_missing() {
        let _guard = oauth_ua_test_guard();
        let previous = std::env::var("OAUTH_USER_AGENT").ok();
        std::env::remove_var("OAUTH_USER_AGENT");

        let ua = oauth_user_agent();
        assert_eq!(ua, crate::constants::USER_AGENT.as_str());

        match previous {
            Some(value) => std::env::set_var("OAUTH_USER_AGENT", value),
            None => std::env::remove_var("OAUTH_USER_AGENT"),
        }
    }

    #[test]
    fn oauth_user_agent_uses_override_when_set() {
        let _guard = oauth_ua_test_guard();
        let previous = std::env::var("OAUTH_USER_AGENT").ok();
        std::env::set_var("OAUTH_USER_AGENT", "vscode/1.95.0 gephyr-test");

        let ua = oauth_user_agent();
        assert_eq!(ua, "vscode/1.95.0 gephyr-test");

        match previous {
            Some(value) => std::env::set_var("OAUTH_USER_AGENT", value),
            None => std::env::remove_var("OAUTH_USER_AGENT"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_access_token_sends_user_agent_header() {
        let _guard = oauth_ua_test_guard();
        let _ua = ScopedEnvVar::set("OAUTH_USER_AGENT", "ua-integration-test");
        // Set both keys to avoid cross-test env races (other tests may remove only one).
        let _cid_primary = ScopedEnvVar::set(
            "GEPHYR_OAUTH_CLIENT_ID",
            "test-client.apps.googleusercontent.com",
        );
        let _cid_fallback = ScopedEnvVar::set(
            "GOOGLE_OAUTH_CLIENT_ID",
            "test-client.apps.googleusercontent.com",
        );

        let (base_url, state, server) = start_mock_oauth_server().await;
        let token_url = format!("{}/token", base_url);

        let _ = refresh_access_token_at("refresh-token", None, &token_url)
            .await
            .expect("refresh should succeed against mock server");
        let captured = state.user_agents.lock().await.clone();

        server.abort();

        assert!(
            captured.iter().any(|ua| ua == "ua-integration-test"),
            "expected OAuth refresh call to carry configured User-Agent"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_user_info_sends_user_agent_header() {
        let _guard = oauth_ua_test_guard();
        let previous_ua = std::env::var("OAUTH_USER_AGENT").ok();
        std::env::set_var("OAUTH_USER_AGENT", "ua-userinfo-test");

        let (base_url, state, server) = start_mock_oauth_server().await;
        let userinfo_url = format!("{}/userinfo", base_url);

        let _ = get_user_info_at("access-token", None, &userinfo_url)
            .await
            .expect("userinfo should succeed against mock server");
        let captured = state.user_agents.lock().await.clone();

        server.abort();

        assert!(
            captured.iter().any(|ua| ua == "ua-userinfo-test"),
            "expected OAuth userinfo call to carry configured User-Agent"
        );

        match previous_ua {
            Some(value) => std::env::set_var("OAUTH_USER_AGENT", value),
            None => std::env::remove_var("OAUTH_USER_AGENT"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_observability_snapshot_tracks_attempts() {
        let _guard = oauth_ua_test_guard();
        clear_refresh_observability_for_tests();

        // Set both keys to avoid cross-test env races (other tests may remove only one).
        let _cid_primary = ScopedEnvVar::set(
            "GEPHYR_OAUTH_CLIENT_ID",
            "test-client.apps.googleusercontent.com",
        );
        let _cid_fallback = ScopedEnvVar::set(
            "GOOGLE_OAUTH_CLIENT_ID",
            "test-client.apps.googleusercontent.com",
        );

        let (base_url, _state, server) = start_mock_oauth_server().await;
        let token_url = format!("{}/token", base_url);

        let _ = refresh_access_token_at("refresh-token-1", Some("acc-1"), &token_url)
            .await
            .expect("refresh should succeed");
        let _ = refresh_access_token_at("refresh-token-2", None, &token_url)
            .await
            .expect("refresh should succeed");

        let snapshot = refresh_observability_snapshot();
        server.abort();

        assert!(snapshot.refresh_attempts_last_minute >= 2);
        assert_eq!(
            snapshot
                .refresh_attempts_by_account_last_minute
                .get("acc-1")
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            snapshot
                .refresh_attempts_by_account_last_minute
                .get("generic")
                .copied()
                .unwrap_or(0),
            1
        );
        clear_refresh_observability_for_tests();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_identity_fallback_rejects_unverified_email() {
        let (_guard, previous_ua) = (
            oauth_ua_test_guard(),
            std::env::var("OAUTH_USER_AGENT").ok(),
        );
        std::env::set_var("OAUTH_USER_AGENT", "ua-verify-unverified");

        let (base_url, _state, server) = start_mock_oauth_server_with_userinfo(json!({
            "email": "unverified@example.com",
            "email_verified": false,
            "sub": "sub-unverified"
        }))
        .await;
        let userinfo_url = format!("{}/userinfo", base_url);

        let err = verify_identity_at("access-token", None, None, &userinfo_url)
            .await
            .expect_err("verify_identity fallback should fail for unverified email");

        server.abort();
        assert!(err.contains("email is not verified"));

        match previous_ua {
            Some(value) => std::env::set_var("OAUTH_USER_AGENT", value),
            None => std::env::remove_var("OAUTH_USER_AGENT"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_identity_fallback_rejects_missing_subject_identifier() {
        let (_guard, previous_ua) = (
            oauth_ua_test_guard(),
            std::env::var("OAUTH_USER_AGENT").ok(),
        );
        std::env::set_var("OAUTH_USER_AGENT", "ua-verify-missing-sub");

        let (base_url, _state, server) = start_mock_oauth_server_with_userinfo(json!({
            "email": "nosub@example.com",
            "email_verified": true,
            "name": "No Sub"
        }))
        .await;
        let userinfo_url = format!("{}/userinfo", base_url);

        let err = verify_identity_at("access-token", None, None, &userinfo_url)
            .await
            .expect_err("verify_identity fallback should fail when subject identifier is missing");

        server.abort();
        assert!(err.contains("missing subject identifier"));

        match previous_ua {
            Some(value) => std::env::set_var("OAUTH_USER_AGENT", value),
            None => std::env::remove_var("OAUTH_USER_AGENT"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_and_verify_identity_rejects_missing_subject_identifier() {
        let _guard = oauth_ua_test_guard();
        let previous_client_id = std::env::var("GEPHYR_OAUTH_CLIENT_ID").ok();
        std::env::set_var(
            "GEPHYR_OAUTH_CLIENT_ID",
            "test-client.apps.googleusercontent.com",
        );

        let (base_url, _state, server) = start_mock_oauth_server_with_userinfo(json!({
            "email": "nosub@example.com",
            "email_verified": true,
            "name": "No Sub"
        }))
        .await;
        let token_url = format!("{}/token", base_url);
        let userinfo_url = format!("{}/userinfo", base_url);

        let err = refresh_and_verify_identity_at("refresh-token", None, &token_url, &userinfo_url)
            .await
            .expect_err(
                "refresh_and_verify_identity should fail when fallback userinfo is missing sub",
            );

        server.abort();
        assert!(err.contains("missing subject identifier"));

        match previous_client_id {
            Some(value) => std::env::set_var("GEPHYR_OAUTH_CLIENT_ID", value),
            None => std::env::remove_var("GEPHYR_OAUTH_CLIENT_ID"),
        }
    }
}
