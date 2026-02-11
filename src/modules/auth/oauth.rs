use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";

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
        "GEPHYR_GOOGLE_OAUTH_CLIENT_ID",
        "ABV_GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_ID",
    ])
    .ok_or_else(|| {
        "Missing Google OAuth client_id. Set GEPHYR_GOOGLE_OAUTH_CLIENT_ID (or ABV_GOOGLE_OAUTH_CLIENT_ID)."
            .to_string()
    })
}

fn client_secret_optional() -> Option<String> {
    env_first(&[
        "GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET",
        "ABV_GOOGLE_OAUTH_CLIENT_SECRET",
        "GOOGLE_OAUTH_CLIENT_SECRET",
    ])
}

fn oauth_user_agent() -> String {
    env_first(&["ABV_OAUTH_USER_AGENT"])
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
        request = request
            .header("x-machine-id", profile.machine_id)
            .header("x-mac-machine-id", profile.mac_machine_id)
            .header("x-dev-device-id", profile.dev_device_id)
            .header("x-sqm-id", profile.sqm_id);
    }

    request
}

fn refresh_jitter_seconds(account_id: Option<&str>) -> i64 {
    let mut hasher = DefaultHasher::new();
    account_id.unwrap_or("generic-account").hash(&mut hasher);
    30 + (hasher.finish() % 91) as i64
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

    let response = apply_google_identity_headers(client.post(TOKEN_URL), None)
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

    let response = apply_google_identity_headers(client.post(TOKEN_URL), account_id)
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
pub async fn get_user_info(
    access_token: &str,
    account_id: Option<&str>,
) -> Result<UserInfo, String> {
    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(account_id, 15)
            .await
            .map_err(|e| format!("Failed to prepare userinfo client: {}", e))?
    } else {
        crate::utils::http::get_client()
    };

    let response = apply_google_identity_headers(client.get(USERINFO_URL), account_id)
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
pub async fn ensure_fresh_token(
    current_token: &crate::models::TokenData,
    account_id: Option<&str>,
) -> Result<crate::models::TokenData, String> {
    let now = chrono::Local::now().timestamp();
    let refresh_window = 300 + refresh_jitter_seconds(account_id);
    if current_token.expiry_timestamp > now + refresh_window {
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
    use std::sync::{Mutex, OnceLock};

    fn oauth_ua_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_get_auth_url_contains_state() {
        std::env::set_var(
            "GEPHYR_GOOGLE_OAUTH_CLIENT_ID",
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
    fn oauth_user_agent_uses_default_when_override_missing() {
        let _guard = oauth_ua_test_lock()
            .lock()
            .expect("oauth user-agent test lock poisoned");
        let previous = std::env::var("ABV_OAUTH_USER_AGENT").ok();
        std::env::remove_var("ABV_OAUTH_USER_AGENT");

        let ua = oauth_user_agent();
        assert_eq!(ua, crate::constants::USER_AGENT.as_str());

        match previous {
            Some(value) => std::env::set_var("ABV_OAUTH_USER_AGENT", value),
            None => std::env::remove_var("ABV_OAUTH_USER_AGENT"),
        }
    }

    #[test]
    fn oauth_user_agent_uses_override_when_set() {
        let _guard = oauth_ua_test_lock()
            .lock()
            .expect("oauth user-agent test lock poisoned");
        let previous = std::env::var("ABV_OAUTH_USER_AGENT").ok();
        std::env::set_var("ABV_OAUTH_USER_AGENT", "vscode/1.95.0 gephyr-test");

        let ua = oauth_user_agent();
        assert_eq!(ua, "vscode/1.95.0 gephyr-test");

        match previous {
            Some(value) => std::env::set_var("ABV_OAUTH_USER_AGENT", value),
            None => std::env::remove_var("ABV_OAUTH_USER_AGENT"),
        }
    }
}
