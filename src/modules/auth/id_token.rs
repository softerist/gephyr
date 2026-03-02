use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const JWKS_CACHE_TTL_SECONDS: i64 = 3600;
const ALLOWED_ISSUERS: [&str; 2] = ["accounts.google.com", "https://accounts.google.com"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoogleIdClaims {
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub hd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawGoogleIdClaims {
    #[serde(rename = "iss")]
    _iss: String,
    #[serde(rename = "aud")]
    _aud: serde_json::Value,
    #[serde(rename = "exp")]
    _exp: i64,
    pub sub: String,
    pub email: String,
    #[serde(default, deserialize_with = "deserialize_email_verified")]
    pub email_verified: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub hd: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}

#[derive(Debug, Deserialize)]
struct GoogleJwk {
    kid: String,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use", default)]
    key_use: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Clone)]
struct CachedJwks {
    fetched_at_unix: i64,
    keys: HashMap<String, Arc<DecodingKey>>,
}

static JWKS_CACHE: OnceLock<Mutex<Option<CachedJwks>>> = OnceLock::new();

fn cache_state() -> &'static Mutex<Option<CachedJwks>> {
    JWKS_CACHE.get_or_init(|| Mutex::new(None))
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn deserialize_email_verified<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrString {
        Bool(bool),
        String(String),
    }

    let raw = Option::<BoolOrString>::deserialize(deserializer)?;
    match raw {
        Some(BoolOrString::Bool(v)) => Ok(v),
        Some(BoolOrString::String(v)) => {
            let normalized = v.trim().to_ascii_lowercase();
            Ok(normalized == "true" || normalized == "1")
        }
        None => Ok(false),
    }
}

fn parse_allowed_domains() -> Option<HashSet<String>> {
    let raw = std::env::var("ALLOWED_GOOGLE_DOMAINS").ok()?;
    let set: HashSet<String> = raw
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

fn validate_domain_allowlist(hd: Option<&str>) -> Result<(), String> {
    let Some(allowed) = parse_allowed_domains() else {
        return Ok(());
    };
    let Some(domain) = hd.map(|v| v.trim().to_ascii_lowercase()) else {
        return Err(
            "Google hosted domain is required but missing (ALLOWED_GOOGLE_DOMAINS)".to_string(),
        );
    };
    if allowed.contains(&domain) {
        Ok(())
    } else {
        Err(format!(
            "Google hosted domain '{}' is not in ALLOWED_GOOGLE_DOMAINS",
            domain
        ))
    }
}

fn get_cached_keys_if_fresh(now: i64) -> Result<Option<HashMap<String, Arc<DecodingKey>>>, String> {
    let lock = cache_state()
        .lock()
        .map_err(|_| "JWKS cache lock is poisoned".to_string())?;
    let Some(cached) = lock.as_ref() else {
        return Ok(None);
    };
    if now - cached.fetched_at_unix < JWKS_CACHE_TTL_SECONDS {
        Ok(Some(cached.keys.clone()))
    } else {
        Ok(None)
    }
}

async fn fetch_google_jwks() -> Result<HashMap<String, Arc<DecodingKey>>, String> {
    let client = if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(None, 60)
            .await
            .map_err(|e| format!("Failed to prepare JWKS client: {}", e))?
    } else {
        crate::utils::http::get_long_client()
    };
    let response = client
        .get(GOOGLE_JWKS_URL)
        .header(
            reqwest::header::USER_AGENT,
            crate::constants::USER_AGENT.as_str(),
        )
        .send()
        .await
        .map_err(|e| format!("Failed to fetch Google JWKS: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Google JWKS fetch failed with status {}: {}",
            status, body
        ));
    }

    let jwks = response
        .json::<GoogleJwks>()
        .await
        .map_err(|e| format!("Failed to parse Google JWKS response: {}", e))?;

    let mut keys = HashMap::new();
    for jwk in jwks.keys {
        if jwk.kty != "RSA" {
            continue;
        }
        if let Some(key_use) = jwk.key_use.as_deref() {
            if key_use != "sig" {
                continue;
            }
        }
        if let Some(alg) = jwk.alg.as_deref() {
            if alg != "RS256" {
                continue;
            }
        }
        let (Some(n), Some(e)) = (jwk.n.as_deref(), jwk.e.as_deref()) else {
            continue;
        };
        match DecodingKey::from_rsa_components(n, e) {
            Ok(key) => {
                keys.insert(jwk.kid, Arc::new(key));
            }
            Err(err) => {
                tracing::warn!("Skipping invalid Google JWK: {}", err);
            }
        }
    }

    if keys.is_empty() {
        return Err("Google JWKS did not contain any usable RS256 keys".to_string());
    }

    let mut lock = cache_state()
        .lock()
        .map_err(|_| "JWKS cache lock is poisoned".to_string())?;
    *lock = Some(CachedJwks {
        fetched_at_unix: now_unix(),
        keys: keys.clone(),
    });

    Ok(keys)
}

async fn get_jwks_keys(force_refresh: bool) -> Result<HashMap<String, Arc<DecodingKey>>, String> {
    if !force_refresh {
        if let Some(keys) = get_cached_keys_if_fresh(now_unix())? {
            return Ok(keys);
        }
    }
    fetch_google_jwks().await
}

pub async fn validate_id_token(raw_jwt: &str) -> Result<GoogleIdClaims, String> {
    let header = decode_header(raw_jwt).map_err(|e| format!("Invalid id_token header: {}", e))?;
    if header.alg != Algorithm::RS256 {
        return Err(format!(
            "Unsupported id_token algorithm: {:?} (expected RS256)",
            header.alg
        ));
    }
    let kid = header
        .kid
        .ok_or_else(|| "id_token missing 'kid' header".to_string())?;

    let mut keys = get_jwks_keys(false).await?;
    let key = if let Some(k) = keys.get(&kid) {
        k.clone()
    } else {
        keys = get_jwks_keys(true).await?;
        keys.get(&kid)
            .cloned()
            .ok_or_else(|| format!("No matching Google JWK for kid '{}'", kid))?
    };

    let audience = crate::modules::auth::oauth::client_id()?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&ALLOWED_ISSUERS);
    validation.set_audience(&[audience.as_str()]);
    validation.validate_exp = true;
    validation.leeway = 0;

    let token_data = decode::<RawGoogleIdClaims>(raw_jwt, key.as_ref(), &validation)
        .map_err(|e| format!("id_token validation failed: {}", e))?;
    let claims = token_data.claims;

    if !claims.email_verified {
        return Err("Google id_token rejected: email is not verified".to_string());
    }
    validate_domain_allowlist(claims.hd.as_deref())?;

    Ok(GoogleIdClaims {
        sub: claims.sub,
        email: claims.email,
        email_verified: claims.email_verified,
        name: claims.name,
        hd: claims.hd,
    })
}

#[cfg(test)]
fn set_jwks_cache_for_tests(keys: HashMap<String, Arc<DecodingKey>>) {
    let mut lock = cache_state().lock().expect("set_jwks_cache_for_tests lock");
    *lock = Some(CachedJwks {
        fetched_at_unix: now_unix(),
        keys,
    });
}

#[cfg(test)]
fn clear_jwks_cache_for_tests() {
    let mut lock = cache_state()
        .lock()
        .expect("clear_jwks_cache_for_tests lock");
    *lock = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ScopedEnvVar;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    const TEST_KID: &str = "test-kid-1";
    const TEST_CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
    const TEST_ISSUER: &str = "https://accounts.google.com";
    const TEST_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC65tN/qAE+tTZS
7RR+L0vpkMzkNv/JTk9d9lAAKAi/1Hq3R4T5fMbEBrGtMNR3HbyUwCkOYdv5XYqK
k4546wUfvkcIuYdfRLwvlqXSjJ/nvvyCXZGCBqzxiYCrNnWWOEBV52L89qzBKBL4
7KHSAf+xL4Swj25QoStZz4+G/Q3uS4pfrejsroGB5+dXJQgtiq7kylC4C/jUsKh+
xMvgVOflujAnvouYdryosxKGceBpxAhsrrydbTD+37qwD9W6ncl/KCDlebhHBi+/
VQjTd0/AAxPW3pqi6NHocKpl8KUAEnd2S4RzlZFtIOAXIO7f+yAXux3Je/qOBLNI
45bOuTAFAgMBAAECggEAB+/LZW1d+Cq7ztOwfhdGEvoKKVrIi+Tea/AMv6TzkinU
uDm6RNnumt5p5x/etdw2aN6sH6c6LyGww2e2sh3QzuNGovE19W62yxKLoiBEnhO3
J1YP2sSrzWn4Y8zhO2rSGJPF2VYkSeOIwrdRu9hH4l9RNCozFgtyCtNMlf/i+o56
EtzPbpSIC+EuEQGD/MAAGNtllEJ6fgGVfKcR+PGa2HwaEpOHm+UrrDMZbdyehKCL
VqdqQsr2CcJME59M3Og46czYJLFsrif8JDWNy7CbI8KWomjjR+DUISFekI9JGi97
sLrk9CzIDpFpoYTQkPFcYDzt4cUmyMyyj+pxspv9gQKBgQDb5gw0jWysYJzRKTN6
6eNqarkF3Umq/hUN/wvPD6bB5NndO+JmmyUBdGafu36WE/qC42sYRF87VuH6TTMM
Pcu9Qf0xdTdvD1UUY0v/EGOWPUeeDnQN3nT3WIsL8swjLVmT/VgKF9K69u/m/IKo
NjZfc3NhzVxTJXcL2sEus7TD5QKBgQDZlflu4s1RvBYy9E5eDOwWfxTW+4BHuPsh
+V7IYZlJaQKtAZsAJ9Zqlu4DCDWT/nxY/wfEKAFH6xxl+GYUQQVkou1+Pre4Gbwe
MXkrf7SgLjieQeIRzV2ADPQWxn8lPaY6Az7vukGTGFJBC06zC9VfcsNamSR6bmVs
IlYjkfw5oQKBgQDEh1mpLixN8xq0JKqJ07cYSMGL6DYKyIJwu90F9esHp0y/WOIC
6e2s2ydM4vlDkB94E2CHk7O5CPF2DsDs093fC7cKGMSuUXmsewJUt4UJpUL4k9pM
+uB2n3/F8f1YAxPoG6gvfRMtXb0TJ+JuC+WUcU5RvoQhG37F7YByCNIpsQKBgFz4
ozsJOBf7mTSuhSnUtbArHtl5X2fGF7B9oE1YvqnKb/VCoVtgqlKjKRIsmNAixjk0
x7m+KkXzpQ/BIsT2v3ovz/DIlbHZdTMlipPWnnRvK4wbtKBMsu37GvT8XemovPU+
286NNGXI16SpUzhYDxUYsXZtx1N1Bms9BLdwMmjhAoGANBM2/Fd4Zm4w0l27XHiJ
yyimSFrbqZkXdASfNAC1GTu0J457pWj8Z/bogEguZ4lK8yflCX7AJZJUfsoUysti
qXAeL4sDAiTEWTED3vuPuG72BN+yQ1CtmNMY+KfN80T584gcOoT+u30jM7ucn5fJ
I5B6EmW+tn/EROqBlqI6yIQ=
-----END PRIVATE KEY-----"#;
    const TEST_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuubTf6gBPrU2Uu0Ufi9L
6ZDM5Db/yU5PXfZQACgIv9R6t0eE+XzGxAaxrTDUdx28lMApDmHb+V2KipOOeOsF
H75HCLmHX0S8L5al0oyf5778gl2Rggas8YmAqzZ1ljhAVedi/PaswSgS+Oyh0gH/
sS+EsI9uUKErWc+Phv0N7kuKX63o7K6BgefnVyUILYqu5MpQuAv41LCofsTL4FTn
5bowJ76LmHa8qLMShnHgacQIbK68nW0w/t+6sA/Vup3Jfygg5Xm4RwYvv1UI03dP
wAMT1t6aoujR6HCqZfClABJ3dkuEc5WRbSDgFyDu3/sgF7sdyXv6jgSzSOOWzrkw
BQIDAQAB
-----END PUBLIC KEY-----"#;

    #[derive(Serialize)]
    struct TestClaims<'a> {
        iss: &'a str,
        aud: &'a str,
        exp: i64,
        sub: &'a str,
        email: &'a str,
        email_verified: bool,
        hd: Option<&'a str>,
        name: Option<&'a str>,
    }

    fn setup_test_env() -> (ScopedEnvVar, ScopedEnvVar) {
        let decoding =
            DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).expect("test decoding key");
        let mut keys = HashMap::new();
        keys.insert(TEST_KID.to_string(), Arc::new(decoding));
        set_jwks_cache_for_tests(keys);
        let client_id = ScopedEnvVar::set("GOOGLE_OAUTH_CLIENT_ID", TEST_CLIENT_ID);
        let allow_domains = ScopedEnvVar::unset("ALLOWED_GOOGLE_DOMAINS");
        (client_id, allow_domains)
    }

    fn teardown_test_env() {
        clear_jwks_cache_for_tests();
    }

    fn sign_test_jwt(claims: &TestClaims<'_>) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let encoding_key =
            EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY_PEM.as_bytes()).expect("test encoding key");
        encode(&header, claims, &encoding_key).expect("encode test jwt")
    }

    #[tokio::test]
    async fn test_validate_valid_id_token() {
        let _guard = crate::test_utils::lock_env();
        let (_client_id, _allow_domains) = setup_test_env();
        let now = now_unix();
        let token = sign_test_jwt(&TestClaims {
            iss: TEST_ISSUER,
            aud: TEST_CLIENT_ID,
            exp: now + 3600,
            sub: "google-sub-1",
            email: "valid@example.com",
            email_verified: true,
            hd: Some("example.com"),
            name: Some("Valid User"),
        });

        let result = validate_id_token(&token).await.expect("valid id_token");
        assert_eq!(result.sub, "google-sub-1");
        assert_eq!(result.email, "valid@example.com");
        assert!(result.email_verified);
        teardown_test_env();
    }

    #[tokio::test]
    async fn test_reject_expired_token() {
        let _guard = crate::test_utils::lock_env();
        let (_client_id, _allow_domains) = setup_test_env();
        let now = now_unix();
        let token = sign_test_jwt(&TestClaims {
            iss: TEST_ISSUER,
            aud: TEST_CLIENT_ID,
            exp: now - 10,
            sub: "google-sub-2",
            email: "expired@example.com",
            email_verified: true,
            hd: None,
            name: None,
        });

        let err = validate_id_token(&token)
            .await
            .expect_err("expired token must fail");
        assert!(err.contains("id_token validation failed"));
        teardown_test_env();
    }

    #[tokio::test]
    async fn test_reject_wrong_audience() {
        let _guard = crate::test_utils::lock_env();
        let (_client_id, _allow_domains) = setup_test_env();
        let now = now_unix();
        let token = sign_test_jwt(&TestClaims {
            iss: TEST_ISSUER,
            aud: "another-client.apps.googleusercontent.com",
            exp: now + 3600,
            sub: "google-sub-3",
            email: "aud@example.com",
            email_verified: true,
            hd: None,
            name: None,
        });

        let err = validate_id_token(&token)
            .await
            .expect_err("wrong audience must fail");
        assert!(err.contains("id_token validation failed"));
        teardown_test_env();
    }

    #[tokio::test]
    async fn test_reject_wrong_issuer() {
        let _guard = crate::test_utils::lock_env();
        let (_client_id, _allow_domains) = setup_test_env();
        let now = now_unix();
        let token = sign_test_jwt(&TestClaims {
            iss: "https://malicious.example",
            aud: TEST_CLIENT_ID,
            exp: now + 3600,
            sub: "google-sub-4",
            email: "issuer@example.com",
            email_verified: true,
            hd: None,
            name: None,
        });

        let err = validate_id_token(&token)
            .await
            .expect_err("wrong issuer must fail");
        assert!(err.contains("id_token validation failed"));
        teardown_test_env();
    }

    #[tokio::test]
    async fn test_reject_unverified_email() {
        let _guard = crate::test_utils::lock_env();
        let (_client_id, _allow_domains) = setup_test_env();
        let now = now_unix();
        let token = sign_test_jwt(&TestClaims {
            iss: TEST_ISSUER,
            aud: TEST_CLIENT_ID,
            exp: now + 3600,
            sub: "google-sub-5",
            email: "unverified@example.com",
            email_verified: false,
            hd: None,
            name: None,
        });

        let err = validate_id_token(&token)
            .await
            .expect_err("unverified email must fail");
        assert!(err.contains("email is not verified"));
        teardown_test_env();
    }

    #[tokio::test]
    async fn test_domain_allowlist_rejects_unknown_domain() {
        let _guard = crate::test_utils::lock_env();
        let (_client_id, _allow_domains) = setup_test_env();
        let _allowed_domains = ScopedEnvVar::set("ALLOWED_GOOGLE_DOMAINS", "corp.example.com");
        let now = now_unix();
        let token = sign_test_jwt(&TestClaims {
            iss: TEST_ISSUER,
            aud: TEST_CLIENT_ID,
            exp: now + 3600,
            sub: "google-sub-6",
            email: "domain@example.com",
            email_verified: true,
            hd: Some("gmail.com"),
            name: None,
        });

        let err = validate_id_token(&token)
            .await
            .expect_err("disallowed domain must fail");
        assert!(err.contains("not in ALLOWED_GOOGLE_DOMAINS"));
        teardown_test_env();
    }
}
