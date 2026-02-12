use axum::{
    extract::Request,
    extract::State,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::proxy::{ProxyAuthMode, ProxySecurityConfig};

fn constant_time_str_eq(left: &str, right: &str) -> bool {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let max_len = left_bytes.len().max(right_bytes.len());
    let mut diff = left_bytes.len() ^ right_bytes.len();

    for i in 0..max_len {
        let l = left_bytes.get(i).copied().unwrap_or(0);
        let r = right_bytes.get(i).copied().unwrap_or(0);
        diff |= (l ^ r) as usize;
    }

    diff == 0
}

fn provided_secret_matches(provided: Option<&str>, expected: &str) -> bool {
    provided
        .map(|candidate| constant_time_str_eq(candidate, expected))
        .unwrap_or(false)
}

fn is_authorized(
    security: &ProxySecurityConfig,
    provided_api_key: Option<&str>,
    force_strict: bool,
) -> bool {
    if force_strict {
        match &security.admin_password {
            Some(pwd) if !pwd.is_empty() => provided_secret_matches(provided_api_key, pwd),
            _ => provided_secret_matches(provided_api_key, &security.api_key),
        }
    } else {
        provided_secret_matches(provided_api_key, &security.api_key)
    }
}

pub async fn auth_middleware(
    state: State<Arc<RwLock<ProxySecurityConfig>>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    auth_middleware_internal(state, request, next, false).await
}
pub async fn admin_auth_middleware(
    state: State<Arc<RwLock<ProxySecurityConfig>>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    auth_middleware_internal(state, request, next, true).await
}
async fn auth_middleware_internal(
    State(security): State<Arc<RwLock<ProxySecurityConfig>>>,
    request: Request,
    next: Next,
    force_strict: bool,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let is_health_check = path == "/healthz" || path == "/api/health" || path == "/health";
    let is_internal_endpoint = path.starts_with("/internal/");
    if !path.contains("event_logging") && !is_health_check {
        tracing::info!("Request: {} {}", method, path);
    } else {
        tracing::trace!("Heartbeat/Health: {} {}", method, path);
    }
    if method == axum::http::Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    let security = security.read().await.clone();
    let effective_mode = security.effective_auth_mode();
    if !force_strict {
        if matches!(effective_mode, ProxyAuthMode::Off) {
            let api_key = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ").or(Some(s)))
                .or_else(|| {
                    request
                        .headers()
                        .get("x-api-key")
                        .and_then(|h| h.to_str().ok())
                });

            if let Some(token) = api_key {
                if let Some(client_ip) =
                    crate::proxy::middleware::client_ip::extract_client_ip(&request)
                {
                    match crate::modules::persistence::user_token_db::validate_token(
                        token, &client_ip,
                    ) {
                        Ok((true, _)) => {
                            if let Ok(Some(user_token)) =
                                crate::modules::persistence::user_token_db::get_token_by_value(
                                    token,
                                )
                            {
                                let identity = UserTokenIdentity {
                                    token_id: user_token.id,
                                    username: user_token.username,
                                };
                                let (mut parts, body) = request.into_parts();
                                parts.extensions.insert(identity);
                                let request = Request::from_parts(parts, body);
                                return Ok(next.run(request).await);
                            }
                        }
                        Ok((false, reason)) => {
                            tracing::debug!(
                                "Auth off-mode ignored invalid user token for identity attach: {:?}",
                                reason
                            );
                        }
                        Err(e) => {
                            tracing::warn!("Auth off-mode user token validation error: {}", e);
                        }
                    }
                } else {
                    tracing::warn!(
                        "Auth off-mode skipped user token identity attach: missing socket client IP"
                    );
                }
            }

            return Ok(next.run(request).await);
        }

        if matches!(effective_mode, ProxyAuthMode::AllExceptHealth) && is_health_check {
            return Ok(next.run(request).await);
        }
        if is_internal_endpoint {
            tracing::debug!("Internal endpoint bypassed auth: {}", path);
            return Ok(next.run(request).await);
        }
    } else {
        // Admin routes must never become unauthenticated due to proxy auth mode.
        // Health checks for operators should use /healthz (non-admin) instead.
    }
    let api_key = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").or(Some(s)))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|h| h.to_str().ok())
        })
        .or_else(|| {
            request
                .headers()
                .get("x-goog-api-key")
                .and_then(|h| h.to_str().ok())
        });

    if security.api_key.is_empty()
        && (security.admin_password.is_none()
            || security.admin_password.as_ref().unwrap().is_empty())
    {
        if force_strict {
            tracing::error!("Admin auth is required but both api_key and admin_password are empty; denying request");
            return Err(StatusCode::UNAUTHORIZED);
        }
        tracing::error!("Proxy auth is enabled but api_key is empty; denying request");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let authorized = is_authorized(&security, api_key, force_strict);

    if authorized {
        return Ok(next.run(request).await);
    }

    // Allow user token auth fallback for both proxy and admin routes.
    if let Some(token) = api_key {
        let Some(client_ip) = crate::proxy::middleware::client_ip::extract_client_ip(&request)
        else {
            tracing::warn!(
                "Rejecting user token auth: missing socket client IP for token validation"
            );
            return Err(StatusCode::UNAUTHORIZED);
        };
        match crate::modules::persistence::user_token_db::validate_token(token, &client_ip) {
            Ok((true, _)) => {
                if let Ok(Some(user_token)) =
                    crate::modules::persistence::user_token_db::get_token_by_value(token)
                {
                    let identity = UserTokenIdentity {
                        token_id: user_token.id,
                        username: user_token.username,
                    };
                    let (mut parts, body) = request.into_parts();
                    parts.extensions.insert(identity);
                    let request = Request::from_parts(parts, body);
                    return Ok(next.run(request).await);
                }
                Err(StatusCode::UNAUTHORIZED)
            }
            Ok((false, reason)) => {
                tracing::warn!("UserToken rejected: {:?}", reason);
                Err(StatusCode::UNAUTHORIZED)
            }
            Err(e) => {
                tracing::error!("UserToken validation error: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
#[derive(Clone, Debug)]
pub struct UserTokenIdentity {
    pub token_id: String,
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::config::SecurityMonitorConfig;
    use crate::proxy::ProxyAuthMode;

    fn make_security(api_key: &str, admin_password: Option<&str>) -> ProxySecurityConfig {
        ProxySecurityConfig {
            auth_mode: ProxyAuthMode::Strict,
            api_key: api_key.to_string(),
            admin_password: admin_password.map(ToString::to_string),
            allow_lan_access: true,
            port: 8045,
            security_monitor: SecurityMonitorConfig::default(),
        }
    }

    #[tokio::test]
    async fn test_admin_auth_with_password() {
        let _security = Arc::new(RwLock::new(ProxySecurityConfig {
            auth_mode: ProxyAuthMode::Strict,
            api_key: "sk-api".to_string(),
            admin_password: Some("admin123".to_string()),
            allow_lan_access: true,
            port: 8045,
            security_monitor: crate::proxy::config::SecurityMonitorConfig::default(),
        }));
        let _req = Request::builder()
            .header("Authorization", "Bearer admin123")
            .uri("/admin/stats")
            .body(axum::body::Body::empty())
            .unwrap();
    }

    #[test]
    fn constant_time_compare_matches_and_rejects() {
        assert!(constant_time_str_eq("abc123", "abc123"));
        assert!(!constant_time_str_eq("abc123", "abc124"));
        assert!(!constant_time_str_eq("abc123", "abc1234"));
    }

    #[test]
    fn strict_auth_prefers_admin_password_when_present() {
        let security = make_security("sk-api", Some("admin123"));
        assert!(is_authorized(&security, Some("admin123"), true));
        assert!(!is_authorized(&security, Some("sk-api"), true));
    }

    #[test]
    fn strict_auth_falls_back_to_api_key_when_admin_password_missing() {
        let security = make_security("sk-api", None);
        assert!(is_authorized(&security, Some("sk-api"), true));
        assert!(!is_authorized(&security, Some("wrong"), true));
    }

    #[test]
    fn non_strict_auth_uses_api_key_only() {
        let security = make_security("sk-api", Some("admin123"));
        assert!(is_authorized(&security, Some("sk-api"), false));
        assert!(!is_authorized(&security, Some("admin123"), false));
        assert!(!is_authorized(&security, None, false));
    }
}
