use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use crate::proxy::server::AppState;
use crate::modules::security_db;

// IP Blacklist/Whitelist Filter Middleware
pub async fn ip_filter_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Extract client IP
    let client_ip = extract_client_ip(&request);
    
    if let Some(ip) = &client_ip {
        // Read security config
        let security_config = state.security.read().await;
        
        // 1. Check whitelist (if enabled, only allow whitelisted IPs)
        if security_config.security_monitor.whitelist.enabled {
            match security_db::is_ip_in_whitelist(ip) {
                Ok(true) => {
                    // In whitelist, allow access
                    tracing::debug!("[IP Filter] IP {} is in whitelist, allowing", ip);
                    return next.run(request).await;
                }
                Ok(false) => {
                    // Not in whitelist and whitelist mode enabled, block access
                    tracing::warn!("[IP Filter] IP {} not in whitelist, blocking", ip);
                    return create_blocked_response(
                        ip,
                        "Access denied. Your IP is not in the whitelist.",
                    );
                }
                Err(e) => {
                    tracing::error!("[IP Filter] Failed to check whitelist: {}", e);
                }
            }
        } else {
            // Whitelist priority mode: if in whitelist, skip blacklist check
            if security_config.security_monitor.whitelist.whitelist_priority {
                match security_db::is_ip_in_whitelist(ip) {
                    Ok(true) => {
                        tracing::debug!("[IP Filter] IP {} is in whitelist (priority mode), skipping blacklist check", ip);
                        return next.run(request).await;
                    }
                    Ok(false) => {
                        // Continue to check blacklist
                    }
                    Err(e) => {
                        tracing::error!("[IP Filter] Failed to check whitelist: {}", e);
                    }
                }
            }
        }

        // 2. Check blacklist
        if security_config.security_monitor.blacklist.enabled {
            match security_db::get_blacklist_entry_for_ip(ip) {
                Ok(Some(entry)) => {
                    tracing::warn!("[IP Filter] IP {} is in blacklist, blocking", ip);
                    
                    // Build detailed block message
                    let reason = entry.reason.as_deref().unwrap_or("Malicious activity detected");
                    let ban_type = if let Some(expires_at) = entry.expires_at {
                        let now = chrono::Utc::now().timestamp();
                        let remaining_seconds = expires_at - now;
                        
                        if remaining_seconds > 0 {
                            let hours = remaining_seconds / 3600;
                            let minutes = (remaining_seconds % 3600) / 60;
                            
                            if hours > 24 {
                                let days = hours / 24;
                                format!("Temporary ban. Please try again after {} day(s).", days)
                            } else if hours > 0 {
                                format!("Temporary ban. Please try again after {} hour(s) and {} minute(s).", hours, minutes)
                            } else {
                                format!("Temporary ban. Please try again after {} minute(s).", minutes)
                            }
                        } else {
                            "Temporary ban (expired, will be removed soon).".to_string()
                        }
                    } else {
                        "Permanent ban.".to_string()
                    };
                    
                    let detailed_message = format!(
                        "Access denied. Reason: {}. {}",
                        reason,
                        ban_type
                    );
                    
                    // Record blocked access log
                    let log = security_db::IpAccessLog {
                        id: uuid::Uuid::new_v4().to_string(),
                        client_ip: ip.clone(),
                        timestamp: chrono::Utc::now().timestamp(),
                        method: Some(request.method().to_string()),
                        path: Some(request.uri().to_string()),
                        user_agent: request
                            .headers()
                            .get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string()),
                        status: Some(403),
                        duration: Some(0),
                        api_key_hash: None,
                        blocked: true,
                        block_reason: Some(format!("IP in blacklist: {}", reason)),
                        username: None,
                    };
                    
                    tokio::spawn(async move {
                        if let Err(e) = security_db::save_ip_access_log(&log) {
                            tracing::error!("[IP Filter] Failed to save blocked access log: {}", e);
                        }
                    });
                    
                    return create_blocked_response(
                        ip,
                        &detailed_message,
                    );
                }
                Ok(None) => {
                    // Not in blacklist, allow access
                    tracing::debug!("[IP Filter] IP {} not in blacklist, allowing", ip);
                }
                Err(e) => {
                    tracing::error!("[IP Filter] Failed to check blacklist: {}", e);
                }
            }
        }
    } else {
        tracing::warn!("[IP Filter] Unable to extract client IP from request");
    }

    // Allow request
    next.run(request).await
}

// Extract client IP from request
fn extract_client_ip(request: &Request) -> Option<String> {
    // 1. Prefer X-Forwarded-For (take the first IP)
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            // 2. Fallback to X-Real-IP
            request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            // 3. Finally try to get from ConnectInfo (TCP connection IP)
            // This can solve the issue of failing to get IP during local development/testing when there is no proxy header.
            request
                .extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|info| info.0.ip().to_string())
        })
}

// Create blocked response
fn create_blocked_response(ip: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "ip_blocked",
            "code": "ip_blocked",
            "ip": ip,
        }
    });
    
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_else(|_| message.to_string()),
    )
        .into_response()
}
