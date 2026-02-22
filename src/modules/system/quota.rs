use crate::models::QuotaData;
use crate::proxy::upstream::header_policy::{
    build_google_headers, build_load_code_assist_metadata, host_from_url,
    load_policy_from_runtime_config, GoogleHeaderPolicyContext, GoogleHeaderScope,
};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::json;

const QUOTA_API_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels";
const CLOUD_CODE_BASE_URL: &str = "https://cloudcode-pa.googleapis.com";

const MAX_RETRIES: u32 = 3;

fn load_account_device_profile(account_id: Option<&str>) -> Option<crate::models::DeviceProfile> {
    let id = account_id?;
    crate::modules::auth::account::load_account(id)
        .ok()
        .and_then(|account| account.device_profile)
}

#[derive(Debug, Serialize, Deserialize)]
struct QuotaResponse {
    models: std::collections::HashMap<String, ModelInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ModelInfo {
    #[serde(rename = "quotaInfo")]
    quota_info: Option<QuotaInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuotaInfo {
    #[serde(rename = "remainingFraction")]
    remaining_fraction: Option<f64>,
    #[serde(rename = "resetTime")]
    reset_time: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoadProjectResponse {
    #[serde(rename = "cloudaicompanionProject")]
    project_id: Option<String>,
    #[serde(rename = "currentTier")]
    current_tier: Option<Tier>,
    #[serde(rename = "paidTier")]
    paid_tier: Option<Tier>,
}

#[derive(Debug, Deserialize)]
struct Tier {
    id: Option<String>,
    #[serde(rename = "quotaTier")]
    _quota_tier: Option<String>,
    _name: Option<String>,
    _slug: Option<String>,
}
async fn create_client(account_id: Option<&str>) -> Result<reqwest::Client, String> {
    if let Some(pool) = crate::proxy::proxy_pool::get_global_proxy_pool() {
        pool.get_effective_client(account_id, 15).await
    } else {
        Ok(crate::utils::http::get_client())
    }
}

async fn fetch_project_id(
    access_token: &str,
    email: &str,
    account_id: Option<&str>,
) -> Result<(Option<String>, Option<String>), String> {
    let profile = crate::modules::system::config::load_app_config()
        .ok()
        .map(|cfg| cfg.proxy.google.mimic.profile)
        .unwrap_or_default();
    let hosts = crate::proxy::google::endpoints::cloudcode_hosts_for_profile(profile);
    let mut last_err = String::new();
    for host in hosts {
        let cloud_code_base_url = format!("https://{}", host);
        match fetch_project_id_at(access_token, email, account_id, &cloud_code_base_url).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_err = e;
            }
        }
    }
    if last_err.is_empty() {
        return Err("No cloudcode hosts configured".to_string());
    }
    Err(last_err)
}

async fn fetch_project_id_at(
    access_token: &str,
    email: &str,
    account_id: Option<&str>,
    cloud_code_base_url: &str,
) -> Result<(Option<String>, Option<String>), String> {
    let client = create_client(account_id).await?;
    let policy = load_policy_from_runtime_config();
    let meta = build_load_code_assist_metadata(&policy);
    let endpoint = format!("{}/v1internal:loadCodeAssist", cloud_code_base_url);
    let endpoint_host = host_from_url(&endpoint);
    let device_profile = load_account_device_profile(account_id);
    let headers = build_google_headers(
        GoogleHeaderPolicyContext {
            endpoint: &endpoint,
            endpoint_host: endpoint_host.as_deref(),
            scope: GoogleHeaderScope::Cloudcode,
            user_agent: crate::constants::USER_AGENT.as_str(),
            access_token: Some(access_token),
            content_type_json: true,
            device_profile: device_profile.as_ref(),
            extra_headers: None,
            force_connection_close: true,
        },
        &policy,
    );

    let res = client.post(&endpoint).headers(headers).json(&meta).send().await;

    match res {
        Ok(res) => {
            if res.status().is_success() {
                if let Ok(data) = res.json::<LoadProjectResponse>().await {
                    let project_id = data.project_id.clone();
                    let subscription_tier = data
                        .paid_tier
                        .and_then(|t| t.id)
                        .or_else(|| data.current_tier.and_then(|t| t.id));

                    if let Some(ref tier) = subscription_tier {
                        crate::modules::system::logger::log_info(&format!(
                            "📊 [{}] Subscription identified successfully: {}",
                            email, tier
                        ));
                    }

                    return Ok((project_id, subscription_tier));
                }
            } else {
                crate::modules::system::logger::log_warn(&format!(
                    "⚠️  [{}] loadCodeAssist failed: Status: {}",
                    email,
                    res.status()
                ));
            }
        }
        Err(e) => {
            crate::modules::system::logger::log_error(&format!(
                "❌ [{}] loadCodeAssist network error: {}",
                email, e
            ));
        }
    }

    Ok((None, None))
}
pub async fn fetch_quota(
    access_token: &str,
    email: &str,
    account_id: Option<&str>,
) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    fetch_quota_with_cache(access_token, email, None, account_id).await
}
pub async fn fetch_quota_with_cache(
    access_token: &str,
    email: &str,
    cached_project_id: Option<&str>,
    account_id: Option<&str>,
) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    let profile = crate::modules::system::config::load_app_config()
        .ok()
        .map(|cfg| cfg.proxy.google.mimic.profile)
        .unwrap_or_default();
    let hosts = crate::proxy::google::endpoints::cloudcode_hosts_for_profile(profile);
    let mut last_err: Option<crate::error::AppError> = None;
    for host in hosts {
        let cloud_code_base_url = format!("https://{}", host);
        let quota_api_url = crate::proxy::google::endpoints::endpoint_fetch_available_models(host);
        match fetch_quota_with_cache_at(
            access_token,
            email,
            cached_project_id,
            account_id,
            &quota_api_url,
            &cloud_code_base_url,
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    if let Some(err) = last_err {
        return Err(err);
    }

    fetch_quota_with_cache_at(
        access_token,
        email,
        cached_project_id,
        account_id,
        QUOTA_API_URL,
        CLOUD_CODE_BASE_URL,
    )
    .await
}

async fn fetch_quota_with_cache_at(
    access_token: &str,
    email: &str,
    cached_project_id: Option<&str>,
    account_id: Option<&str>,
    quota_api_url: &str,
    cloud_code_base_url: &str,
) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    use crate::error::AppError;
    let cached_project_id = cached_project_id
        .map(str::trim)
        .filter(|pid| !pid.is_empty());
    let (project_id, subscription_tier) = if let Some(pid) = cached_project_id {
        (Some(pid.to_string()), None)
    } else if cloud_code_base_url == CLOUD_CODE_BASE_URL {
        fetch_project_id(access_token, email, account_id)
            .await
            .map_err(AppError::Unknown)?
    } else {
        fetch_project_id_at(access_token, email, account_id, cloud_code_base_url)
            .await
            .map_err(AppError::Unknown)?
    };

    let final_project_id = project_id.as_deref().unwrap_or("bamboo-precept-lgxtn");

    let client = create_client(account_id).await.map_err(AppError::Unknown)?;
    let payload = json!({
        "project": final_project_id
    });

    let url = quota_api_url;
    let policy = load_policy_from_runtime_config();
    let endpoint_host = host_from_url(url);
    let device_profile = load_account_device_profile(account_id);
    let headers = build_google_headers(
        GoogleHeaderPolicyContext {
            endpoint: url,
            endpoint_host: endpoint_host.as_deref(),
            scope: GoogleHeaderScope::Cloudcode,
            user_agent: crate::constants::USER_AGENT.as_str(),
            access_token: Some(access_token),
            content_type_json: true,
            device_profile: device_profile.as_ref(),
            extra_headers: None,
            force_connection_close: true,
        },
        &policy,
    );
    let mut last_error: Option<AppError> = None;

    for attempt in 1..=MAX_RETRIES {
        match client
            .post(url)
            .headers(headers.clone())
            .json(&payload)
            .send()
            .await
        {
            Ok(response) => {
                if response.error_for_status_ref().is_err() {
                    let status = response.status();
                    if status == reqwest::StatusCode::FORBIDDEN {
                        crate::modules::system::logger::log_warn(
                            "Account unauthorized (403 Forbidden), marking as forbidden",
                        );
                        let mut q = QuotaData::new();
                        q.is_forbidden = true;
                        q.subscription_tier = subscription_tier.clone();
                        return Ok((q, project_id.clone()));
                    }
                    if attempt < MAX_RETRIES {
                        let text = response.text().await.unwrap_or_default();
                        crate::modules::system::logger::log_warn(&format!(
                            "API Error: {} - {} (Attempt {}/{})",
                            status, text, attempt, MAX_RETRIES
                        ));
                        last_error = Some(AppError::Unknown(format!("HTTP {} - {}", status, text)));
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    } else {
                        let text = response.text().await.unwrap_or_default();
                        return Err(AppError::Unknown(format!(
                            "API Error: {} - {}",
                            status, text
                        )));
                    }
                }

                let quota_response: QuotaResponse =
                    response.json().await.map_err(AppError::Network)?;

                let mut quota_data = QuotaData::new();
                tracing::debug!("Quota API returned {} models", quota_response.models.len());

                for (name, info) in quota_response.models {
                    if let Some(quota_info) = info.quota_info {
                        let percentage = quota_info
                            .remaining_fraction
                            .map(|f| (f * 100.0) as i32)
                            .unwrap_or(0);

                        let reset_time = quota_info.reset_time.unwrap_or_default();
                        if name.contains("gemini") || name.contains("claude") {
                            quota_data.add_model(name, percentage, reset_time);
                        }
                    }
                }
                quota_data.subscription_tier = subscription_tier.clone();

                return Ok((quota_data, project_id.clone()));
            }
            Err(e) => {
                crate::modules::system::logger::log_warn(&format!(
                    "Request failed: {} (Attempt {}/{})",
                    e, attempt, MAX_RETRIES
                ));
                last_error = Some(AppError::Network(e));
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| AppError::Unknown("Quota fetch failed".to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;

    #[derive(Clone, Default)]
    struct QuotaCaptureState {
        load_headers: Arc<AsyncMutex<Vec<(String, String)>>>,
        load_body: Arc<AsyncMutex<Option<serde_json::Value>>>,
        quota_headers: Arc<AsyncMutex<Vec<(String, String)>>>,
        quota_body: Arc<AsyncMutex<Option<serde_json::Value>>>,
    }

    async fn quota_router_handler(
        State(state): State<QuotaCaptureState>,
        uri: axum::http::Uri,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let mut out = Vec::new();
        for (name, value) in &headers {
            out.push((
                name.as_str().to_string(),
                value.to_str().unwrap_or("<non-utf8>").to_string(),
            ));
        }
        if uri.path().ends_with(":loadCodeAssist") {
            *state.load_headers.lock().await = out;
            *state.load_body.lock().await = Some(body);
            return Json(json!({
                "cloudaicompanionProject": "quota-proj-1",
                "currentTier": { "id": "free" }
            }));
        }

        *state.quota_headers.lock().await = out;
        *state.quota_body.lock().await = Some(body);
        Json(json!({
            "models": {
                "gemini-2.5-pro": {
                    "quotaInfo": {
                        "remainingFraction": 0.42,
                        "resetTime": "2026-02-14T00:00:00Z"
                    }
                }
            }
        }))
    }

    async fn start_mock_quota_server() -> (String, QuotaCaptureState, tokio::task::JoinHandle<()>) {
        let state = QuotaCaptureState::default();
        let app = Router::new()
            .route("/*path", post(quota_router_handler))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock quota server");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock quota server");
        });

        (format!("http://{}", addr), state, server)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn quota_flow_sends_gzip_and_standardized_metadata() {
        let (base_url, state, server) = start_mock_quota_server().await;
        let quota_url = format!("{}/v1internal:fetchAvailableModels", base_url);

        let (quota, project_id) = fetch_quota_with_cache_at(
            "access-token",
            "test@example.com",
            None,
            None,
            &quota_url,
            &base_url,
        )
        .await
        .expect("quota flow should succeed");

        assert_eq!(project_id.as_deref(), Some("quota-proj-1"));
        assert!(quota
            .models
            .iter()
            .any(|m| m.name == "gemini-2.5-pro"));

        let load_headers = state.load_headers.lock().await.clone();
        let load_body = state
            .load_body
            .lock()
            .await
            .clone()
            .expect("captured loadCodeAssist body");
        let quota_headers = state.quota_headers.lock().await.clone();
        let quota_body = state
            .quota_body
            .lock()
            .await
            .clone()
            .expect("captured fetchAvailableModels body");
        server.abort();

        let find = |headers: &Vec<(String, String)>, name: &str| -> Option<String> {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };

        assert_eq!(
            find(&load_headers, "accept-encoding"),
            Some("gzip, deflate, br".to_string())
        );
        assert_eq!(
            find(&quota_headers, "accept-encoding"),
            Some("gzip, deflate, br".to_string())
        );
        assert!(load_body.pointer("/metadata/ideType").is_some());
        assert!(load_body.pointer("/metadata/platform").is_some());
        assert!(load_body.pointer("/metadata/pluginType").is_some());
        assert_eq!(quota_body.pointer("/project").and_then(|v| v.as_str()), Some("quota-proj-1"));
    }
}
