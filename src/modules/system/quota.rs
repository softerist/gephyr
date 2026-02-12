use crate::models::QuotaData;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::json;

const QUOTA_API_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels";

const MAX_RETRIES: u32 = 3;

fn load_account_device_profile(account_id: Option<&str>) -> Option<crate::models::DeviceProfile> {
    let id = account_id?;
    crate::modules::auth::account::load_account(id)
        .ok()
        .and_then(|account| account.device_profile)
}

fn apply_account_device_headers(
    mut request: reqwest::RequestBuilder,
    account_id: Option<&str>,
) -> reqwest::RequestBuilder {
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

const CLOUD_CODE_BASE_URL: &str = "https://cloudcode-pa.googleapis.com";
async fn fetch_project_id(
    access_token: &str,
    email: &str,
    account_id: Option<&str>,
) -> Result<(Option<String>, Option<String>), String> {
    let client = create_client(account_id).await?;
    let meta = json!({"metadata": {"ideType": "ANTIGRAVITY"}});

    let res = apply_account_device_headers(
        client
            .post(format!("{}/v1internal:loadCodeAssist", CLOUD_CODE_BASE_URL))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", access_token),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::USER_AGENT,
                crate::constants::USER_AGENT.as_str(),
            ),
        account_id,
    )
    .json(&meta)
    .send()
    .await;

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
    use crate::error::AppError;
    let (project_id, subscription_tier) = if let Some(pid) = cached_project_id {
        (Some(pid.to_string()), None)
    } else {
        fetch_project_id(access_token, email, account_id)
            .await
            .map_err(AppError::Unknown)?
    };

    let final_project_id = project_id.as_deref().unwrap_or("bamboo-precept-lgxtn");

    let client = create_client(account_id).await.map_err(AppError::Unknown)?;
    let payload = json!({
        "project": final_project_id
    });

    let url = QUOTA_API_URL;
    let mut last_error: Option<AppError> = None;

    for attempt in 1..=MAX_RETRIES {
        match apply_account_device_headers(
            client
                .post(url)
                .bearer_auth(access_token)
                .header(
                    reqwest::header::USER_AGENT,
                    crate::constants::USER_AGENT.as_str(),
                )
                .json(&json!(payload)),
            account_id,
        )
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
