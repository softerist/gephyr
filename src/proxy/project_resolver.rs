use serde_json::Value;

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
        request = request
            .header("x-machine-id", profile.machine_id)
            .header("x-mac-machine-id", profile.mac_machine_id)
            .header("x-dev-device-id", profile.dev_device_id)
            .header("x-sqm-id", profile.sqm_id);
    }
    request
}

pub async fn fetch_project_id(
    access_token: &str,
    account_id: Option<&str>,
) -> Result<String, String> {
    let url = "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:loadCodeAssist";

    let request_body = serde_json::json!({
        "metadata": {
            "ideType": "ANTIGRAVITY"
        }
    });

    let client = crate::utils::http::get_client();
    let response = apply_account_device_headers(
        client
            .post(url)
            .bearer_auth(access_token)
            .header("User-Agent", crate::constants::USER_AGENT.as_str())
            .header("Content-Type", "application/json"),
        account_id,
    )
    .json(&request_body)
    .send()
    .await
    .map_err(|e| format!("loadCodeAssist request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "loadCodeAssist returned error {}: {}",
            status, body
        ));
    }

    let data: Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    if let Some(project_id) = data.get("cloudaicompanionProject").and_then(|v| v.as_str()) {
        return Ok(project_id.to_string());
    }
    let mock_id = generate_mock_project_id();
    tracing::warn!("Account ineligible for official cloudaicompanionProject, using randomly generated Project ID as fallback: {}", mock_id);
    Ok(mock_id)
}
pub fn generate_mock_project_id() -> String {
    use rand::Rng;

    let adjectives = ["useful", "bright", "swift", "calm", "bold"];
    let nouns = ["fuze", "wave", "spark", "flow", "core"];

    let mut rng = rand::thread_rng();
    let adj = adjectives[rng.gen_range(0..adjectives.len())];
    let noun = nouns[rng.gen_range(0..nouns.len())];
    let random_num: String = (0..5)
        .map(|_| {
            let chars = "abcdefghijklmnopqrstuvwxyz0123456789";
            let idx = rng.gen_range(0..chars.len());
            chars.chars().nth(idx).unwrap()
        })
        .collect();

    format!("{}-{}-{}", adj, noun, random_num)
}
