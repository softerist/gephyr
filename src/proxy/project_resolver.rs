use serde_json::Value;

// Use Antigravity's loadCodeAssist API to fetch project_id
// This is the correct way to get the cloudaicompanionProject
pub async fn fetch_project_id(access_token: &str) -> Result<String, String> {
    // Use Sandbox environment to avoid 429 errors from the Prod environment
    let url = "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:loadCodeAssist";
    
    let request_body = serde_json::json!({
        "metadata": {
            "ideType": "ANTIGRAVITY"
        }
    });
    
    let client = crate::utils::http::get_client();
    let response = client
        .post(url)
        .bearer_auth(access_token)
        // .header("Host", "cloudcode-pa.googleapis.com") // Host header removed due to domain change

        .header("User-Agent", crate::constants::USER_AGENT.as_str())
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("loadCodeAssist request failed: {}", e))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("loadCodeAssist returned error {}: {}", status, body));
    }
    
    let data: Value = response.json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    // Extract cloudaicompanionProject
    if let Some(project_id) = data.get("cloudaicompanionProject")
        .and_then(|v| v.as_str()) {
        return Ok(project_id.to_string());
    }
    
    // If no project_id is returned, the account is ineligible; use randomly generated fallback logic
    let mock_id = generate_mock_project_id();
    tracing::warn!("Account ineligible for official cloudaicompanionProject, using randomly generated Project ID as fallback: {}", mock_id);
    Ok(mock_id)
}

// Generate random project_id (used when fetching from API fails)
// Format: {adjective}-{noun}-{5-character-random-string}
pub fn generate_mock_project_id() -> String {
    use rand::Rng;
    
    let adjectives = ["useful", "bright", "swift", "calm", "bold"];
    let nouns = ["fuze", "wave", "spark", "flow", "core"];
    
    let mut rng = rand::thread_rng();
    let adj = adjectives[rng.gen_range(0..adjectives.len())];
    let noun = nouns[rng.gen_range(0..nouns.len())];
    
    // Generate 5 random characters (base36)
    let random_num: String = (0..5)
        .map(|_| {
            let chars = "abcdefghijklmnopqrstuvwxyz0123456789";
            let idx = rng.gen_range(0..chars.len());
            chars.chars().nth(idx).unwrap()
        })
        .collect();
    
    format!("{}-{}-{}", adj, noun, random_num)
}
