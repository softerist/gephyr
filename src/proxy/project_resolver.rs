use serde_json::Value;
use crate::proxy::upstream::header_policy::{
    build_google_headers, build_load_code_assist_metadata, host_from_url,
    load_policy_from_runtime_config, GoogleHeaderPolicyContext, GoogleHeaderScope,
};

fn load_account_device_profile(account_id: Option<&str>) -> Option<crate::models::DeviceProfile> {
    let id = account_id?;
    crate::modules::auth::account::load_account(id)
        .ok()
        .and_then(|account| account.device_profile)
}

pub async fn fetch_project_id(
    access_token: &str,
    account_id: Option<&str>,
) -> Result<String, String> {
    let profile = crate::modules::system::config::load_app_config()
        .ok()
        .map(|cfg| cfg.proxy.google.mimic.profile)
        .unwrap_or_default();
    let hosts = crate::proxy::google::endpoints::cloudcode_hosts_for_profile(profile);
    let mut last_err = String::new();
    for host in hosts {
        let endpoint = crate::proxy::google::endpoints::endpoint_load_code_assist(host);
        match fetch_project_id_at(access_token, account_id, &endpoint).await {
            Ok(project_id) => return Ok(project_id),
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
    account_id: Option<&str>,
    url: &str,
) -> Result<String, String> {
    let policy = load_policy_from_runtime_config();
    let request_body = build_load_code_assist_metadata(&policy);
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

    let client = crate::utils::http::get_client();
    let response = client
        .post(url)
        .headers(headers)
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
    if let Some(project_id) = data
        .get("cloudaicompanionProject")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;

    #[derive(Clone, Default)]
    struct LoadCodeAssistCaptureState {
        headers: Arc<AsyncMutex<Vec<(String, String)>>>,
        body: Arc<AsyncMutex<Option<serde_json::Value>>>,
    }

    async fn load_code_assist_handler(
        State(state): State<LoadCodeAssistCaptureState>,
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
        *state.headers.lock().await = out;
        *state.body.lock().await = Some(body);

        Json(json!({
            "cloudaicompanionProject": "test-proj-123"
        }))
    }

    async fn load_code_assist_empty_project_handler() -> Json<serde_json::Value> {
        Json(json!({
            "cloudaicompanionProject": "   "
        }))
    }

    async fn start_mock_load_code_assist_server(
    ) -> (String, LoadCodeAssistCaptureState, tokio::task::JoinHandle<()>) {
        let state = LoadCodeAssistCaptureState::default();
        let app = Router::new()
            .route("/v1internal:loadCodeAssist", post(load_code_assist_handler))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock loadCodeAssist");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock loadCodeAssist");
        });

        (
            format!("http://{}/v1internal:loadCodeAssist", addr),
            state,
            server,
        )
    }

    async fn start_mock_empty_project_server() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/v1internal:loadCodeAssist",
            post(load_code_assist_empty_project_handler),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock empty project");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock empty project");
        });
        (
            format!("http://{}/v1internal:loadCodeAssist", addr),
            server,
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_project_id_sets_gzip_and_standard_metadata() {
        let (url, state, server) = start_mock_load_code_assist_server().await;
        let project_id = fetch_project_id_at("access-token", None, &url)
            .await
            .expect("fetch_project_id should succeed");
        assert_eq!(project_id, "test-proj-123");

        let headers = state.headers.lock().await.clone();
        let body = state
            .body
            .lock()
            .await
            .clone()
            .expect("captured loadCodeAssist request body");
        server.abort();

        let find = |name: &str| -> Option<String> {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };

        assert_eq!(
            find("accept-encoding"),
            Some("gzip, deflate, br".to_string())
        );
        assert_eq!(find("authorization"), Some("Bearer access-token".to_string()));
        assert!(body.pointer("/metadata/ideType").is_some());
        assert!(body.pointer("/metadata/platform").is_some());
        assert!(body.pointer("/metadata/pluginType").is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_project_id_rejects_blank_project_and_uses_fallback() {
        let (url, server) = start_mock_empty_project_server().await;
        let project_id = fetch_project_id_at("access-token", None, &url)
            .await
            .expect("fetch_project_id should succeed");
        server.abort();

        assert!(
            !project_id.trim().is_empty(),
            "blank project id must not be propagated"
        );
        assert_ne!(project_id, "   ");
    }
}
