use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::proxy::upstream::header_policy::{
    build_google_headers, build_load_code_assist_metadata, host_from_url, load_policy_from_runtime_config,
    GoogleHeaderPolicyContext, GoogleHeaderScope,
};

#[derive(Debug, Clone)]
struct GoogleMimicEndpointSet {
    userinfo: Vec<String>,
    load_code_assist: Vec<String>,
    fetch_user_info: Vec<String>,
    fetch_available_models: Vec<String>,
    onboard_user: Vec<String>,
    cascade_nuxes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct GoogleMimicFlowResult {
    pub triggered: bool,
    pub attempted_steps: u32,
    pub ok_steps: u32,
    pub failed_steps: u32,
    pub skipped_reason: Option<String>,
}

fn load_account_device_profile(account_id: Option<&str>) -> Option<crate::models::DeviceProfile> {
    let id = account_id?;
    crate::modules::auth::account::load_account(id)
        .ok()
        .and_then(|account| account.device_profile)
}

fn mimic_cooldown_state() -> &'static Mutex<HashMap<String, Instant>> {
    static STATE: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn should_run_now(account_id: Option<&str>, cooldown_seconds: u64) -> bool {
    let key = account_id.unwrap_or("<unknown-account>").to_string();
    if let Ok(mut state) = mimic_cooldown_state().lock() {
        let now = Instant::now();
        let cooldown = Duration::from_secs(cooldown_seconds.max(1));
        state.retain(|_, ts| now.duration_since(*ts) < cooldown.saturating_mul(4));
        if let Some(last_run) = state.get(&key) {
            if now.duration_since(*last_run) < cooldown {
                return false;
            }
        }
        state.insert(key, now);
        return true;
    }
    true
}

async fn get_effective_client(account_id: Option<&str>) -> Result<reqwest::Client, String> {
    if let (Some(pool), Some(acc_id)) = (
        crate::proxy::proxy_pool::get_global_proxy_pool(),
        account_id,
    ) {
        return pool
            .get_effective_client(Some(acc_id), 15)
            .await
            .map_err(|e| format!("Failed to prepare mimic-flow client: {}", e));
    }
    Ok(crate::utils::http::get_client())
}

fn build_headers_for_endpoint(
    endpoint: &str,
    account_id: Option<&str>,
    access_token: Option<&str>,
    scope: GoogleHeaderScope,
    content_type_json: bool,
    force_connection_close: bool,
) -> reqwest::header::HeaderMap {
    let policy = load_policy_from_runtime_config();
    let endpoint_host = host_from_url(endpoint);
    let device_profile = load_account_device_profile(account_id);
    build_google_headers(
        GoogleHeaderPolicyContext {
            endpoint,
            endpoint_host: endpoint_host.as_deref(),
            scope,
            user_agent: crate::constants::USER_AGENT.as_str(),
            access_token,
            content_type_json,
            device_profile: device_profile.as_ref(),
            extra_headers: None,
            force_connection_close,
        },
        &policy,
    )
}

async fn run_get_step(
    client: &reqwest::Client,
    account_id: Option<&str>,
    step: &str,
    endpoint: &str,
    access_token: &str,
) -> Result<u16, String> {
    let started = Instant::now();
    let headers = build_headers_for_endpoint(
        endpoint,
        account_id,
        Some(access_token),
        GoogleHeaderScope::OAuth,
        false,
        true,
    );

    let response = client
        .get(endpoint)
        .headers(headers)
        .send()
        .await
        .map_err(|e| format!("{} request failed: {}", step, e))?;

    let status = response.status().as_u16();
    let latency_ms = started.elapsed().as_millis() as u64;
    let is_ok = response.status().is_success();
    tracing::debug!(
        account_id = account_id.unwrap_or("<none>"),
        step = step,
        endpoint = endpoint,
        status = status,
        latency_ms = latency_ms,
        fail_open_result = if is_ok { "ok" } else { "continued_after_failure" },
        "google_mimic_flow_step"
    );

    if is_ok {
        Ok(status)
    } else {
        Err(format!("{} returned HTTP {}", step, status))
    }
}

async fn run_get_step_with_endpoints(
    client: &reqwest::Client,
    account_id: Option<&str>,
    step: &str,
    endpoints: &[String],
    access_token: &str,
) -> Result<(), String> {
    let mut last_err = String::new();
    for endpoint in endpoints {
        match run_get_step(client, account_id, step, endpoint, access_token).await {
            Ok(_) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

async fn run_json_post_step(
    client: &reqwest::Client,
    account_id: Option<&str>,
    step: &str,
    endpoint: &str,
    access_token: &str,
    body: &serde_json::Value,
) -> Result<(u16, Option<serde_json::Value>), String> {
    let started = Instant::now();
    let headers = build_headers_for_endpoint(
        endpoint,
        account_id,
        Some(access_token),
        GoogleHeaderScope::Cloudcode,
        true,
        true,
    );

    let response = client
        .post(endpoint)
        .headers(headers)
        .json(body)
        .send()
        .await
        .map_err(|e| format!("{} request failed: {}", step, e))?;

    let status = response.status().as_u16();
    let is_ok = response.status().is_success();
    let parsed_json = if is_ok {
        response.json::<serde_json::Value>().await.ok()
    } else {
        None
    };
    let latency_ms = started.elapsed().as_millis() as u64;
    tracing::debug!(
        account_id = account_id.unwrap_or("<none>"),
        step = step,
        endpoint = endpoint,
        status = status,
        latency_ms = latency_ms,
        fail_open_result = if is_ok { "ok" } else { "continued_after_failure" },
        "google_mimic_flow_step"
    );

    if is_ok {
        Ok((status, parsed_json))
    } else {
        Err(format!("{} returned HTTP {}", step, status))
    }
}

async fn run_json_post_step_with_endpoints(
    client: &reqwest::Client,
    account_id: Option<&str>,
    step: &str,
    endpoints: &[String],
    access_token: &str,
    body: &serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    let mut last_err = String::new();
    for endpoint in endpoints {
        match run_json_post_step(client, account_id, step, endpoint, access_token, body).await {
            Ok((_, parsed)) => return Ok(parsed),
            Err(e) => {
                last_err = e;
                continue;
            }
        }
    }
    Err(last_err)
}

async fn run_mimic_flow_with_endpoints(
    client: &reqwest::Client,
    access_token: &str,
    account_id: Option<&str>,
    project_id: Option<&str>,
    endpoints: &GoogleMimicEndpointSet,
) -> GoogleMimicFlowResult {
    let mut result = GoogleMimicFlowResult::default();
    result.triggered = true;

    let mut active_project = project_id
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "bamboo-precept-lgxtn".to_string());

    let policy = load_policy_from_runtime_config();
    let metadata = build_load_code_assist_metadata(&policy);

    result.attempted_steps += 1;
    match run_get_step_with_endpoints(
        client,
        account_id,
        "userinfo",
        &endpoints.userinfo,
        access_token,
    )
    .await
    {
        Ok(()) => result.ok_steps += 1,
        Err(_) => result.failed_steps += 1,
    }

    result.attempted_steps += 1;
    match run_json_post_step_with_endpoints(
        client,
        account_id,
        "loadCodeAssist",
        &endpoints.load_code_assist,
        access_token,
        &metadata,
    )
    .await
    {
        Ok(Some(data)) => {
            if let Some(pid) = data
                .get("cloudaicompanionProject")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                active_project = pid.to_string();
            }
            result.ok_steps += 1;
        }
        Ok(None) => result.ok_steps += 1,
        Err(_) => result.failed_steps += 1,
    }

    let project_payload = json!({ "project": active_project });
    let onboard_payload = json!({
        "project": project_payload["project"].clone(),
        "metadata": {
            "ideType": policy.identity_metadata.ide_type,
            "platform": policy.identity_metadata.platform,
            "pluginType": policy.identity_metadata.plugin_type
        }
    });

    for (step, endpoints, body) in [
        ("fetchUserInfo", &endpoints.fetch_user_info, &project_payload),
        (
            "fetchAvailableModels",
            &endpoints.fetch_available_models,
            &project_payload,
        ),
        ("onboardUser", &endpoints.onboard_user, &onboard_payload),
        ("cascadeNuxes", &endpoints.cascade_nuxes, &project_payload),
    ] {
        result.attempted_steps += 1;
        match run_json_post_step_with_endpoints(client, account_id, step, endpoints, access_token, body)
            .await
        {
            Ok(_) => result.ok_steps += 1,
            Err(_) => result.failed_steps += 1,
        }
    }

    result
}

pub async fn run_auth_event_mimic_flow(
    access_token: &str,
    account_id: Option<&str>,
    project_id: Option<&str>,
) -> GoogleMimicFlowResult {
    let mut result = GoogleMimicFlowResult::default();
    let config = match crate::modules::system::config::load_app_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            result.skipped_reason = Some(format!("config_load_failed: {}", e));
            return result;
        }
    };
    let google_cfg = config.proxy.google;
    if !google_cfg.mimic.trigger_on_auth_events {
        result.skipped_reason = Some("trigger_on_auth_events_disabled".to_string());
        return result;
    }
    if matches!(
        google_cfg.mimic.profile,
        crate::proxy::config::GoogleMimicProfile::Functional
    ) {
        result.skipped_reason = Some("mimic_profile_functional".to_string());
        return result;
    }
    if !should_run_now(account_id, google_cfg.mimic.cooldown_seconds) {
        result.skipped_reason = Some("cooldown_active".to_string());
        return result;
    }

    let client = match get_effective_client(account_id).await {
        Ok(c) => c,
        Err(e) => {
            result.skipped_reason = Some(e);
            return result;
        }
    };

    let hosts =
        crate::proxy::google::endpoints::cloudcode_hosts_for_profile(google_cfg.mimic.profile);
    let userinfo_endpoints =
        crate::proxy::google::endpoints::userinfo_endpoints(google_cfg.userinfo_endpoint);
    let endpoints = GoogleMimicEndpointSet {
        userinfo: userinfo_endpoints.iter().map(|s| (*s).to_string()).collect(),
        load_code_assist: hosts
            .iter()
            .map(|h| crate::proxy::google::endpoints::endpoint_load_code_assist(h))
            .collect(),
        fetch_user_info: hosts
            .iter()
            .map(|h| crate::proxy::google::endpoints::endpoint_fetch_user_info(h))
            .collect(),
        fetch_available_models: hosts
            .iter()
            .map(|h| crate::proxy::google::endpoints::endpoint_fetch_available_models(h))
            .collect(),
        onboard_user: hosts
            .iter()
            .map(|h| crate::proxy::google::endpoints::endpoint_onboard_user(h))
            .collect(),
        cascade_nuxes: hosts
            .iter()
            .map(|h| crate::proxy::google::endpoints::endpoint_cascade_nuxes(h))
            .collect(),
    };

    tracing::debug!(
        account_id = account_id.unwrap_or("<none>"),
        profile = "strict_mimic",
        trigger = "auth_event",
        cooldown_seconds = google_cfg.mimic.cooldown_seconds,
        "google_mimic_flow_start"
    );

    result = run_mimic_flow_with_endpoints(&client, access_token, account_id, project_id, &endpoints)
        .await;

    tracing::debug!(
        account_id = account_id.unwrap_or("<none>"),
        attempted_steps = result.attempted_steps,
        ok_steps = result.ok_steps,
        failed_steps = result.failed_steps,
        fail_open_result = if result.failed_steps == 0 {
            "all_steps_ok"
        } else {
            "continued_with_partial_failures"
        },
        "google_mimic_flow_end"
    );

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
    use serde_json::Value;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;

    #[test]
    fn cooldown_blocks_immediate_replay_for_same_account() {
        let account = "cooldown-test-account";
        assert!(should_run_now(Some(account), 60));
        assert!(!should_run_now(Some(account), 60));
    }

    #[test]
    fn cooldown_is_isolated_per_account() {
        let a = "cooldown-test-account-a";
        let b = "cooldown-test-account-b";
        assert!(should_run_now(Some(a), 60));
        assert!(should_run_now(Some(b), 60));
    }

    #[derive(Clone, Default)]
    struct CaptureState {
        order: Arc<AsyncMutex<Vec<String>>>,
        bodies: Arc<AsyncMutex<Vec<(String, Value)>>>,
        fail_step: Arc<AsyncMutex<Option<String>>>,
    }

    async fn userinfo_handler(State(state): State<CaptureState>) -> (StatusCode, Json<Value>) {
        state.order.lock().await.push("userinfo".to_string());
        (StatusCode::OK, Json(json!({"email":"x@example.com"})))
    }

    async fn cloudcode_handler(
        State(state): State<CaptureState>,
        uri: axum::http::Uri,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        let path = uri.path().to_string();
        let step = if path.ends_with(":loadCodeAssist") {
            "loadCodeAssist"
        } else if path.ends_with(":fetchUserInfo") {
            "fetchUserInfo"
        } else if path.ends_with(":fetchAvailableModels") {
            "fetchAvailableModels"
        } else if path.ends_with(":onboardUser") {
            "onboardUser"
        } else if path.ends_with("/cascadeNuxes") {
            "cascadeNuxes"
        } else {
            "unknown"
        };

        if step == "unknown" {
            return (StatusCode::NOT_FOUND, Json(json!({"error":"unknown"})));
        }
        if let Some(fail) = state.fail_step.lock().await.clone() {
            if fail == step {
                state.order.lock().await.push(step.to_string());
                state.bodies.lock().await.push((step.to_string(), body));
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error":"forced"})));
            }
        }

        state.order.lock().await.push(step.to_string());
        state.bodies.lock().await.push((step.to_string(), body));

        if step == "loadCodeAssist" {
            return (
                StatusCode::OK,
                Json(json!({"cloudaicompanionProject":"proj-from-load"})),
            );
        }
        (StatusCode::OK, Json(json!({})))
    }

    async fn start_mock_server(
        fail_step: Option<&str>,
    ) -> (String, CaptureState, tokio::task::JoinHandle<()>) {
        let state = CaptureState::default();
        *state.fail_step.lock().await = fail_step.map(|s| s.to_string());
        let app = Router::new()
            .route("/oauth2/v2/userinfo", get(userinfo_handler))
            .route("/*path", post(cloudcode_handler))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("http://{}", addr), state, server)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn strict_mimic_flow_happy_path_orders_steps_and_payloads() {
        let (base, state, server) = start_mock_server(None).await;
        let endpoints = GoogleMimicEndpointSet {
            userinfo: vec![format!("{}/oauth2/v2/userinfo", base)],
            load_code_assist: vec![format!("{}/v1internal:loadCodeAssist", base)],
            fetch_user_info: vec![format!("{}/v1internal:fetchUserInfo", base)],
            fetch_available_models: vec![format!("{}/v1internal:fetchAvailableModels", base)],
            onboard_user: vec![format!("{}/v1internal:onboardUser", base)],
            cascade_nuxes: vec![format!("{}/v1internal/cascadeNuxes", base)],
        };

        let client = reqwest::Client::new();
        let result = run_mimic_flow_with_endpoints(&client, "tok", None, Some("proj-ignored"), &endpoints).await;
        server.abort();

        assert!(result.triggered);
        assert_eq!(result.attempted_steps, 6);
        assert_eq!(result.failed_steps, 0);

        let order = state.order.lock().await.clone();
        assert_eq!(
            order,
            vec![
                "userinfo",
                "loadCodeAssist",
                "fetchUserInfo",
                "fetchAvailableModels",
                "onboardUser",
                "cascadeNuxes"
            ]
        );

        let bodies = state.bodies.lock().await.clone();
        let find = |step: &str| bodies.iter().find(|(s, _)| s == step).map(|(_, b)| b.clone());

        let load = find("loadCodeAssist").expect("load body");
        assert!(load.pointer("/metadata/ideType").is_some());
        assert!(load.pointer("/metadata/platform").is_some());
        assert!(load.pointer("/metadata/pluginType").is_some());

        let fetch_user = find("fetchUserInfo").expect("fetchUserInfo body");
        assert_eq!(
            fetch_user.pointer("/project").and_then(|v| v.as_str()),
            Some("proj-from-load")
        );

        let onboard = find("onboardUser").expect("onboardUser body");
        assert_eq!(
            onboard.pointer("/project").and_then(|v| v.as_str()),
            Some("proj-from-load")
        );
        assert!(onboard.pointer("/metadata/ideType").is_some());
        assert!(onboard.pointer("/metadata/platform").is_some());
        assert!(onboard.pointer("/metadata/pluginType").is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn strict_mimic_flow_is_fail_open_on_step_failure() {
        let (base, state, server) = start_mock_server(Some("fetchUserInfo")).await;
        let endpoints = GoogleMimicEndpointSet {
            userinfo: vec![format!("{}/oauth2/v2/userinfo", base)],
            load_code_assist: vec![format!("{}/v1internal:loadCodeAssist", base)],
            fetch_user_info: vec![format!("{}/v1internal:fetchUserInfo", base)],
            fetch_available_models: vec![format!("{}/v1internal:fetchAvailableModels", base)],
            onboard_user: vec![format!("{}/v1internal:onboardUser", base)],
            cascade_nuxes: vec![format!("{}/v1internal/cascadeNuxes", base)],
        };

        let client = reqwest::Client::new();
        let result = run_mimic_flow_with_endpoints(&client, "tok", None, None, &endpoints).await;
        server.abort();

        assert_eq!(result.attempted_steps, 6);
        assert!(result.failed_steps >= 1);

        // Ensure later steps still happened.
        let order = state.order.lock().await.clone();
        assert!(order.contains(&"onboardUser".to_string()));
        assert!(order.contains(&"cascadeNuxes".to_string()));
    }
}
