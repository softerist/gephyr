use tokio::time::{sleep, Duration};
use tracing::{debug, info};
use axum::{http::StatusCode, response::{IntoResponse, Response}, Json, extract::State};
use serde_json::{json, Value};
use crate::proxy::server::ModelCatalogState;

// ===== Unified Retry and Backoff Strategies =====

// Retry strategy enum
#[derive(Debug, Clone)]
pub enum RetryStrategy {
    // No retry, return error directly
    NoRetry,
    // Fixed delay
    FixedDelay(Duration),
    // Linear backoff: base_ms * (attempt + 1)
    LinearBackoff { base_ms: u64 },
    // Exponential backoff: base_ms * 2^attempt, capped at max_ms
    ExponentialBackoff { base_ms: u64, max_ms: u64 },
}

// Determine retry strategy based on error status code and error message
pub fn determine_retry_strategy(
    status_code: u16,
    error_text: &str,
    retried_without_thinking: bool,
) -> RetryStrategy {
    match status_code {
        // 400 Error: Retry once only for specific Thinking signature failures
        400 if !retried_without_thinking
            && (error_text.contains("Invalid `signature`")
                || error_text.contains("thinking.signature")
                || error_text.contains("thinking.thinking")
                || error_text.contains("Corrupted thought signature")) =>
        {
            RetryStrategy::FixedDelay(Duration::from_millis(200))
        }

        // 429 Rate limiting error
        429 => {
            // Prioritize using Retry-After returned by the server
            if let Some(delay_ms) = crate::proxy::upstream::retry::parse_retry_delay(error_text) {
                let actual_delay = delay_ms.saturating_add(200).min(30_000); // cap increased to 30s
                RetryStrategy::FixedDelay(Duration::from_millis(actual_delay))
            } else {
                // Otherwise use linear backoff: starting at 5s, increasing gradually
                RetryStrategy::LinearBackoff { base_ms: 5000 }
            }
        }

        // Exponential backoff: starting at 10s, capped at 60s (targeting Google edge node overload)
        503 | 529 => {
            RetryStrategy::ExponentialBackoff {
                base_ms: 10000,
                max_ms: 60000,
            }
        }

        // 500 Internal Server Error
        500 => {
            // Linear backoff: starting at 3s
            RetryStrategy::LinearBackoff { base_ms: 3000 }
        }

        // 401/403 Auth/Permission error: provide a short buffer before switching accounts
        401 | 403 => RetryStrategy::FixedDelay(Duration::from_millis(200)),

        // Other errors: no retry
        _ => RetryStrategy::NoRetry,
    }
}

// Execute backoff strategy and return whether retry should continue
pub async fn apply_retry_strategy(
    strategy: RetryStrategy,
    attempt: usize,
    max_attempts: usize,
    status_code: u16,
    trace_id: &str,
) -> bool {
    match strategy {
        RetryStrategy::NoRetry => {
            debug!("[{}] Non-retryable error {}, stopping", trace_id, status_code);
            false
        }

        RetryStrategy::FixedDelay(duration) => {
            let base_ms = duration.as_millis() as u64;
            info!(
                "[{}] ⏱️ Retry with fixed delay: status={}, attempt={}/{}, delay={}ms",
                trace_id,
                status_code,
                attempt + 1,
                max_attempts,
                base_ms
            );
            sleep(duration).await;
            true
        }

        RetryStrategy::LinearBackoff { base_ms } => {
            let calculated_ms = base_ms * (attempt as u64 + 1);
            info!(
                "[{}] ⏱️ Retry with linear backoff: status={}, attempt={}/{}, delay={}ms",
                trace_id,
                status_code,
                attempt + 1,
                max_attempts,
                calculated_ms
            );
            sleep(Duration::from_millis(calculated_ms)).await;
            true
        }

        RetryStrategy::ExponentialBackoff { base_ms, max_ms } => {
            let calculated_ms = (base_ms * 2_u64.pow(attempt as u32)).min(max_ms);
            info!(
                "[{}] ⏱️ Retry with exponential backoff: status={}, attempt={}/{}, delay={}ms",
                trace_id,
                status_code,
                attempt + 1,
                max_attempts,
                calculated_ms
            );
            sleep(Duration::from_millis(calculated_ms)).await;
            true
        }
    }
}

// Determine if account rotation is needed
pub fn should_rotate_account(status_code: u16) -> bool {
    match status_code {
        // These errors are account-level or node-specific quota issues, rotation is needed
        429 | 401 | 403 | 500 => true,
        // These errors are usually protocol or server-level global issues, or even parameter errors, rotation is usually meaningless
        400 | 503 | 529 => false,
        _ => false,
    }
}

// Detects model capabilities and configuration
// POST /v1/models/detect
pub async fn handle_detect_model(
    State(state): State<ModelCatalogState>,
    Json(body): Json<Value>,
) -> Response {
    let model_name = body.get("model").and_then(|v| v.as_str()).unwrap_or("");
    
    if model_name.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing 'model' field").into_response();
    }

    // 1. Resolve mapping
    let mapped_model = crate::proxy::common::model_mapping::resolve_model_route(
        model_name,
        &*state.custom_mapping.read().await,
    );

    // 2. Resolve capabilities
    let config = crate::proxy::mappers::common_utils::resolve_request_config(
        model_name,
        &mapped_model,
        &None, // We don't check tools for static capability detection
        None,  // size
        None,  // quality
        None,  // body (not needed for static detection)
    );

    // 3. Construct response
    let mut response = json!({
        "model": model_name,
        "mapped_model": mapped_model,
        "type": config.request_type,
        "features": {
            "has_web_search": config.inject_google_search,
            "is_image_gen": config.request_type == "image_gen"
        }
    });

    if let Some(img_conf) = config.image_config {
        if let Some(obj) = response.as_object_mut() {
            obj.insert("config".to_string(), img_conf);
        }
    }

    Json(response).into_response()
}

pub async fn build_models_list_response(state: &ModelCatalogState) -> Json<Value> {
    use crate::proxy::common::model_mapping::get_all_dynamic_models;

    let model_ids = get_all_dynamic_models(&state.custom_mapping).await;

    let data: Vec<_> = model_ids
        .into_iter()
        .map(|id| {
            json!({
                "id": id,
                "object": "model",
                "created": 1706745600,
                "owned_by": "antigravity"
            })
        })
        .collect();

    Json(json!({
        "object": "list",
        "data": data
    }))
}
