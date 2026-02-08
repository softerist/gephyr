use axum::{
    extract::Json, extract::State, http::StatusCode, response::IntoResponse, response::Response,
};
use bytes::Bytes;
use futures::StreamExt;
use serde_json::{json, Value};
use tracing::{debug, error, info};

use crate::proxy::debug_logger;
use crate::proxy::mappers::openai::{
    transform_openai_request, transform_openai_response, OpenAIRequest,
};
use crate::proxy::state::{ModelCatalogState, OpenAIHandlerState};

const MAX_RETRY_ATTEMPTS: usize = 3;
use super::common::build_models_list_response;
use super::retry::{
    apply_retry_strategy, determine_retry_strategy, should_rotate_account, RetryStrategy,
};
use crate::proxy::common::client_adapter::CLIENT_ADAPTERS;
use crate::proxy::session_manager::SessionManager;
use axum::http::HeaderMap;
use tokio::time::Duration;

pub async fn handle_chat_completions(
    State(state): State<OpenAIHandlerState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let original_body = body.clone();
    let is_responses_format = body.get("messages").is_none()
        && (body.get("instructions").is_some() || body.get("input").is_some());

    if is_responses_format {
        debug!("Detected Responses API format, converting to Chat Completions format");
        if let Some(instructions) = body.get("instructions").and_then(|v| v.as_str()) {
            if !instructions.is_empty() {
                let system_msg = json!({
                    "role": "system",
                    "content": instructions
                });
                if body.get("messages").is_none() {
                    body["messages"] = json!([]);
                }
                if let Some(messages) = body.get_mut("messages").and_then(|v| v.as_array_mut()) {
                    messages.insert(0, system_msg);
                }
            }
        }
        if let Some(input) = body.get("input") {
            let user_msg = if input.is_string() {
                json!({
                    "role": "user",
                    "content": input.as_str().unwrap_or("")
                })
            } else {
                json!({
                    "role": "user",
                    "content": input.to_string()
                })
            };

            if let Some(messages) = body.get_mut("messages").and_then(|v| v.as_array_mut()) {
                messages.push(user_msg);
            }
        }
    }

    let mut openai_req: OpenAIRequest = serde_json::from_value(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)))?;
    if openai_req.messages.is_empty() {
        debug!("Received request with empty messages, injecting fallback...");
        openai_req
            .messages
            .push(crate::proxy::mappers::openai::OpenAIMessage {
                role: "user".to_string(),
                content: Some(crate::proxy::mappers::openai::OpenAIContent::String(
                    " ".to_string(),
                )),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
                name: None,
            });
    }

    let trace_id = format!("req_{}", chrono::Utc::now().timestamp_subsec_millis());
    info!(
        "[{}] OpenAI Chat Request: {} | {} messages | stream: {}",
        trace_id,
        openai_req.model,
        openai_req.messages.len(),
        openai_req.stream
    );
    let debug_cfg = state.debug_logging.read().await.clone();
    if debug_logger::is_enabled(&debug_cfg) {
        let original_payload = json!({
            "kind": "original_request",
            "protocol": "openai",
            "trace_id": trace_id,
            "original_model": openai_req.model,
            "request": original_body,
        });
        debug_logger::write_debug_payload(
            &debug_cfg,
            Some(&trace_id),
            "original_request",
            &original_payload,
        )
        .await;
    }
    let client_adapter = CLIENT_ADAPTERS
        .iter()
        .find(|a| a.matches(&headers))
        .cloned();
    if client_adapter.is_some() {
        debug!("[{}] Client Adapter detected", trace_id);
    }
    let upstream = state.upstream.clone();
    let token_manager = state.token_manager;
    let pool_size = token_manager.len();
    let max_attempts = MAX_RETRY_ATTEMPTS.min(pool_size.saturating_add(1)).max(2);

    let mut last_error = String::new();
    let mut last_email: Option<String> = None;
    let mapped_model = crate::proxy::common::model_mapping::resolve_model_route(
        &openai_req.model,
        &*state.custom_mapping.read().await,
    );

    for attempt in 0..max_attempts {
        let tools_val: Option<Vec<Value>> = openai_req.tools.as_ref().map(|list| list.to_vec());
        let config = crate::proxy::mappers::common_utils::resolve_request_config(
            &openai_req.model,
            &mapped_model,
            &tools_val,
            None,
            None,
            None,
        );
        let session_id = SessionManager::extract_openai_session_id(&openai_req);
        let (access_token, project_id, email, account_id, _wait_ms) = match token_manager
            .get_token(
                &config.request_type,
                attempt > 0,
                Some(&session_id),
                &mapped_model,
            )
            .await
        {
            Ok(t) => t,
            Err(e) => {
                return Ok(crate::proxy::handlers::errors::text_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("Token error: {}", e),
                    None,
                    Some(&mapped_model),
                ));
            }
        };

        last_email = Some(email.clone());
        info!("✓ Using account: {} (type: {})", email, config.request_type);
        let (gemini_body, session_id, message_count) =
            transform_openai_request(&openai_req, &project_id, &mapped_model);

        if debug_logger::is_enabled(&debug_cfg) {
            let payload = json!({
                "kind": "v1internal_request",
                "protocol": "openai",
                "trace_id": trace_id,
                "original_model": openai_req.model,
                "mapped_model": mapped_model,
                "request_type": config.request_type,
                "attempt": attempt,
                "v1internal_request": gemini_body.clone(),
            });
            debug_logger::write_debug_payload(
                &debug_cfg,
                Some(&trace_id),
                "v1internal_request",
                &payload,
            )
            .await;
        }
        if let Ok(body_json) = serde_json::to_string_pretty(&gemini_body) {
            debug!("[OpenAI-Request] Transformed Gemini Body:\n{}", body_json);
        }
        let client_wants_stream = openai_req.stream;
        let force_stream_internally = !client_wants_stream;
        let actual_stream = client_wants_stream || force_stream_internally;

        if force_stream_internally {
            debug!(
                "[{}] 🔄 Auto-converting non-stream request to stream for better quota",
                trace_id
            );
        }

        let method = if actual_stream {
            "streamGenerateContent"
        } else {
            "generateContent"
        };
        let query_string = if actual_stream { Some("alt=sse") } else { None };
        let mut extra_headers = std::collections::HashMap::new();
        if crate::proxy::common::model_mapping::is_claude_model(&mapped_model) {
            extra_headers.insert(
                "anthropic-beta".to_string(),
                "claude-code-20250219".to_string(),
            );
            tracing::debug!(
                "[{}] Injected Anthropic beta headers for Claude model (via OpenAI)",
                trace_id
            );
        }

        let response = match upstream
            .call_v1_internal_with_headers(
                method,
                &access_token,
                gemini_body,
                query_string,
                extra_headers.clone(),
                Some(account_id.as_str()),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_error = e.clone();
                debug!(
                    "OpenAI Request failed on attempt {}/{}: {}",
                    attempt + 1,
                    max_attempts,
                    e
                );
                continue;
            }
        };

        let status = response.status();
        if status.is_success() {
            if actual_stream {
                use axum::body::Body;

                let meta = json!({
                    "protocol": "openai",
                    "trace_id": trace_id,
                    "original_model": openai_req.model,
                    "mapped_model": mapped_model,
                    "request_type": config.request_type,
                    "attempt": attempt,
                    "status": status.as_u16(),
                });
                let gemini_stream = debug_logger::wrap_reqwest_stream_with_debug(
                    Box::pin(response.bytes_stream()),
                    debug_cfg.clone(),
                    trace_id.clone(),
                    "upstream_response",
                    meta,
                );
                use crate::proxy::mappers::openai::streaming::create_openai_sse_stream;
                let mut openai_stream = create_openai_sse_stream(
                    gemini_stream,
                    openai_req.model.clone(),
                    session_id,
                    message_count,
                );
                let first_data_chunk = match crate::proxy::handlers::streaming::peek_first_data_chunk(
                    &mut openai_stream,
                    &crate::proxy::handlers::streaming::StreamPeekOptions {
                        timeout: Duration::from_secs(60),
                        context: "OpenAI:chat",
                        skip_data_colon_heartbeat: true,
                        detect_error_events: true,
                        error_event_message: "Error event during peek",
                        stream_error_prefix: "Stream error during peek",
                        empty_stream_message: "Empty response stream during peek",
                        timeout_message: "Timeout waiting for first data",
                    },
                )
                .await {
                    Ok(chunk) => chunk,
                    Err(err) => {
                        last_error = err;
                        continue;
                    }
                };
                let combined_stream =
                    futures::stream::once(async move { Ok::<Bytes, String>(first_data_chunk) })
                        .chain(openai_stream);

                if client_wants_stream {
                    let body = Body::from_stream(combined_stream);
                    return Ok(crate::proxy::handlers::streaming::build_sse_response(
                        body,
                        &email,
                        &mapped_model,
                        true,
                    )
                    .into_response());
                } else {
                    use crate::proxy::mappers::openai::collector::collect_stream_to_json;

                    match collect_stream_to_json(Box::pin(combined_stream)).await {
                        Ok(full_response) => {
                            info!("[{}] ✓ Stream collected and converted to JSON", trace_id);
                            return Ok(
                                crate::proxy::handlers::streaming::build_json_response_with_headers(
                                    StatusCode::OK,
                                    &full_response,
                                    Some(&email),
                                    Some(&mapped_model),
                                    &[],
                                )
                                .into_response(),
                            );
                        }
                        Err(e) => {
                            error!("[{}] Stream collection error: {}", trace_id, e);
                            return Ok(crate::proxy::handlers::errors::stream_collection_error_response(
                                &e.to_string(),
                            ));
                        }
                    }
                }
            }

            let gemini_resp: Value = response
                .json()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Parse error: {}", e)))?;

            let openai_response =
                transform_openai_response(&gemini_resp, Some(&session_id), message_count);
            return Ok(
                crate::proxy::handlers::streaming::build_json_response_with_headers(
                    StatusCode::OK,
                    &openai_response,
                    Some(&email),
                    Some(&mapped_model),
                    &[],
                )
                .into_response(),
            );
        }
        let status_code = status.as_u16();
        let _retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| format!("HTTP {}", status_code));
        last_error = format!("HTTP {}: {}", status_code, error_text);
        tracing::error!(
            "[OpenAI-Upstream] Error Response {}: {}",
            status_code,
            error_text
        );
        if debug_logger::is_enabled(&debug_cfg) {
            let payload = json!({
                "kind": "upstream_response_error",
                "protocol": "openai",
                "trace_id": trace_id,
                "original_model": openai_req.model,
                "mapped_model": mapped_model,
                "request_type": config.request_type,
                "attempt": attempt,
                "status": status_code,
                "error_text": error_text,
            });
            debug_logger::write_debug_payload(
                &debug_cfg,
                Some(&trace_id),
                "upstream_response_error",
                &payload,
            )
            .await;
        }
        let strategy = determine_retry_strategy(status_code, &error_text, false);
        if status_code == 429 || status_code == 529 || status_code == 503 || status_code == 500 {
            token_manager
                .mark_rate_limited_async(
                    &email,
                    status_code,
                    _retry_after.as_deref(),
                    &error_text,
                    Some(&mapped_model),
                )
                .await;
        }
        if apply_retry_strategy(strategy, attempt, max_attempts, status_code, &trace_id).await {
            if let Some(adapter) = &client_adapter {
                if adapter.let_it_crash() && attempt > 0 {
                    tracing::warn!(
                        "[OpenAI] let_it_crash active: Aborting retries after attempt {}",
                        attempt
                    );
                    break;
                }
            }
            if !should_rotate_account(status_code) {
                debug!(
                    "[{}] Keeping same account for status {} (server-side issue)",
                    trace_id, status_code
                );
            }
            tracing::warn!(
                "OpenAI Upstream {} on {} attempt {}/{}, rotating account",
                status_code,
                email,
                attempt + 1,
                max_attempts
            );
            continue;
        }
        if status_code == 400
            && (error_text.contains("Invalid `signature`")
                || error_text.contains("thinking.signature")
                || error_text.contains("Invalid signature")
                || error_text.contains("Corrupted thought signature"))
        {
            tracing::warn!(
                "[OpenAI] Signature error detected on account {}, retrying without thinking",
                email
            );
            if let Some(last_msg) = openai_req.messages.last_mut() {
                if last_msg.role == "user" {
                    let repair_prompt = "\n\n[System Recovery] Your previous output contained an invalid signature. Please regenerate the response without the corrupted signature block.";

                    if let Some(content) = &mut last_msg.content {
                        use crate::proxy::mappers::openai::{OpenAIContent, OpenAIContentBlock};
                        match content {
                            OpenAIContent::String(s) => {
                                s.push_str(repair_prompt);
                            }
                            OpenAIContent::Array(arr) => {
                                arr.push(OpenAIContentBlock::Text {
                                    text: repair_prompt.to_string(),
                                });
                            }
                        }
                        tracing::debug!("[OpenAI] Appended repair prompt to last user message");
                    }
                }
            }

            continue;
        }
        if (status_code == 403 || status_code == 401)
            && apply_retry_strategy(
                RetryStrategy::FixedDelay(Duration::from_millis(200)),
                attempt,
                max_attempts,
                status_code,
                &trace_id,
            )
            .await
        {
            continue;
        }
        if status_code == 403 || status_code == 401 {
            if status_code == 403 {
                if let Some(acc_id) = token_manager.get_account_id_by_email(&email) {
                    if error_text.contains("VALIDATION_REQUIRED")
                        || error_text.contains("verify your account")
                        || error_text.contains("validation_url")
                    {
                        tracing::warn!(
                            "[OpenAI] VALIDATION_REQUIRED detected on account {}, temporarily blocking",
                            email
                        );
                        let block_minutes = 10i64;
                        let block_until = chrono::Utc::now().timestamp() + (block_minutes * 60);

                        if let Err(e) = token_manager
                            .set_validation_block_public(&acc_id, block_until, &error_text)
                            .await
                        {
                            tracing::error!("Failed to set validation block: {}", e);
                        }
                    }
                    if let Err(e) = token_manager.set_forbidden(&acc_id, &error_text).await {
                        tracing::error!("Failed to set forbidden status: {}", e);
                    }
                }
            }

            if apply_retry_strategy(
                RetryStrategy::FixedDelay(Duration::from_millis(200)),
                attempt,
                max_attempts,
                status_code,
                &trace_id,
            )
            .await
            {
                continue;
            }
        }
        error!(
            "OpenAI Upstream non-retryable error {} on account {}: {}",
            status_code, email, error_text
        );
        return Ok(crate::proxy::handlers::errors::openai_upstream_error_response(
            status,
            &error_text,
            Some(&email),
            Some(&mapped_model),
        ));
    }
    Ok(crate::proxy::handlers::errors::accounts_exhausted_text_response(
        &last_error,
        last_email.as_deref(),
        Some(&mapped_model),
    ))
}
pub async fn handle_completions(
    State(state): State<OpenAIHandlerState>,
    Json(mut body): Json<Value>,
) -> Response {
    debug!(
        "Received /v1/completions or /v1/responses payload: {:?}",
        body
    );

    let is_codex_style = body.get("input").is_some() || body.get("instructions").is_some();
    if is_codex_style {
        let instructions = body
            .get("instructions")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let input_items = body.get("input").and_then(|v| v.as_array());

        let mut messages = Vec::new();
        if !instructions.is_empty() {
            messages.push(json!({ "role": "system", "content": instructions }));
        }

        let mut call_id_to_name = std::collections::HashMap::new();
        if let Some(items) = input_items {
            for item in items {
                let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match item_type {
                    "function_call" | "local_shell_call" | "web_search_call" => {
                        let call_id = item
                            .get("call_id")
                            .and_then(|v| v.as_str())
                            .or_else(|| item.get("id").and_then(|v| v.as_str()))
                            .unwrap_or("unknown");

                        let name = if item_type == "local_shell_call" {
                            "shell"
                        } else if item_type == "web_search_call" {
                            "google_search"
                        } else {
                            item.get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        };

                        call_id_to_name.insert(call_id.to_string(), name.to_string());
                        tracing::debug!("Mapped call_id {} to name {}", call_id, name);
                    }
                    _ => {}
                }
            }
        }
        if let Some(items) = input_items {
            for item in items {
                let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match item_type {
                    "message" => {
                        let role = item.get("role").and_then(|v| v.as_str()).unwrap_or("user");
                        let content = item.get("content").and_then(|v| v.as_array());
                        let mut text_parts = Vec::new();
                        let mut image_parts: Vec<Value> = Vec::new();

                        if let Some(parts) = content {
                            for part in parts {
                                if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                                    text_parts.push(text.to_string());
                                } else if part.get("type").and_then(|v| v.as_str())
                                    == Some("input_image")
                                {
                                    if let Some(image_url) =
                                        part.get("image_url").and_then(|v| v.as_str())
                                    {
                                        image_parts.push(json!({
                                            "type": "image_url",
                                            "image_url": { "url": image_url }
                                        }));
                                        debug!("[Codex] Found input_image: {}", image_url);
                                    }
                                } else if part.get("type").and_then(|v| v.as_str())
                                    == Some("image_url")
                                {
                                    if let Some(url_obj) = part.get("image_url") {
                                        image_parts.push(json!({
                                            "type": "image_url",
                                            "image_url": url_obj.clone()
                                        }));
                                    }
                                }
                            }
                        }
                        if image_parts.is_empty() {
                            messages.push(json!({
                                "role": role,
                                "content": text_parts.join("\n")
                            }));
                        } else {
                            let mut content_blocks: Vec<Value> = Vec::new();
                            if !text_parts.is_empty() {
                                content_blocks.push(json!({
                                    "type": "text",
                                    "text": text_parts.join("\n")
                                }));
                            }
                            content_blocks.extend(image_parts);
                            messages.push(json!({
                                "role": role,
                                "content": content_blocks
                            }));
                        }
                    }
                    "function_call" | "local_shell_call" | "web_search_call" => {
                        let mut name = item
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let mut args_str = item
                            .get("arguments")
                            .and_then(|v| v.as_str())
                            .unwrap_or("{}")
                            .to_string();
                        let call_id = item
                            .get("call_id")
                            .and_then(|v| v.as_str())
                            .or_else(|| item.get("id").and_then(|v| v.as_str()))
                            .unwrap_or("unknown");
                        if item_type == "local_shell_call" {
                            name = "shell";
                            if let Some(action) = item.get("action") {
                                if let Some(exec) = action.get("exec") {
                                    let mut args_obj = serde_json::Map::new();
                                    if let Some(cmd) = exec.get("command") {
                                        let cmd_val = if cmd.is_string() {
                                            json!([cmd])
                                        } else {
                                            cmd.clone()
                                        };
                                        args_obj.insert("command".to_string(), cmd_val);
                                    }
                                    if let Some(wd) =
                                        exec.get("working_directory").or(exec.get("workdir"))
                                    {
                                        args_obj.insert("workdir".to_string(), wd.clone());
                                    }
                                    args_str = serde_json::to_string(&args_obj)
                                        .unwrap_or("{}".to_string());
                                }
                            }
                        } else if item_type == "web_search_call" {
                            name = "google_search";
                            if let Some(action) = item.get("action") {
                                let mut args_obj = serde_json::Map::new();
                                if let Some(q) = action.get("query") {
                                    args_obj.insert("query".to_string(), q.clone());
                                }
                                args_str =
                                    serde_json::to_string(&args_obj).unwrap_or("{}".to_string());
                            }
                        }

                        messages.push(json!({
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments": args_str
                                    }
                                }
                            ]
                        }));
                    }
                    "function_call_output" | "custom_tool_call_output" => {
                        let call_id = item
                            .get("call_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let output = item.get("output");
                        let output_str = if let Some(o) = output {
                            if o.is_string() {
                                o.as_str().unwrap().to_string()
                            } else if let Some(content) = o.get("content").and_then(|v| v.as_str())
                            {
                                content.to_string()
                            } else {
                                o.to_string()
                            }
                        } else {
                            "".to_string()
                        };

                        let name = call_id_to_name.get(call_id).cloned().unwrap_or_else(|| {
                            tracing::warn!(
                                "Unknown tool name for call_id {}, defaulting to 'shell'",
                                call_id
                            );
                            "shell".to_string()
                        });

                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "name": name,
                            "content": output_str
                        }));
                    }
                    _ => {}
                }
            }
        }

        if let Some(obj) = body.as_object_mut() {
            obj.insert("messages".to_string(), json!(messages));
        }
    } else if let Some(prompt_val) = body.get("prompt") {
        let prompt_str = match prompt_val {
            Value::String(s) => s.clone(),
            Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            _ => prompt_val.to_string(),
        };
        let messages = json!([ { "role": "user", "content": prompt_str } ]);
        if let Some(obj) = body.as_object_mut() {
            obj.remove("prompt");
            obj.insert("messages".to_string(), messages);
        }
    }
    let has_codex_fields = body.get("instructions").is_some() || body.get("input").is_some();
    let already_normalized = body
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false);
    if has_codex_fields && !already_normalized {
        tracing::debug!("[Codex] Performing simple normalization (messages not yet populated)");

        let mut messages = Vec::new();
        if let Some(inst) = body.get("instructions").and_then(|v| v.as_str()) {
            if !inst.is_empty() {
                messages.push(json!({
                    "role": "system",
                    "content": inst
                }));
            }
        }
        if let Some(input) = body.get("input") {
            if let Some(s) = input.as_str() {
                messages.push(json!({
                    "role": "user",
                    "content": s
                }));
            } else if let Some(arr) = input.as_array() {
                let is_message_array = arr
                    .first()
                    .and_then(|v| v.as_object())
                    .map(|obj| obj.contains_key("role"))
                    .unwrap_or(false);

                if is_message_array {
                    for item in arr {
                        messages.push(item.clone());
                    }
                } else {
                    let content = arr
                        .iter()
                        .map(|v| {
                            if let Some(s) = v.as_str() {
                                s.to_string()
                            } else if v.is_object() {
                                v.to_string()
                            } else {
                                "".to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n");

                    if !content.is_empty() {
                        messages.push(json!({
                            "role": "user",
                            "content": content
                        }));
                    }
                }
            } else {
                let content = input.to_string();
                if !content.is_empty() {
                    messages.push(json!({
                        "role": "user",
                        "content": content
                    }));
                }
            };
        }

        if let Some(obj) = body.as_object_mut() {
            tracing::debug!(
                "[Codex] Injecting normalized messages: {} messages",
                messages.len()
            );
            obj.insert("messages".to_string(), json!(messages));
        }
    } else if already_normalized {
        tracing::debug!(
            "[Codex] Skipping normalization (messages already populated by first pass)"
        );
    }

    let mut openai_req: OpenAIRequest = match serde_json::from_value(body.clone()) {
        Ok(req) => req,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)).into_response();
        }
    };
    if openai_req.messages.is_empty() {
        openai_req
            .messages
            .push(crate::proxy::mappers::openai::OpenAIMessage {
                role: "user".to_string(),
                content: Some(crate::proxy::mappers::openai::OpenAIContent::String(
                    " ".to_string(),
                )),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
                name: None,
            });
    }

    let upstream = state.upstream.clone();
    let token_manager = state.token_manager;
    let pool_size = token_manager.len();
    let max_attempts = MAX_RETRY_ATTEMPTS.min(pool_size.saturating_add(1)).max(2);

    let mut last_error = String::new();
    let mut last_email: Option<String> = None;
    let mapped_model = crate::proxy::common::model_mapping::resolve_model_route(
        &openai_req.model,
        &*state.custom_mapping.read().await,
    );
    let trace_id = format!("req_{}", chrono::Utc::now().timestamp_subsec_millis());

    for attempt in 0..max_attempts {
        let tools_val: Option<Vec<Value>> = openai_req.tools.as_ref().map(|list| list.to_vec());
        let config = crate::proxy::mappers::common_utils::resolve_request_config(
            &openai_req.model,
            &mapped_model,
            &tools_val,
            None,
            None,
            None,
        );
        let session_id_str = SessionManager::extract_openai_session_id(&openai_req);
        let session_id = Some(session_id_str.as_str());
        let force_rotate = attempt > 0;

        let (access_token, project_id, email, account_id, _wait_ms) = match token_manager
            .get_token(
                &config.request_type,
                force_rotate,
                session_id,
                &mapped_model,
            )
            .await
        {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("X-Mapped-Model", mapped_model)],
                    format!("Token error: {}", e),
                )
                    .into_response()
            }
        };

        last_email = Some(email.clone());

        info!("✓ Using account: {} (type: {})", email, config.request_type);

        let (gemini_body, session_id, message_count) =
            transform_openai_request(&openai_req, &project_id, &mapped_model);
        debug!(
            "[Codex-Request] Transformed Gemini Body ({} parts)",
            gemini_body
                .get("contents")
                .and_then(|c| c.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        );
        let client_wants_stream = openai_req.stream;
        let force_stream_internally = !client_wants_stream;
        let list_response = client_wants_stream || force_stream_internally;
        let method = if list_response {
            "streamGenerateContent"
        } else {
            "generateContent"
        };
        let query_string = if list_response { Some("alt=sse") } else { None };

        let response = match upstream
            .call_v1_internal(
                method,
                &access_token,
                gemini_body,
                query_string,
                Some(account_id.as_str()),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_error = e.clone();
                debug!(
                    "Codex Request failed on attempt {}/{}: {}",
                    attempt + 1,
                    max_attempts,
                    e
                );
                continue;
            }
        };

        let status = response.status();
        if status.is_success() {
            token_manager.mark_account_success(&email);

            if list_response {
                use axum::body::Body;

                let gemini_stream = response.bytes_stream();

                if client_wants_stream {
                    let mut openai_stream = if is_codex_style {
                        use crate::proxy::mappers::openai::streaming::create_codex_sse_stream;
                        create_codex_sse_stream(
                            Box::pin(gemini_stream),
                            openai_req.model.clone(),
                            session_id,
                            message_count,
                        )
                    } else {
                        use crate::proxy::mappers::openai::streaming::create_legacy_sse_stream;
                        create_legacy_sse_stream(
                            Box::pin(gemini_stream),
                            openai_req.model.clone(),
                            session_id,
                            message_count,
                        )
                    };
                    let first_data_chunk = match crate::proxy::handlers::streaming::peek_first_data_chunk(
                        &mut openai_stream,
                        &crate::proxy::handlers::streaming::StreamPeekOptions {
                            timeout: Duration::from_secs(60),
                            context: "OpenAI:legacy",
                            skip_data_colon_heartbeat: true,
                            detect_error_events: true,
                            error_event_message: "Error event during peek",
                            stream_error_prefix: "Stream error during peek",
                            empty_stream_message: "Empty response stream",
                            timeout_message: "Timeout waiting for first data",
                        },
                    )
                    .await {
                        Ok(chunk) => chunk,
                        Err(err) => {
                            last_error = err;
                            continue;
                        }
                    };

                    let combined_stream = futures::stream::once(async move {
                        Ok::<Bytes, String>(first_data_chunk)
                    })
                    .chain(openai_stream);

                    return crate::proxy::handlers::streaming::build_sse_response(
                        Body::from_stream(combined_stream),
                        &email,
                        &mapped_model,
                        false,
                    )
                    .into_response();
                } else {
                    use crate::proxy::mappers::openai::streaming::create_openai_sse_stream;
                    let mut openai_stream = create_openai_sse_stream(
                        Box::pin(gemini_stream),
                        openai_req.model.clone(),
                        session_id,
                        message_count,
                    );
                    let first_data_chunk = match crate::proxy::handlers::streaming::peek_first_data_chunk(
                        &mut openai_stream,
                        &crate::proxy::handlers::streaming::StreamPeekOptions {
                            timeout: Duration::from_secs(60),
                            context: "OpenAI:internal",
                            skip_data_colon_heartbeat: true,
                            detect_error_events: true,
                            error_event_message: "Error event in internal stream",
                            stream_error_prefix: "Internal stream error",
                            empty_stream_message: "Empty internal stream",
                            timeout_message: "Timeout peek internal",
                        },
                    )
                    .await {
                        Ok(chunk) => chunk,
                        Err(err) => {
                            last_error = err;
                            continue;
                        }
                    };

                    let combined_stream = futures::stream::once(async move {
                        Ok::<Bytes, String>(first_data_chunk)
                    })
                    .chain(openai_stream);
                    use crate::proxy::mappers::openai::collector::collect_stream_to_json;
                    match collect_stream_to_json(Box::pin(combined_stream)).await {
                        Ok(chat_resp) => {
                            let choices = chat_resp.choices.iter().map(|c| {
                                json!({
                                    "text": match &c.message.content {
                                        Some(crate::proxy::mappers::openai::OpenAIContent::String(s)) => s.clone(),
                                        _ => "".to_string()
                                    },
                                    "index": c.index,
                                    "logprobs": null,
                                    "finish_reason": c.finish_reason
                                })
                            }).collect::<Vec<_>>();

                            let legacy_resp = json!({
                                "id": chat_resp.id,
                                "object": "text_completion",
                                "created": chat_resp.created,
                                "model": chat_resp.model,
                                "choices": choices,
                                "usage": chat_resp.usage
                            });

                            return crate::proxy::handlers::streaming::build_json_response_with_headers(
                                StatusCode::OK,
                                &legacy_resp,
                                Some(&email),
                                Some(&mapped_model),
                                &[],
                            );
                        }
                        Err(e) => {
                            return crate::proxy::handlers::errors::stream_collection_error_response(
                                &e.to_string(),
                            );
                        }
                    }
                }
            }

            let gemini_resp: Value = match response.json().await {
                Ok(json) => json,
                Err(e) => {
                    return crate::proxy::handlers::errors::parse_error_response(
                        &e.to_string(),
                        Some(mapped_model.as_str()),
                    );
                }
            };

            let chat_resp =
                transform_openai_response(&gemini_resp, Some(&session_id), message_count);
            let choices = chat_resp.choices.iter().map(|c| {
                json!({
                    "text": match &c.message.content {
                        Some(crate::proxy::mappers::openai::OpenAIContent::String(s)) => s.clone(),
                        _ => "".to_string()
                    },
                    "index": c.index,
                    "logprobs": null,
                    "finish_reason": c.finish_reason
                })
            }).collect::<Vec<_>>();

            let legacy_resp = json!({
                "id": chat_resp.id,
                "object": "text_completion",
                "created": chat_resp.created,
                "model": chat_resp.model,
                "choices": choices,
                "usage": chat_resp.usage
            });

            return crate::proxy::handlers::streaming::build_json_response_with_headers(
                StatusCode::OK,
                &legacy_resp,
                Some(&email),
                Some(&mapped_model),
                &[],
            );
        }
        let status_code = status.as_u16();
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| format!("HTTP {}", status_code));
        last_error = format!("HTTP {}: {}", status_code, error_text);

        tracing::error!(
            "[Codex-Upstream] Error Response {}: {}",
            status_code,
            error_text
        );
        if status_code == 429 || status_code == 529 || status_code == 503 || status_code == 500 {
            token_manager
                .mark_rate_limited_async(
                    &email,
                    status_code,
                    retry_after.as_deref(),
                    &error_text,
                    Some(&mapped_model),
                )
                .await;
        }
        let strategy = determine_retry_strategy(status_code, &error_text, false);

        if apply_retry_strategy(strategy, attempt, max_attempts, status_code, &trace_id).await {
            continue;
        } else {
            return crate::proxy::handlers::errors::text_error_response(
                status,
                &error_text,
                Some(&email),
                Some(&mapped_model),
            );
        }
    }
    crate::proxy::handlers::errors::accounts_exhausted_text_response(
        &last_error,
        last_email.as_deref(),
        Some(&mapped_model),
    )
}

pub async fn handle_list_models(State(state): State<ModelCatalogState>) -> impl IntoResponse {
    build_models_list_response(&state).await
}
