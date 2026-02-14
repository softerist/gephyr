use axum::{
    extract::State,
    extract::{Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{json, Value};
use tracing::{debug, error, info};

use crate::proxy::common::client_adapter::CLIENT_ADAPTERS;
use crate::proxy::debug_logger;
use crate::proxy::handlers::retry::{
    apply_retry_strategy, determine_retry_strategy, should_rotate_account,
};
use crate::proxy::mappers::gemini::{unwrap_response, wrap_request};
use crate::proxy::session_manager::SessionManager;
use crate::proxy::state::{ModelCatalogState, OpenAIHandlerState};
use axum::http::HeaderMap;

const MAX_RETRY_ATTEMPTS: usize = 3;
pub async fn handle_generate(
    State(state): State<OpenAIHandlerState>,
    Path(model_action): Path<String>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (model_name, method) = if let Some((m, action)) = model_action.rsplit_once(':') {
        (m.to_string(), action.to_string())
    } else {
        (model_action, "generateContent".to_string())
    };

    crate::modules::system::logger::log_info(&format!(
        "Received Gemini request: {}/{}",
        model_name, method
    ));
    let trace_id = format!("req_{}", chrono::Utc::now().timestamp_subsec_millis());
    let debug_cfg = state.debug_logging.read().await.clone();
    let client_adapter = CLIENT_ADAPTERS
        .iter()
        .find(|a| a.matches(&headers))
        .cloned();
    if client_adapter.is_some() {
        debug!("[{}] Client Adapter detected", trace_id);
    }
    if method != "generateContent" && method != "streamGenerateContent" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Unsupported method: {}", method),
        ));
    }
    if debug_logger::is_enabled(&debug_cfg) {
        let original_payload = json!({
            "kind": "original_request",
            "protocol": "gemini",
            "trace_id": trace_id,
            "original_model": model_name,
            "method": method,
            "request": body.clone(),
        });
        debug_logger::write_debug_payload(
            &debug_cfg,
            Some(&trace_id),
            "original_request",
            &original_payload,
        )
        .await;
    }
    let client_wants_stream = method == "streamGenerateContent";
    let force_stream_internally = !client_wants_stream;
    let is_stream = client_wants_stream || force_stream_internally;

    let upstream = state.upstream.clone();
    let token_manager = state.token_manager;
    let pool_size = token_manager.len();
    let base_max_attempts = MAX_RETRY_ATTEMPTS.min(pool_size).max(1);
    let max_attempts = token_manager
        .effective_retry_attempts(base_max_attempts)
        .await;

    let mut last_error = String::new();
    let mut last_email: Option<String> = None;

    for attempt in 0..max_attempts {
        let mapped_model = crate::proxy::common::model_mapping::resolve_model_route(
            &model_name,
            &*state.custom_mapping.read().await,
        );
        let tools_val: Option<Vec<Value>> =
            body.get("tools").and_then(|t| t.as_array()).map(|arr| {
                let mut flattened = Vec::new();
                for tool_entry in arr {
                    if let Some(decls) = tool_entry
                        .get("functionDeclarations")
                        .and_then(|v| v.as_array())
                    {
                        flattened.extend(decls.iter().cloned());
                    } else {
                        flattened.push(tool_entry.clone());
                    }
                }
                flattened
            });

        let config = crate::proxy::mappers::common_utils::resolve_request_config(
            &model_name,
            &mapped_model,
            &tools_val,
            None,
            None,
            Some(&body),
        );
        let session_id = SessionManager::extract_gemini_session_id_with_overrides(
            &body,
            &model_name,
            Some(&headers),
        );
        let (access_token, project_id, email, account_id, _wait_ms) = match token_manager
            .get_token(
                &config.request_type,
                attempt > 0,
                Some(&session_id),
                &config.final_model,
            )
            .await
        {
            Ok(t) => t,
            Err(e) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Token error: {}", e),
                ));
            }
        };
        let compliance_guard = match token_manager
            .try_acquire_compliance_guard(&account_id)
            .await
        {
            Ok(guard) => guard,
            Err(e) => {
                last_error = e;
                continue;
            }
        };

        last_email = Some(email.clone());
        info!("✓ Using account: {} (type: {})", email, config.request_type);
        let wrapped_body = wrap_request(&body, &project_id, &mapped_model, Some(&session_id));

        if debug_logger::is_enabled(&debug_cfg) {
            let payload = json!({
                "kind": "v1internal_request",
                "protocol": "gemini",
                "trace_id": trace_id,
                "original_model": model_name,
                "mapped_model": mapped_model,
                "request_type": config.request_type,
                "attempt": attempt,
                "v1internal_request": wrapped_body.clone(),
            });
            debug_logger::write_debug_payload(
                &debug_cfg,
                Some(&trace_id),
                "v1internal_request",
                &payload,
            )
            .await;
        }
        let query_string = if is_stream { Some("alt=sse") } else { None };
        let upstream_method = if is_stream {
            "streamGenerateContent"
        } else {
            "generateContent"
        };
        let mut extra_headers = std::collections::HashMap::new();
        if mapped_model.to_lowercase().contains("claude") {
            extra_headers.insert("anthropic-beta".to_string(), "claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14".to_string());
            tracing::debug!(
                "[Gemini] Injected Anthropic beta headers for Claude model: {}",
                mapped_model
            );
        }

        let response = match upstream
            .call_v1_internal_with_headers(
                upstream_method,
                &access_token,
                wrapped_body,
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
                    "Gemini Request failed on attempt {}/{}: {}",
                    attempt + 1,
                    max_attempts,
                    e
                );
                continue;
            }
        };

        let status = response.status();
        if status.is_success() {
            if is_stream {
                use axum::body::Body;
                use bytes::{Bytes, BytesMut};
                use futures::StreamExt;

                let meta = json!({
                    "protocol": "gemini",
                    "trace_id": trace_id,
                    "original_model": model_name,
                    "mapped_model": mapped_model,
                    "request_type": config.request_type,
                    "attempt": attempt,
                    "status": status.as_u16(),
                });
                let mut response_stream: crate::proxy::handlers::streaming::BytesResultStream =
                    Box::pin(
                        debug_logger::wrap_reqwest_stream_with_debug(
                            Box::pin(response.bytes_stream()),
                            debug_cfg.clone(),
                            trace_id.clone(),
                            "upstream_response",
                            meta,
                        )
                        .map(|r| r.map_err(|e| e.to_string())),
                    );
                let mut buffer = BytesMut::new();
                let s_id = session_id.clone();
                let first_chunk = match crate::proxy::handlers::streaming::peek_first_data_chunk(
                    &mut response_stream,
                    &crate::proxy::handlers::streaming::StreamPeekOptions {
                        timeout: std::time::Duration::from_secs(30),
                        context: "Gemini:stream",
                        fail_on_empty_chunk: true,
                        empty_chunk_message: "Empty first chunk received",
                        skip_data_colon_heartbeat: false,
                        detect_error_events: false,
                        error_event_message: "Error event during peek",
                        stream_error_prefix: "Stream error",
                        empty_stream_message: "Empty response",
                        timeout_message: "Timeout",
                    },
                )
                .await
                {
                    Ok(chunk) => chunk,
                    Err(err) => {
                        last_error = err;
                        continue;
                    }
                };

                let s_id_for_stream = s_id.clone();
                let model_name_for_stream = mapped_model.clone();
                let stream = async_stream::stream! {
                    let mut first_data = Some(first_chunk);
                    loop {
                        let item = if let Some(fd) = first_data.take() {
                            Some(Ok(fd))
                        } else {
                            response_stream.next().await
                        };

                        let bytes = match item {
                            Some(Ok(b)) => b,
                            Some(Err(e)) => {
                                error!("[Gemini-SSE] Connection error: {}", e);
                                yield Err(format!("Stream error: {}", e));
                                break;
                            }
                            None => break,
                        };

                        debug!("[Gemini-SSE] Received chunk: {} bytes", bytes.len());
                        buffer.extend_from_slice(&bytes);
                        while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                            let line_raw = buffer.split_to(pos + 1);
                            if let Ok(line_str) = std::str::from_utf8(&line_raw) {
                                let line = line_str.trim();
                                if line.is_empty() { continue; }

                                if line.starts_with("data: ") {
                                    let json_part = line.trim_start_matches("data: ").trim();
                                    if json_part == "[DONE]" {
                                        yield Ok::<Bytes, String>(Bytes::from("data: [DONE]\n\n"));
                                        continue;
                                    }

                                    match serde_json::from_str::<Value>(json_part) {
                                        Ok(mut json) => {
                                            let inner_val = if json.get("response").is_some() {
                                                json.get("response")
                                            } else {
                                                Some(&json)
                                            };

                                            if let Some(resp) = inner_val {
                                                if let Some(candidates) = resp.get("candidates").and_then(|c| c.as_array()) {
                                                    for cand in candidates {
                                                        if let Some(parts) = cand.get("content").and_then(|c| c.get("parts")).and_then(|p| p.as_array()) {
                                                            for part in parts {
                                                                if let Some(sig) = part.get("thoughtSignature").and_then(|s| s.as_str()) {
                                                                    crate::proxy::SignatureCache::global()
                                                                        .cache_session_signature(&s_id_for_stream, sig.to_string(), 1);
                                                                    debug!("[Gemini-SSE] Cached signature (len: {}) for session: {}", sig.len(), s_id_for_stream);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            crate::proxy::mappers::gemini::wrapper::inject_ids_to_response(&mut json, &model_name_for_stream);
                                            if let Some(inner) = json.get_mut("response").map(|v| v.take()) {
                                                let new_line = format!("data: {}\n\n", serde_json::to_string(&inner).unwrap_or_default());
                                                yield Ok::<Bytes, String>(Bytes::from(new_line));
                                            } else {
                                                yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&json).unwrap_or_default())));
                                            }
                                        }
                                        Err(e) => {
                                            debug!("[Gemini-SSE] JSON parse error: {}, passing raw line", e);
                                            yield Ok::<Bytes, String>(Bytes::from(format!("{}\n\n", line)));
                                        }
                                    }
                                } else {
                                    yield Ok::<Bytes, String>(Bytes::from(format!("{}\n\n", line)));
                                }
                            } else {
                                debug!("[Gemini-SSE] Non-UTF8 line encountered");
                                yield Ok::<Bytes, String>(line_raw.freeze());
                            }
                        }
                    }
                };

                if client_wants_stream {
                    let guarded_stream = crate::proxy::handlers::streaming::attach_guard_to_stream(
                        stream,
                        compliance_guard,
                    );
                    let body = Body::from_stream(guarded_stream);
                    return Ok(crate::proxy::handlers::streaming::build_sse_response(
                        body,
                        &email,
                        &mapped_model,
                        true,
                    )
                    .into_response());
                } else {
                    use crate::proxy::mappers::gemini::collector::collect_stream_to_json;
                    match collect_stream_to_json(Box::pin(stream), &s_id).await {
                        Ok(gemini_resp) => {
                            info!(
                                "[{}] ✓ Stream collected and converted to JSON (Gemini)",
                                session_id
                            );
                            let unwrapped = unwrap_response(&gemini_resp);
                            return Ok(
                                crate::proxy::handlers::streaming::build_json_response_with_headers(
                                    StatusCode::OK,
                                    &unwrapped,
                                    Some(&email),
                                    Some(&mapped_model),
                                    &[],
                                )
                                .into_response(),
                            );
                        }
                        Err(e) => {
                            error!("Stream collection error: {}", e);
                            return Ok(
                                crate::proxy::handlers::errors::stream_collection_error_response(
                                    &e.to_string(),
                                ),
                            );
                        }
                    }
                }
            }

            let mut gemini_resp: Value = response
                .json()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Parse error: {}", e)))?;
            crate::proxy::mappers::gemini::wrapper::inject_ids_to_response(
                &mut gemini_resp,
                &mapped_model,
            );
            let inner_val = if gemini_resp.get("response").is_some() {
                gemini_resp.get("response")
            } else {
                Some(&gemini_resp)
            };

            if let Some(resp) = inner_val {
                if let Some(candidates) = resp.get("candidates").and_then(|c| c.as_array()) {
                    for cand in candidates {
                        if let Some(parts) = cand
                            .get("content")
                            .and_then(|c| c.get("parts"))
                            .and_then(|p| p.as_array())
                        {
                            for part in parts {
                                if let Some(sig) =
                                    part.get("thoughtSignature").and_then(|s| s.as_str())
                                {
                                    crate::proxy::SignatureCache::global().cache_session_signature(
                                        &session_id,
                                        sig.to_string(),
                                        1,
                                    );
                                    debug!("[Gemini-Response] Cached signature (len: {}) for session: {}", sig.len(), session_id);
                                }
                            }
                        }
                    }
                }
            }

            let unwrapped = unwrap_response(&gemini_resp);
            return Ok(
                crate::proxy::handlers::streaming::build_json_response_with_headers(
                    StatusCode::OK,
                    &unwrapped,
                    Some(&email),
                    Some(&mapped_model),
                    &[],
                )
                .into_response(),
            );
        }
        let status_code = status.as_u16();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| format!("HTTP {}", status_code));
        last_error = format!("HTTP {}: {}", status_code, error_text);
        token_manager
            .mark_compliance_risk_signal(&account_id, status_code)
            .await;
        if debug_logger::is_enabled(&debug_cfg) {
            let payload = json!({
                "kind": "upstream_response_error",
                "protocol": "gemini",
                "trace_id": trace_id,
                "original_model": model_name,
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
        let trace_id = format!("gemini_{}", session_id);
        if apply_retry_strategy(strategy, attempt, max_attempts, status_code, &trace_id).await {
            if let Some(adapter) = &client_adapter {
                if adapter.let_it_crash() && attempt > 0 {
                    tracing::warn!(
                        "[Gemini] let_it_crash active: Aborting retries after attempt {}",
                        attempt
                    );
                    break;
                }
            }
            if !should_rotate_account(status_code) {
                debug!(
                    "[{}] Keeping same account for status {} (Gemini server-side issue)",
                    trace_id, status_code
                );
            }
            continue;
        }
        if status_code == 400
            && (error_text.contains("Invalid `signature`")
                || error_text.contains("thinking.signature")
                || error_text.contains("Invalid signature")
                || error_text.contains("Corrupted thought signature"))
        {
            tracing::warn!(
                "[Gemini] Signature error detected on account {}, retrying without thinking",
                email
            );
            if let Some(contents) = body.get_mut("contents").and_then(|v| v.as_array_mut()) {
                if let Some(last_content) = contents.last_mut() {
                    if let Some(parts) =
                        last_content.get_mut("parts").and_then(|v| v.as_array_mut())
                    {
                        parts.push(json!({
                            "text": "\n\n[System Recovery] Your previous output contained an invalid signature. Please regenerate the response without the corrupted signature block."
                        }));
                        tracing::debug!("[Gemini] Appended repair prompt to last content");
                    }
                }
            }

            continue;
        }
        error!(
            "Gemini Upstream non-retryable error {}: {}",
            status_code, error_text
        );
        return Ok(
            crate::proxy::handlers::errors::gemini_upstream_error_response(
                status,
                &error_text,
                Some(&email),
                Some(&mapped_model),
            ),
        );
    }

    Ok(
        crate::proxy::handlers::errors::accounts_exhausted_text_response(
            &last_error,
            last_email.as_deref(),
            None,
        ),
    )
}

pub async fn handle_list_models(
    State(state): State<ModelCatalogState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use crate::proxy::common::model_mapping::get_all_dynamic_models;
    let model_ids = get_all_dynamic_models(&state.custom_mapping).await;
    let models: Vec<_> = model_ids
        .into_iter()
        .map(|id| {
            json!({
                "name": format!("models/{}", id),
                "version": "001",
                "displayName": id.clone(),
                "description": "",
                "inputTokenLimit": 128000,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "countTokens"],
                "temperature": 1.0,
                "topP": 0.95,
                "topK": 64
            })
        })
        .collect();

    Ok(Json(json!({ "models": models })))
}

pub async fn handle_get_model(Path(model_name): Path<String>) -> impl IntoResponse {
    Json(json!({
        "name": format!("models/{}", model_name),
        "displayName": model_name
    }))
}

pub async fn handle_count_tokens(
    State(state): State<OpenAIHandlerState>,
    Path(_model_name): Path<String>,
    Json(_body): Json<Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let model_group = "gemini";
    let (_access_token, _project_id, _, _, _wait_ms) = state
        .token_manager
        .get_token(model_group, false, None, "gemini")
        .await
        .map_err(|e| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Token error: {}", e),
            )
        })?;

    Ok(Json(json!({"totalTokens": 0})))
}