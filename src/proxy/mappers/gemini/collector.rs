use bytes::Bytes;
use futures::StreamExt;
use serde_json::{json, Value};
use tracing::debug;

use crate::proxy::SignatureCache;
pub async fn collect_stream_to_json<S, E>(mut stream: S, session_id: &str) -> Result<Value, String>
where
    S: futures::Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    let mut collected_response = json!({
        "candidates": [
            {
                "content": {
                    "parts": [],
                    "role": "model"
                },
                "finishReason": "STOP",
                "index": 0
            }
        ]
    });

    let mut content_parts: Vec<Value> = Vec::new();
    let mut usage_metadata: Option<Value> = None;
    let mut finish_reason: Option<String> = None;

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| format!("Stream error: {}", e))?;
        let text = std::str::from_utf8(&chunk).unwrap_or("");

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("data: ") {
                let json_part = line.trim_start_matches("data: ").trim();
                if json_part == "[DONE]" {
                    continue;
                }

                if let Ok(mut json) = serde_json::from_str::<Value>(json_part) {
                    let actual_data =
                        if let Some(inner) = json.get_mut("response").map(|v| v.take()) {
                            inner
                        } else {
                            json
                        };
                    if let Some(usage) = actual_data.get("usageMetadata") {
                        usage_metadata = Some(usage.clone());
                    }
                    if let Some(candidates) =
                        actual_data.get("candidates").and_then(|c| c.as_array())
                    {
                        if let Some(candidate) = candidates.first() {
                            if let Some(fr) = candidate.get("finishReason").and_then(|v| v.as_str())
                            {
                                finish_reason = Some(fr.to_string());
                            }

                            if let Some(parts) = candidate
                                .get("content")
                                .and_then(|c| c.get("parts"))
                                .and_then(|p| p.as_array())
                            {
                                for part in parts {
                                    if let Some(sig) =
                                        part.get("thoughtSignature").and_then(|s| s.as_str())
                                    {
                                        SignatureCache::global().cache_session_signature(
                                            session_id,
                                            sig.to_string(),
                                            1,
                                        );
                                        debug!("[Gemini-AutoConverter] Cached signature (len: {}) for session: {}", sig.len(), session_id);
                                    }

                                    if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                                        if let Some(last) = content_parts.last_mut() {
                                            if last.get("text").is_some()
                                                && part.get("thought").is_none()
                                                && last.get("thought").is_none()
                                            {
                                                if let Some(last_text) =
                                                    last.get_mut("text").and_then(|v| v.as_str())
                                                {
                                                    let new_text = format!("{}{}", last_text, text);
                                                    *last = json!({"text": new_text});
                                                    continue;
                                                }
                                            }
                                        }
                                        content_parts.push(part.clone());
                                    } else {
                                        content_parts.push(part.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    collected_response["candidates"][0]["content"]["parts"] = json!(content_parts);
    if let Some(fr) = finish_reason {
        collected_response["candidates"][0]["finishReason"] = json!(fr);
    }
    if let Some(usage) = usage_metadata {
        collected_response["usageMetadata"] = usage;
    }

    Ok(collected_response)
}