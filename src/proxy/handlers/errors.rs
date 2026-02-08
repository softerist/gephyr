use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

pub fn claude_invalid_request_response(message: impl Into<String>, suggestion: Option<String>) -> Response {
    let mut body = json!({
        "type": "error",
        "error": {
            "type": "invalid_request_error",
            "message": message.into()
        }
    });

    if let Some(s) = suggestion {
        if let Some(err) = body.get_mut("error").and_then(Value::as_object_mut) {
            err.insert("suggestion".to_string(), json!(s));
        }
    }

    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

pub fn claude_prompt_too_long_response(email: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [("X-Account-Email", email)],
        Json(json!({
            "id": "err_prompt_too_long",
            "type": "error",
            "error": {
                "type": "invalid_request_error",
                "message": "Prompt is too long (server-side context limit reached).",
                "suggestion": format!(
                    "Please: 1) Executive '/compact' in Claude Code 2) Reduce conversation history 3) Switch to {} (2M context limit)",
                    crate::proxy::common::model_mapping::MODEL_GEMINI_3_PRO
                )
            }
        })),
    )
        .into_response()
}

pub fn claude_retry_exhausted_response(
    max_attempts: usize,
    last_status: StatusCode,
    last_error: &str,
    last_email: Option<&str>,
    mapped_model: Option<&str>,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(email) = last_email {
        if let Ok(v) = HeaderValue::from_str(email) {
            headers.insert("X-Account-Email", v);
        }
    }
    if let Some(model) = mapped_model {
        if let Ok(v) = HeaderValue::from_str(model) {
            headers.insert("X-Mapped-Model", v);
        }
    }

    let error_type = match last_status.as_u16() {
        400 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        429 => "rate_limit_error",
        529 => "overloaded_error",
        _ => "api_error",
    };
    let response_status = if last_status.as_u16() == 403 {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        last_status
    };

    (
        response_status,
        headers,
        Json(json!({
            "type": "error",
            "error": {
                "id": "err_retry_exhausted",
                "type": error_type,
                "message": format!(
                    "All {} attempts failed. Last status: {}. Error: {}",
                    max_attempts, last_status, last_error
                )
            }
        })),
    )
        .into_response()
}

pub fn accounts_exhausted_text_response(
    last_error: &str,
    last_email: Option<&str>,
    mapped_model: Option<&str>,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(email) = last_email {
        if let Ok(v) = HeaderValue::from_str(email) {
            headers.insert("X-Account-Email", v);
        }
    }
    if let Some(model) = mapped_model {
        if let Ok(v) = HeaderValue::from_str(model) {
            headers.insert("X-Mapped-Model", v);
        }
    }

    (
        StatusCode::TOO_MANY_REQUESTS,
        headers,
        format!("All accounts exhausted. Last error: {}", last_error),
    )
        .into_response()
}

pub fn stream_collection_error_response(error: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Stream collection error: {}", error),
    )
        .into_response()
}

pub fn parse_error_response(error: &str, mapped_model: Option<&str>) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(model) = mapped_model {
        if let Ok(v) = HeaderValue::from_str(model) {
            headers.insert("X-Mapped-Model", v);
        }
    }
    (
        StatusCode::BAD_GATEWAY,
        headers,
        format!("Parse error: {}", error),
    )
        .into_response()
}

pub fn openai_upstream_error_response(
    status: StatusCode,
    error_text: &str,
    account_email: Option<&str>,
    mapped_model: Option<&str>,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(email) = account_email {
        if let Ok(v) = HeaderValue::from_str(email) {
            headers.insert("X-Account-Email", v);
        }
    }
    if let Some(model) = mapped_model {
        if let Ok(v) = HeaderValue::from_str(model) {
            headers.insert("X-Mapped-Model", v);
        }
    }

    (
        status,
        headers,
        Json(json!({
            "error": {
                "message": error_text,
                "type": "upstream_error",
                "code": status.as_u16()
            }
        })),
    )
        .into_response()
}

pub fn gemini_upstream_error_response(
    status: StatusCode,
    error_text: &str,
    account_email: Option<&str>,
    mapped_model: Option<&str>,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(email) = account_email {
        if let Ok(v) = HeaderValue::from_str(email) {
            headers.insert("X-Account-Email", v);
        }
    }
    if let Some(model) = mapped_model {
        if let Ok(v) = HeaderValue::from_str(model) {
            headers.insert("X-Mapped-Model", v);
        }
    }

    (
        status,
        headers,
        Json(json!({
            "error": {
                "code": status.as_u16(),
                "message": error_text,
                "status": "UPSTREAM_ERROR"
            }
        })),
    )
        .into_response()
}
