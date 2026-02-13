use axum::{extract::Request, middleware::Next, response::Response};

fn sanitize_request_header(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Keep these identifiers small to avoid accidental log/header abuse.
    if trimmed.len() > 128 {
        return None;
    }
    Some(trimmed.to_string())
}

pub async fn request_context_middleware(mut request: Request, next: Next) -> Response {
    let mut correlation_id = request
        .headers()
        .get("x-correlation-id")
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_request_header)
        .or_else(|| {
            request
                .headers()
                .get("x-trace-id")
                .and_then(|v| v.to_str().ok())
                .and_then(sanitize_request_header)
        });

    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_request_header)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    if correlation_id.is_none() {
        correlation_id = Some(request_id.clone());
    }

    // Ensure downstream components that read directly from headers (audit, monitor) can
    // access the resolved IDs, even when the client didn't supply them.
    if request.headers().get("x-request-id").is_none() {
        if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
            request.headers_mut().insert("x-request-id", value);
        }
    }
    if request.headers().get("x-correlation-id").is_none() {
        if let Some(correlation_id) = correlation_id.as_deref() {
            if let Ok(value) = axum::http::HeaderValue::from_str(correlation_id) {
                request.headers_mut().insert("x-correlation-id", value);
            }
        }
    }

    let ctx = crate::modules::system::request_context::RequestContext {
        correlation_id: correlation_id.clone(),
        request_id: Some(request_id.clone()),
    };

    let mut response = crate::modules::system::request_context::with_request_context(ctx, async move {
        next.run(request).await
    })
    .await;

    // Echo back for clients/scripts so a single request can be traced end-to-end.
    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    if let Some(correlation_id) = correlation_id.as_deref() {
        if let Ok(value) = axum::http::HeaderValue::from_str(correlation_id) {
            response.headers_mut().insert("x-correlation-id", value);
        }
    }

    response
}
