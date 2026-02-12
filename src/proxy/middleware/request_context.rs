use axum::{extract::Request, middleware::Next, response::Response};

pub async fn request_context_middleware(request: Request, next: Next) -> Response {
    let correlation_id = request
        .headers()
        .get("x-correlation-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let ctx = crate::modules::system::request_context::RequestContext {
        correlation_id,
        request_id,
    };

    crate::modules::system::request_context::with_request_context(ctx, async move {
        next.run(request).await
    })
    .await
}
