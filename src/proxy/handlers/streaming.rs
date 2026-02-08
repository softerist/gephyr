use axum::{body::Body, response::Response};

pub fn build_sse_response(
    body: Body,
    account_email: &str,
    mapped_model: &str,
    include_x_accel_buffering: bool,
) -> Response {
    let mut builder = Response::builder()
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .header("X-Account-Email", account_email)
        .header("X-Mapped-Model", mapped_model);

    if include_x_accel_buffering {
        builder = builder.header("X-Accel-Buffering", "no");
    }

    builder.body(body).unwrap()
}
