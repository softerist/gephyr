use axum::{
    body::Body,
    http::StatusCode,
    response::Response,
};
use serde::Serialize;

pub fn build_sse_response(
    body: Body,
    account_email: &str,
    mapped_model: &str,
    include_x_accel_buffering: bool,
) -> Response {
    build_sse_response_with_headers(
        body,
        Some(account_email),
        Some(mapped_model),
        include_x_accel_buffering,
        &[],
    )
}

pub fn build_sse_response_with_headers(
    body: Body,
    account_email: Option<&str>,
    mapped_model: Option<&str>,
    include_x_accel_buffering: bool,
    extra_headers: &[(&str, &str)],
) -> Response {
    let mut builder = Response::builder()
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive");

    if let Some(email) = account_email {
        builder = builder.header("X-Account-Email", email);
    }
    if let Some(model) = mapped_model {
        builder = builder.header("X-Mapped-Model", model);
    }

    if include_x_accel_buffering {
        builder = builder.header("X-Accel-Buffering", "no");
    }
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }

    builder.body(body).unwrap()
}

pub fn build_json_response_with_headers<T: Serialize>(
    status: StatusCode,
    payload: &T,
    account_email: Option<&str>,
    mapped_model: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json");

    if let Some(email) = account_email {
        builder = builder.header("X-Account-Email", email);
    }
    if let Some(model) = mapped_model {
        builder = builder.header("X-Mapped-Model", model);
    }
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }

    builder
        .body(Body::from(serde_json::to_string(payload).unwrap()))
        .unwrap()
}
