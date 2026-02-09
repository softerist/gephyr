use axum::{body::Body, http::StatusCode, response::Response};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde::Serialize;
use std::pin::Pin;
use std::time::Duration;

pub type BytesResultStream = Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>>;

pub struct StreamPeekOptions<'a> {
    pub timeout: Duration,
    pub context: &'a str,
    pub fail_on_empty_chunk: bool,
    pub empty_chunk_message: &'a str,
    pub skip_data_colon_heartbeat: bool,
    pub detect_error_events: bool,
    pub error_event_message: &'a str,
    pub stream_error_prefix: &'a str,
    pub empty_stream_message: &'a str,
    pub timeout_message: &'a str,
}

pub async fn peek_first_data_chunk(
    stream: &mut BytesResultStream,
    options: &StreamPeekOptions<'_>,
) -> Result<Bytes, String> {
    loop {
        match tokio::time::timeout(options.timeout, stream.next()).await {
            Ok(Some(Ok(bytes))) => {
                if bytes.is_empty() {
                    if options.fail_on_empty_chunk {
                        tracing::warn!(
                            "[{}] Empty chunk during peek (configured as failure)",
                            options.context
                        );
                        return Err(options.empty_chunk_message.to_string());
                    }
                    continue;
                }

                let text = String::from_utf8_lossy(&bytes);
                let is_heartbeat = text.trim().starts_with(":")
                    || (options.skip_data_colon_heartbeat && text.trim().starts_with("data: :"));
                if is_heartbeat {
                    tracing::debug!("[{}] Skipping peek heartbeat", options.context);
                    continue;
                }

                if options.detect_error_events && text.contains("\"error\"") {
                    tracing::warn!("[{}] Error detected during peek", options.context);
                    return Err(options.error_event_message.to_string());
                }

                return Ok(bytes);
            }
            Ok(Some(Err(e))) => {
                tracing::warn!("[{}] Stream error during peek: {}", options.context, e);
                return Err(format!("{}: {}", options.stream_error_prefix, e));
            }
            Ok(None) => {
                tracing::warn!("[{}] Stream ended during peek", options.context);
                return Err(options.empty_stream_message.to_string());
            }
            Err(_) => {
                tracing::warn!("[{}] Timeout waiting for first data", options.context);
                return Err(options.timeout_message.to_string());
            }
        }
    }
}

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

pub fn attach_guard_to_stream<S, T, G>(
    stream: S,
    guard: Option<G>,
) -> Pin<Box<dyn Stream<Item = T> + Send>>
where
    S: Stream<Item = T> + Send + 'static,
    T: Send + 'static,
    G: Send + 'static,
{
    Box::pin(async_stream::stream! {
        let _guard = guard;
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            yield item;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::attach_guard_to_stream;
    use futures::StreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct DropFlag(Arc<AtomicUsize>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn test_attach_guard_to_stream_keeps_guard_alive_until_stream_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        let guard = DropFlag(drops.clone());
        let stream = futures::stream::iter(vec![1u8, 2u8]);
        let mut wrapped = attach_guard_to_stream(stream, Some(guard));

        let first = wrapped.next().await;
        assert_eq!(first, Some(1u8));
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        drop(wrapped);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
