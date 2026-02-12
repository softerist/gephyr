use std::future::Future;

#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub correlation_id: Option<String>,
    pub request_id: Option<String>,
}

tokio::task_local! {
    static CURRENT: RequestContext;
}

pub async fn with_request_context<F, T>(ctx: RequestContext, fut: F) -> T
where
    F: Future<Output = T>,
{
    CURRENT.scope(ctx, fut).await
}

pub fn try_get() -> Option<RequestContext> {
    CURRENT.try_with(|ctx| ctx.clone()).ok()
}
