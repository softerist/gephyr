use crate::proxy::mappers::claude::models::*;
use serde_json::Value;

pub(super) fn transform_claude_request_in(
    claude_req: &ClaudeRequest,
    project_id: &str,
    is_retry: bool,
) -> Result<Value, String> {
    let ctx = super::context::prepare_request_context(claude_req);
    super::builder::build_request_body(&ctx, project_id, is_retry)
}
