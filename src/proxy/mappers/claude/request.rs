use super::models::*;
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
#[path = "request_builder.rs"]
mod builder;
#[path = "request_content.rs"]
mod content;
#[path = "request_context.rs"]
mod context;
#[path = "request_generation.rs"]
mod generation;
#[path = "request_preprocess.rs"]
mod preprocess;
#[path = "request_thinking.rs"]
mod thinking;
#[path = "request_transform.rs"]
mod transform;

pub fn clean_cache_control_from_messages(messages: &mut [Message]) {
    preprocess::clean_cache_control_from_messages(messages);
}

fn sort_thinking_blocks_first(messages: &mut [Message]) {
    preprocess::sort_thinking_blocks_first(messages);
}

pub fn merge_consecutive_messages(messages: &mut Vec<Message>) {
    preprocess::merge_consecutive_messages(messages);
}

pub fn transform_claude_request_in(
    claude_req: &ClaudeRequest,
    project_id: &str,
    is_retry: bool,
) -> Result<Value, String> {
    transform::transform_claude_request_in(claude_req, project_id, is_retry)
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;