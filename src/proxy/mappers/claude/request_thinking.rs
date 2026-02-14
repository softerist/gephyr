use crate::proxy::mappers::claude::models::*;
use serde_json::{json, Value};

pub(super) const MIN_SIGNATURE_LENGTH: usize = 50;

pub(super) fn should_disable_thinking_due_to_history(messages: &[Message]) -> bool {
    for msg in messages.iter().rev() {
        if msg.role == "assistant" {
            if let MessageContent::Array(blocks) = &msg.content {
                let has_tool_use = blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::ToolUse { .. }));
                let has_thinking = blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::Thinking { .. }));
                if has_tool_use && !has_thinking {
                    tracing::info!("[Thinking-Mode] Detected ToolUse without Thinking in history. Requesting disable.");
                    return true;
                }
            }
            return false;
        }
    }
    false
}

pub(super) fn should_enable_thinking_by_default(model: &str) -> bool {
    let should_enable = crate::proxy::common::model_mapping::should_auto_enable_thinking(model);
    if should_enable {
        tracing::debug!(
            "[Thinking-Mode] Auto-enabling thinking for model: {}",
            model
        );
    }
    should_enable
}

pub(super) fn has_valid_signature_for_function_calls(
    messages: &[Message],
    global_sig: &Option<String>,
    session_id: &str,
) -> bool {
    if let Some(sig) = global_sig {
        if sig.len() >= MIN_SIGNATURE_LENGTH {
            tracing::debug!(
                "[Signature-Check] Found valid signature in global store (len: {})",
                sig.len()
            );
            return true;
        }
    }
    if let Some(sig) = crate::proxy::SignatureCache::global().get_session_signature(session_id) {
        if sig.len() >= MIN_SIGNATURE_LENGTH {
            tracing::info!(
                "[Signature-Check] Found valid signature in SESSION cache (session: {}, len: {})",
                session_id,
                sig.len()
            );
            return true;
        }
    }
    for msg in messages.iter().rev() {
        if msg.role == "assistant" {
            if let MessageContent::Array(blocks) = &msg.content {
                for block in blocks {
                    if let ContentBlock::Thinking {
                        signature: Some(sig),
                        ..
                    } = block
                    {
                        if sig.len() >= MIN_SIGNATURE_LENGTH {
                            tracing::debug!(
                                "[Signature-Check] Found valid signature in message history (len: {})",
                                sig.len()
                            );
                            return true;
                        }
                    }
                }
            }
        }
    }

    tracing::warn!(
        "[Signature-Check] No valid signature found (session: {}, checked: global store, session cache, message history)",
        session_id
    );
    false
}

pub(super) fn build_system_instruction(
    system: &Option<SystemPrompt>,
    has_mcp_tools: bool,
) -> Option<Value> {
    let mut parts = Vec::new();
    let antigravity_identity = "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.\n\
    You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.\n\
    **Absolute paths only**\n\
    **Proactiveness**";
    let mut user_has_antigravity = false;
    if let Some(sys) = system {
        match sys {
            SystemPrompt::String(text) => {
                if text.contains("You are Antigravity") {
                    user_has_antigravity = true;
                }
            }
            SystemPrompt::Array(blocks) => {
                for block in blocks {
                    if block.block_type == "text" && block.text.contains("You are Antigravity") {
                        user_has_antigravity = true;
                        break;
                    }
                }
            }
        }
    }
    if !user_has_antigravity {
        parts.push(json!({"text": antigravity_identity}));
    }
    if let Some(sys) = system {
        match sys {
            SystemPrompt::String(text) => {
                parts.push(json!({"text": text}));
            }
            SystemPrompt::Array(blocks) => {
                for block in blocks {
                    if block.block_type == "text" {
                        parts.push(json!({"text": block.text}));
                    }
                }
            }
        }
    }
    if has_mcp_tools {
        let mcp_xml_prompt = "\n\
        ==== MCP XML Tool Calling Protocol (Workaround) ====\n\
        When you need to call an MCP tool with a name starting with `mcp__`:\n\
        1) Try XML format calling first: output `<mcp__tool_name>{\"arg\":\"value\"}</mcp__tool_name>`.\n\
        2) You must directly output the XML block without markdown wrapping, and the content should be JSON formatted input parameters.\n\
        3) This method has higher connectivity and fault tolerance, suitable for large result return scenarios.\n\
        ===========================================";
        parts.push(json!({"text": mcp_xml_prompt}));
    }
    if !user_has_antigravity {
        parts.push(json!({"text": "\n--- [SYSTEM_PROMPT_END] ---"}));
    }

    Some(json!({
        "role": "user",
        "parts": parts
    }))
}