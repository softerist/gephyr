use super::models::{ContentBlock, Message, MessageContent};
use crate::proxy::SignatureCache;
use tracing::{debug, info, warn};

pub const MIN_SIGNATURE_LENGTH: usize = 50;

#[derive(Debug, Default)]
pub struct ConversationState {
    pub in_tool_loop: bool,
    pub interrupted_tool: bool,
    pub last_assistant_idx: Option<usize>,
}
pub fn analyze_conversation_state(messages: &[Message]) -> ConversationState {
    let mut state = ConversationState::default();

    if messages.is_empty() {
        return state;
    }
    for (i, msg) in messages.iter().enumerate().rev() {
        if msg.role == "assistant" {
            state.last_assistant_idx = Some(i);
            break;
        }
    }
    let has_tool_use = if let Some(idx) = state.last_assistant_idx {
        if let Some(msg) = messages.get(idx) {
            if let MessageContent::Array(blocks) = &msg.content {
                blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::ToolUse { .. }))
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    if !has_tool_use {
        return state;
    }
    if let Some(last_msg) = messages.last() {
        if last_msg.role == "user" {
            if let MessageContent::Array(blocks) = &last_msg.content {
                if blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::ToolResult { .. }))
                {
                    state.in_tool_loop = true;
                    debug!(
                        "[Thinking-Recovery] Active tool loop detected (last msg is ToolResult)."
                    );
                } else {
                    state.interrupted_tool = true;
                    debug!(
                        "[Thinking-Recovery] Interrupted tool detected (last msg is Text user)."
                    );
                }
            } else if let MessageContent::String(_) = &last_msg.content {
                state.interrupted_tool = true;
                debug!("[Thinking-Recovery] Interrupted tool detected (last msg is String user).");
            }
        }
    }

    state
}
pub fn close_tool_loop_for_thinking(messages: &mut Vec<Message>) {
    let state = analyze_conversation_state(messages);

    if !state.in_tool_loop && !state.interrupted_tool {
        return;
    }
    let mut has_valid_thinking = false;
    if let Some(idx) = state.last_assistant_idx {
        if let Some(msg) = messages.get(idx) {
            if let MessageContent::Array(blocks) = &msg.content {
                for block in blocks {
                    if let ContentBlock::Thinking {
                        thinking,
                        signature,
                        ..
                    } = block
                    {
                        if !thinking.is_empty()
                            && signature
                                .as_ref()
                                .map(|s| s.len() >= MIN_SIGNATURE_LENGTH)
                                .unwrap_or(false)
                        {
                            has_valid_thinking = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !has_valid_thinking {
        if state.in_tool_loop {
            info!("[Thinking-Recovery] Broken tool loop (ToolResult without preceding Thinking). Recovery triggered.");
            messages.push(Message {
                role: "assistant".to_string(),
                content: MessageContent::Array(vec![ContentBlock::Text {
                    text: "[System: Tool execution completed. Proceeding to final response.]"
                        .to_string(),
                }]),
            });
            messages.push(Message {
                role: "user".to_string(),
                content: MessageContent::Array(vec![ContentBlock::Text {
                    text: "Please provide the final result based on the tool output above."
                        .to_string(),
                }]),
            });
        } else if state.interrupted_tool {
            info!(
                "[Thinking-Recovery] Interrupted tool call detected. Injecting synthetic closure."
            );
            if let Some(idx) = state.last_assistant_idx {
                messages.insert(
                    idx + 1,
                    Message {
                        role: "assistant".to_string(),
                        content: MessageContent::Array(vec![ContentBlock::Text {
                            text: "[Tool call was interrupted by user.]".to_string(),
                        }]),
                    },
                );
            }
        }
    }
}
pub fn get_signature_family(signature: &str) -> Option<String> {
    SignatureCache::global().get_signature_family(signature)
}
pub fn filter_invalid_thinking_blocks_with_family(
    messages: &mut [Message],
    target_family: Option<&str>,
) {
    let mut stripped_count = 0;

    for msg in messages.iter_mut() {
        if msg.role != "assistant" {
            continue;
        }

        if let MessageContent::Array(blocks) = &mut msg.content {
            let original_len = blocks.len();
            blocks.retain(|block| {
                if let ContentBlock::Thinking { signature, .. } = block {
                    let sig = match signature {
                        Some(s) if s.len() >= MIN_SIGNATURE_LENGTH || s.is_empty() => s,
                        None => return true,
                        _ => {
                            stripped_count += 1;
                            return false;
                        }
                    };
                    if let Some(target) = target_family {
                        if let Some(origin_family) = get_signature_family(sig) {
                            if origin_family != target {
                                warn!("[Thinking-Sanitizer] Dropping signature from family '{}' for target '{}'", origin_family, target);
                                stripped_count += 1;
                                return false;
                            }
                        } else {
                            info!("[Thinking-Sanitizer] Dropping unverified signature (cache miss after restart)");
                            stripped_count += 1;
                            return false;
                        }
                    } else if get_signature_family(sig).is_none() && !sig.is_empty() {
                        info!("[Thinking-Sanitizer] Dropping unverified signature (no target family)");
                        stripped_count += 1;
                        return false;
                    }
                }
                true
            });
            if blocks.is_empty() && original_len > 0 {
                blocks.push(ContentBlock::Text {
                    text: ".".to_string(),
                });
            }
        }
    }

    if stripped_count > 0 {
        info!(
            "[Thinking-Sanitizer] Stripped {} invalid or incompatible thinking blocks",
            stripped_count
        );
    }
}