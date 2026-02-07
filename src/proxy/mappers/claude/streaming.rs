// Claude streaming response conversion (Gemini SSE → Claude SSE)
// Corresponds to StreamingState + PartProcessor

use super::models::*;
use super::utils::to_claude_usage;
use crate::proxy::mappers::estimation_calibrator::get_calibrator;
// use crate::proxy::mappers::signature_store::store_thought_signature; // Deprecated
use crate::proxy::SignatureCache;
use crate::proxy::common::client_adapter::{ClientAdapter, SignatureBufferStrategy}; // 
use bytes::Bytes;
use serde_json::{json, Value};

// Known parameter remappings for Gemini → Claude compatibility
//  Gemini sometimes uses different parameter names than specified in tool schema
pub fn remap_function_call_args(name: &str, args: &mut Value) {
    //  Always log incoming tool usage for diagnosis
    if let Some(obj) = args.as_object() {
        tracing::debug!("[Streaming] Tool Call: '{}' Args: {:?}", name, obj);
    }

    // [IMPORTANT] Claude Code CLI's EnterPlanMode tool is prohibited from carrying any parameters.
    // The reason parameter injected by the proxy layer will result in an InputValidationError.
    if name == "EnterPlanMode" {
        if let Some(obj) = args.as_object_mut() {
            obj.clear();
        }
        return;
    }

    if let Some(obj) = args.as_object_mut() {
        //  Case-insensitive matching for tool names
        match name.to_lowercase().as_str() {
            "grep" | "search" | "search_code_definitions" | "search_code_snippets" => {
                //  Gemini hallucination: maps parameter description to "description" field
                if let Some(desc) = obj.remove("description") {
                    if !obj.contains_key("pattern") {
                        obj.insert("pattern".to_string(), desc);
                        tracing::debug!("[Streaming] Remapped Grep: description → pattern");
                    }
                }

                // Gemini uses "query", Claude Code expects "pattern"
                if let Some(query) = obj.remove("query") {
                    if !obj.contains_key("pattern") {
                        obj.insert("pattern".to_string(), query);
                        tracing::debug!("[Streaming] Remapped Grep: query → pattern");
                    }
                }

                // Claude Code uses "path" (string), NOT "paths" (array)!
                if !obj.contains_key("path") {
                    if let Some(paths) = obj.remove("paths") {
                        let path_str = if let Some(arr) = paths.as_array() {
                            arr.get(0)
                                .and_then(|v| v.as_str())
                                .unwrap_or(".")
                                .to_string()
                        } else if let Some(s) = paths.as_str() {
                            s.to_string()
                        } else {
                            ".".to_string()
                        };
                        obj.insert("path".to_string(), serde_json::json!(path_str));
                        tracing::debug!(
                            "[Streaming] Remapped Grep: paths → path(\"{}\")",
                            path_str
                        );
                    } else {
                        // Default to current directory if missing
                        obj.insert("path".to_string(), json!("."));
                        tracing::debug!("[Streaming] Added default path: \".\"");
                    }
                }

                // Note: We keep "-n" and "output_mode" if present as they are valid in Grep schema
            }
            "glob" => {
                //  Gemini hallucination: maps parameter description to "description" field
                if let Some(desc) = obj.remove("description") {
                    if !obj.contains_key("pattern") {
                        obj.insert("pattern".to_string(), desc);
                        tracing::debug!("[Streaming] Remapped Glob: description → pattern");
                    }
                }

                // Gemini uses "query", Claude Code expects "pattern"
                if let Some(query) = obj.remove("query") {
                    if !obj.contains_key("pattern") {
                        obj.insert("pattern".to_string(), query);
                        tracing::debug!("[Streaming] Remapped Glob: query → pattern");
                    }
                }

                // Claude Code uses "path" (string), NOT "paths" (array)!
                if !obj.contains_key("path") {
                    if let Some(paths) = obj.remove("paths") {
                        let path_str = if let Some(arr) = paths.as_array() {
                            arr.get(0)
                                .and_then(|v| v.as_str())
                                .unwrap_or(".")
                                .to_string()
                        } else if let Some(s) = paths.as_str() {
                            s.to_string()
                        } else {
                            ".".to_string()
                        };
                        obj.insert("path".to_string(), serde_json::json!(path_str));
                        tracing::debug!(
                            "[Streaming] Remapped Glob: paths → path(\"{}\")",
                            path_str
                        );
                    } else {
                        // Default to current directory if missing
                        obj.insert("path".to_string(), json!("."));
                        tracing::debug!("[Streaming] Added default path: \".\"");
                    }
                }
            }
            "read" => {
                // Gemini might use "path" vs "file_path"
                if let Some(path) = obj.remove("path") {
                    if !obj.contains_key("file_path") {
                        obj.insert("file_path".to_string(), path);
                        tracing::debug!("[Streaming] Remapped Read: path → file_path");
                    }
                }
            }
            "ls" => {
                // LS tool: ensure "path" parameter exists
                if !obj.contains_key("path") {
                    obj.insert("path".to_string(), json!("."));
                    tracing::debug!("[Streaming] Remapped LS: default path → \".\"");
                }
            }
            other => {
                //  Generic Property Mapping for all tools
                // If a tool has "paths" (array of 1) but no "path", convert it.
                let mut path_to_inject = None;
                if !obj.contains_key("path") {
                    if let Some(paths) = obj.get("paths").and_then(|v| v.as_array()) {
                        if paths.len() == 1 {
                            if let Some(p) = paths[0].as_str() {
                                path_to_inject = Some(p.to_string());
                            }
                        }
                    }
                }

                if let Some(path) = path_to_inject {
                    obj.insert("path".to_string(), json!(path));
                    tracing::debug!(
                        "[Streaming] Probabilistic fix for tool '{}': paths[0] → path(\"{}\")",
                        other,
                        path
                    );
                }
                tracing::debug!(
                    "[Streaming] Unmapped tool call processed via generic rules: {} (keys: {:?})",
                    other,
                    obj.keys()
                );
            }
        }
    }
}

// Block type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    None,
    Text,
    Thinking,
    Function,
}

// Signature manager
pub struct SignatureManager {
    pending: Option<String>,
}

impl SignatureManager {
    pub fn new() -> Self {
        Self { pending: None }
    }

    pub fn store(&mut self, signature: Option<String>) {
        if signature.is_some() {
            self.pending = signature;
        }
    }

    pub fn consume(&mut self) -> Option<String> {
        self.pending.take()
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}

// Streaming state machine
pub struct StreamingState {
    block_type: BlockType,
    pub block_index: usize,
    pub message_start_sent: bool,
    pub message_stop_sent: bool,
    used_tool: bool,
    signatures: SignatureManager,
    trailing_signature: Option<String>,
    pub web_search_query: Option<String>,
    pub grounding_chunks: Option<Vec<serde_json::Value>>,
    //  Error recovery state tracking (prepared for future use)
    #[allow(dead_code)]
    parse_error_count: usize,
    #[allow(dead_code)]
    last_valid_state: Option<BlockType>,
    //  Model tracking for signature cache
    pub model_name: Option<String>,
    // [NEW v3.3.17] Session ID for session-based signature caching
    pub session_id: Option<String>,
    //  Flag for context usage scaling
    pub scaling_enabled: bool,
    //  Context limit for smart threshold recovery (default to 1M)
    pub context_limit: u32,
    //  MCP XML Bridge buffer
    pub mcp_xml_buffer: String,
    pub in_mcp_xml: bool,
    //  Estimated prompt tokens for calibrator learning
    pub estimated_prompt_tokens: Option<u32>,
    // Post-thinking interruption tracking
    pub has_thinking: bool,
    pub has_content: bool,
    pub message_count: usize, //  Message count for rewind detection
    pub client_adapter: Option<std::sync::Arc<dyn ClientAdapter>>, //  Remove Box, use Arc<dyn> directly
}

impl StreamingState {
    pub fn new() -> Self {
        Self {
            block_type: BlockType::None,
            block_index: 0,
            message_start_sent: false,
            message_stop_sent: false,
            used_tool: false,
            signatures: SignatureManager::new(),
            trailing_signature: None,
            web_search_query: None,
            grounding_chunks: None,
            //  Initialize error recovery fields
            parse_error_count: 0,
            last_valid_state: None,
            model_name: None,
            session_id: None,
            scaling_enabled: false,
            context_limit: 1_048_576, // Default to 1M
            mcp_xml_buffer: String::new(),
            in_mcp_xml: false,
            estimated_prompt_tokens: None,
            has_thinking: false,
            has_content: false,
            message_count: 0,
            client_adapter: None,
        }
    }

    //  Set client adapter
    pub fn set_client_adapter(&mut self, adapter: Option<std::sync::Arc<dyn ClientAdapter>>) {
        self.client_adapter = adapter;
    }

    // Emit SSE event
    pub fn emit(&self, event_type: &str, data: serde_json::Value) -> Bytes {
        let sse = format!(
            "event: {}\ndata: {}\n\n",
            event_type,
            serde_json::to_string(&data).unwrap_or_default()
        );
        Bytes::from(sse)
    }

    // Emit message_start event
    pub fn emit_message_start(&mut self, raw_json: &serde_json::Value) -> Bytes {
        if self.message_start_sent {
            return Bytes::new();
        }

        let usage = raw_json
            .get("usageMetadata")
            .and_then(|u| serde_json::from_value::<UsageMetadata>(u.clone()).ok())
            .map(|u| to_claude_usage(&u, self.scaling_enabled, self.context_limit));

        let mut message = json!({
            "id": raw_json.get("responseId")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| "msg_unknown"),
            "type": "message",
            "role": "assistant",
            "content": [],
            "model": raw_json.get("modelVersion")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            "stop_reason": null,
            "stop_sequence": null,
        });

        // Capture model name for signature cache
        if let Some(m) = raw_json.get("modelVersion").and_then(|v| v.as_str()) {
            self.model_name = Some(m.to_string());
        }

        if let Some(u) = usage {
            message["usage"] = json!(u);
        }

        let result = self.emit(
            "message_start",
            json!({
                "type": "message_start",
                "message": message
            }),
        );

        self.message_start_sent = true;
        result
    }

    // Start a new content block
    pub fn start_block(
        &mut self,
        block_type: BlockType,
        content_block: serde_json::Value,
    ) -> Vec<Bytes> {
        let mut chunks = Vec::new();
        if self.block_type != BlockType::None {
            chunks.extend(self.end_block());
        }

        chunks.push(self.emit(
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": self.block_index,
                "content_block": content_block
            }),
        ));

        self.block_type = block_type;
        chunks
    }

    // End current content block
    pub fn end_block(&mut self) -> Vec<Bytes> {
        if self.block_type == BlockType::None {
            return vec![];
        }

        let mut chunks = Vec::new();

        // Send the pending signature when the Thinking block ends
        if self.block_type == BlockType::Thinking && self.signatures.has_pending() {
            if let Some(signature) = self.signatures.consume() {
                chunks.push(self.emit_delta("signature_delta", json!({ "signature": signature })));
            }
        }

        chunks.push(self.emit(
            "content_block_stop",
            json!({
                "type": "content_block_stop",
                "index": self.block_index
            }),
        ));

        self.block_index += 1;
        self.block_type = BlockType::None;

        chunks
    }

    // Emit delta event
    pub fn emit_delta(&self, delta_type: &str, delta_content: serde_json::Value) -> Bytes {
        let mut delta = json!({ "type": delta_type });
        if let serde_json::Value::Object(map) = delta_content {
            for (k, v) in map {
                delta[k] = v;
            }
        }

        self.emit(
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": self.block_index,
                "delta": delta
            }),
        )
    }

    // Emit finish event
    pub fn emit_finish(
        &mut self,
        finish_reason: Option<&str>,
        usage_metadata: Option<&UsageMetadata>,
    ) -> Vec<Bytes> {
        let mut chunks = Vec::new();

        // Close the last block
        chunks.extend(self.end_block());

        // Handle trailingSignature (B4/C3 scenario)
        //  Only when no blocks have been sent yet can it end with a thinking block (as the start of the message).
        // In fact, for the Claude protocol, if Text has already been sent, Thinking cannot be appended here.
        // The solution here is: only store the signature, do not send the illegal trailing Thinking block.
        // The signature will be automatically restored in the next round of requests via SignatureCache.
        if let Some(signature) = self.trailing_signature.take() {
            tracing::info!(
                "[Streaming] Captured trailing signature (len: {}), caching for session.",
                signature.len()
            );
            self.signatures.store(Some(signature));
            // Do not append chunks.push(self.emit("content_block_start", ...))
        }

        // Handle grounding (web search) -> convert to Markdown text block
        if self.web_search_query.is_some() || self.grounding_chunks.is_some() {
            let mut grounding_text = String::new();

            // 1. Handle search queries
            if let Some(query) = &self.web_search_query {
                if !query.is_empty() {
                    grounding_text.push_str("\n\n---\n**🔍 Searched for you:** ");
                    grounding_text.push_str(query);
                }
            }

            // 2. Handle source links
            if let Some(chunks) = &self.grounding_chunks {
                let mut links = Vec::new();
                for (i, chunk) in chunks.iter().enumerate() {
                    if let Some(web) = chunk.get("web") {
                        let title = web
                            .get("title")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Web Source");
                        let uri = web.get("uri").and_then(|v| v.as_str()).unwrap_or("#");
                        links.push(format!("[{}] [{}]({})", i + 1, title, uri));
                    }
                }

                if !links.is_empty() {
                    grounding_text.push_str("\n\n**🌐 Source Citations:**\n");
                    grounding_text.push_str(&links.join("\n"));
                }
            }

            if !grounding_text.is_empty() {
                // Send a new text block
                chunks.push(self.emit(
                    "content_block_start",
                    json!({
                        "type": "content_block_start",
                        "index": self.block_index,
                        "content_block": { "type": "text", "text": "" }
                    }),
                ));
                chunks.push(self.emit_delta("text_delta", json!({ "text": grounding_text })));
                chunks.push(self.emit(
                    "content_block_stop",
                    json!({ "type": "content_block_stop", "index": self.block_index }),
                ));
                self.block_index += 1;
            }
        }

        // Determine stop_reason
        let stop_reason = if self.used_tool {
            "tool_use"
        } else if finish_reason == Some("MAX_TOKENS") {
            "max_tokens"
        } else {
            "end_turn"
        };

        let usage = usage_metadata
            .map(|u| {
                //  Record actual token usage for calibrator learning
                // Now properly pairs estimated tokens from request with actual tokens from response
                if let (Some(estimated), Some(actual)) =
                    (self.estimated_prompt_tokens, u.prompt_token_count)
                {
                    if estimated > 0 && actual > 0 {
                        get_calibrator().record(estimated, actual);
                        tracing::debug!(
                            "[Calibrator] Recorded: estimated={}, actual={}, ratio={:.2}x",
                            estimated,
                            actual,
                            actual as f64 / estimated as f64
                        );
                    }
                }
                to_claude_usage(u, self.scaling_enabled, self.context_limit)
            })
            .unwrap_or(Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                server_tool_use: None,
            });

        chunks.push(self.emit(
            "message_delta",
            json!({
                "type": "message_delta",
                "delta": { "stop_reason": stop_reason, "stop_sequence": null },
                "usage": usage
            }),
        ));

        if !self.message_stop_sent {
            chunks.push(Bytes::from(
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ));
            self.message_stop_sent = true;
        }

        chunks
    }

    // Mark that a tool was used
    pub fn mark_tool_used(&mut self) {
        self.used_tool = true;
    }

    // Get current block type
    pub fn current_block_type(&self) -> BlockType {
        self.block_type
    }

    // Get current block index
    pub fn current_block_index(&self) -> usize {
        self.block_index
    }

    // Store signature
    pub fn store_signature(&mut self, signature: Option<String>) {
        self.signatures.store(signature);
    }

    // Set trailing signature
    pub fn set_trailing_signature(&mut self, signature: Option<String>) {
        self.trailing_signature = signature;
    }

    // Get trailing signature (for checking only)
    pub fn has_trailing_signature(&self) -> bool {
        self.trailing_signature.is_some()
    }

    // Handle SSE parsing error, implement graceful degradation
    //
    // When a parsing error occurs in the SSE stream:
    // 1. Safely close the current block
    // 2. Increment the error counter
    // 3. Output error information in debug mode
    #[allow(dead_code)] // Prepared for future error recovery implementation
    pub fn handle_parse_error(&mut self, raw_data: &str) -> Vec<Bytes> {
        let mut chunks = Vec::new();

        self.parse_error_count += 1;

        tracing::warn!(
            "[SSE-Parser] Parse error #{} occurred. Raw data length: {} bytes",
            self.parse_error_count,
            raw_data.len()
        );

        // Safely close the current block
        if self.block_type != BlockType::None {
            self.last_valid_state = Some(self.block_type);
            chunks.extend(self.end_block());
        }

        // Output detailed error information in Debug mode
        #[cfg(debug_assertions)]
        {
            let preview = if raw_data.len() > 100 {
                format!("{}...", &raw_data[..100])
            } else {
                raw_data.to_string()
            };
            tracing::debug!("[SSE-Parser] Failed chunk preview: {}", preview);
        }

        // Warn and attempt to send error signal when error rate is too high
        if self.parse_error_count > 3 {
            // Lower threshold, notify user earlier
            tracing::error!(
                "[SSE-Parser] High error rate detected ({} errors). Stream may be corrupted.",
                self.parse_error_count
            );

            //  Explicitly signal error to client to prevent UI freeze
            // using standard SSE error event format
            // data: {"type": "error", "error": {...}}
            chunks.push(self.emit(
                "error",
                json!({
                    "type": "error",
                    "error": {
                        "type": "overloaded_error", // Use standard type
                        "message": "Network connection unstable, please check your network or proxy settings.",
                    }
                }),
            ));
        }

        chunks
    }

    // Reset error state (called after recovery)
    #[allow(dead_code)]
    pub fn reset_error_state(&mut self) {
        self.parse_error_count = 0;
        self.last_valid_state = None;
    }

    // Get error count (for monitoring)
    #[allow(dead_code)]
    pub fn get_error_count(&self) -> usize {
        self.parse_error_count
    }
}

// Part processor
pub struct PartProcessor<'a> {
    state: &'a mut StreamingState,
}

impl<'a> PartProcessor<'a> {
    pub fn new(state: &'a mut StreamingState) -> Self {
        Self { state }
    }

    // Process single part
    pub fn process(&mut self, part: &GeminiPart) -> Vec<Bytes> {
        let mut chunks = Vec::new();
        // Decode Base64 signature if present (Gemini sends Base64, Claude expects Raw)
        let signature = part.thought_signature.as_ref().map(|sig| {
            // Try to decode as base64
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(sig) {
                Ok(decoded_bytes) => {
                    match String::from_utf8(decoded_bytes) {
                        Ok(decoded_str) => {
                            tracing::debug!(
                                "[Streaming] Decoded base64 signature (len {} -> {})",
                                sig.len(),
                                decoded_str.len()
                            );
                            decoded_str
                        }
                        Err(_) => sig.clone(), // Not valid UTF-8, keep as is
                    }
                }
                Err(_) => sig.clone(), // Not base64, keep as is
            }
        });

        // 1. FunctionCall handling
        if let Some(fc) = &part.function_call {
            // Handle trailingSignature first (B4/C3 scenarios)
            if self.state.has_trailing_signature() {
                chunks.extend(self.state.end_block());
                if let Some(trailing_sig) = self.state.trailing_signature.take() {
                    chunks.push(self.state.emit(
                        "content_block_start",
                        json!({
                            "type": "content_block_start",
                            "index": self.state.current_block_index(),
                            "content_block": { "type": "thinking", "thinking": "" }
                        }),
                    ));
                    chunks.push(
                        self.state
                            .emit_delta("thinking_delta", json!({ "thinking": "" })),
                    );
                    chunks.push(
                        self.state
                            .emit_delta("signature_delta", json!({ "signature": trailing_sig })),
                    );
                    chunks.extend(self.state.end_block());
                }
            }

            chunks.extend(self.process_function_call(fc, signature));
            // Mark that we have received actual content (tool use)
            self.state.has_content = true;
            return chunks;
        }

        // 2. Text handling
        if let Some(text) = &part.text {
            if part.thought.unwrap_or(false) {
                // Thinking
                chunks.extend(self.process_thinking(text, signature));
            } else {
                // Regular Text
                chunks.extend(self.process_text(text, signature));
            }
        }

        // 3. InlineData (Image) handling
        if let Some(img) = &part.inline_data {
            let mime_type = &img.mime_type;
            let data = &img.data;
            if !data.is_empty() {
                let markdown_img = format!("![image](data:{};base64,{})", mime_type, data);
                chunks.extend(self.process_text(&markdown_img, None));
            }
        }

        chunks
    }

    // Handle Thinking
    fn process_thinking(&mut self, text: &str, signature: Option<String>) -> Vec<Bytes> {
        let mut chunks = Vec::new();

        // Handle previous trailingSignature
        if self.state.has_trailing_signature() {
            chunks.extend(self.state.end_block());
            if let Some(trailing_sig) = self.state.trailing_signature.take() {
                chunks.push(self.state.emit(
                    "content_block_start",
                    json!({
                        "type": "content_block_start",
                        "index": self.state.current_block_index(),
                        "content_block": { "type": "thinking", "thinking": "" }
                    }),
                ));
                chunks.push(
                    self.state
                        .emit_delta("thinking_delta", json!({ "thinking": "" })),
                );
                chunks.push(
                    self.state
                        .emit_delta("signature_delta", json!({ "signature": trailing_sig })),
                );
                chunks.extend(self.state.end_block());
            }
        }

        // Start or continue thinking block
        if self.state.current_block_type() != BlockType::Thinking {
            chunks.extend(self.state.start_block(
                BlockType::Thinking,
                json!({ "type": "thinking", "thinking": "" }),
            ));
        }

        // Mark that we have received thinking content
        self.state.has_thinking = true;

        if !text.is_empty() {
            chunks.push(
                self.state
                    .emit_delta("thinking_delta", json!({ "thinking": text })),
            );
        }

        //  Apply Client Adapter Strategy
        let use_fifo = self.state.client_adapter.as_ref()
            .map(|a| a.signature_buffer_strategy() == SignatureBufferStrategy::Fifo)
            .unwrap_or(false);

        //  Store signature to global cache
        if let Some(ref sig) = signature {
            // 1. Cache family if we know the model
            if let Some(model) = &self.state.model_name {
                SignatureCache::global().cache_thinking_family(sig.clone(), model.clone());
            }

            // 2. [NEW v3.3.17] Cache to session-based storage for tool loop recovery
            if let Some(session_id) = &self.state.session_id {
                // If FIFO strategy is enabled, use a unique index for each signature (e.g. timestamp or counter)
                // However, our cache implementation currently keys by session_id.
                // For FIFO, we might just rely on the fact that we are processing in order.
                // But specifically for opencode, it might be calling tools in parallel or sequence.
                
                SignatureCache::global().cache_session_signature(
                    session_id, 
                    sig.clone(), 
                    self.state.message_count
                );
                tracing::debug!(
                    "[Claude-SSE] Cached signature to session {} (length: {}) [FIFO: {}]",
                    session_id,
                    sig.len(),
                    use_fifo
                );
            }

            tracing::debug!(
                "[Claude-SSE] Captured thought_signature from thinking block (length: {})",
                sig.len()
            );
        }

        // Temporarily store signature (for local block handling)
        // If FIFO, we strictly follow the sequence. The default logic is effectively LIFO for a single turn 
        // (store latest, consume at end). 
        // For opencode, we just want to ensure we capture IT.
        self.state.store_signature(signature);

        chunks
    }

    // Handle regular Text
    fn process_text(&mut self, text: &str, signature: Option<String>) -> Vec<Bytes> {
        let mut chunks = Vec::new();

        // Empty text with signature - temporarily store
        if text.is_empty() {
            if signature.is_some() {
                self.state.set_trailing_signature(signature);
            }
            return chunks;
        }

        // Mark that we have received actual content (text)
        self.state.has_content = true;

        // Handle previous trailingSignature
        if self.state.has_trailing_signature() {
            chunks.extend(self.state.end_block());
            if let Some(trailing_sig) = self.state.trailing_signature.take() {
                chunks.push(self.state.emit(
                    "content_block_start",
                    json!({
                        "type": "content_block_start",
                        "index": self.state.current_block_index(),
                        "content_block": { "type": "thinking", "thinking": "" }
                    }),
                ));
                chunks.push(
                    self.state
                        .emit_delta("thinking_delta", json!({ "thinking": "" })),
                );
                chunks.push(
                    self.state
                        .emit_delta("signature_delta", json!({ "signature": trailing_sig })),
                );
                chunks.extend(self.state.end_block());
            }
        }

        // Non-empty text with signature - handle immediately
        if signature.is_some() {
            //  To protect signature, send the Text block with signature directly.
            // Note: Do not start a thinking block here, because there may have been non-thinking content before.
            // In this case, we just need to ensure the signature is cached in the state.
            self.state.store_signature(signature);

            chunks.extend(
                self.state
                    .start_block(BlockType::Text, json!({ "type": "text", "text": "" })),
            );
            chunks.push(self.state.emit_delta("text_delta", json!({ "text": text })));
            chunks.extend(self.state.end_block());

            return chunks;
        }

        // Ordinary text (without signature)

        //  MCP XML Bridge: Intercept and parse <mcp__...> tags
        if text.contains("<mcp__") || self.state.in_mcp_xml {
            self.state.in_mcp_xml = true;
            self.state.mcp_xml_buffer.push_str(text);

            // Check if we have a complete tag in the buffer
            if self.state.mcp_xml_buffer.contains("</mcp__")
                && self.state.mcp_xml_buffer.contains('>')
            {
                let buffer = self.state.mcp_xml_buffer.clone();
                if let Some(start_idx) = buffer.find("<mcp__") {
                    if let Some(tag_end_idx) = buffer[start_idx..].find('>') {
                        let actual_tag_end = start_idx + tag_end_idx;
                        let tool_name = &buffer[start_idx + 1..actual_tag_end];
                        let end_tag = format!("</{}>", tool_name);

                        if let Some(close_idx) = buffer.find(&end_tag) {
                            let input_str = &buffer[actual_tag_end + 1..close_idx];
                            let input_json: serde_json::Value =
                                serde_json::from_str(input_str.trim())
                                    .unwrap_or_else(|_| json!({ "input": input_str.trim() }));

                            // Construct and send tool_use
                            let fc = FunctionCall {
                                name: tool_name.to_string(),
                                args: Some(input_json),
                                id: Some(format!("{}-xml", tool_name)),
                            };

                            let tool_chunks = self.process_function_call(&fc, None);

                            // Clean buffer and reset state
                            self.state.mcp_xml_buffer.clear();
                            self.state.in_mcp_xml = false;

                            // Handle possible non-XML text before the tag
                            if start_idx > 0 {
                                let prefix_text = &buffer[..start_idx];
                                // Cannot recurse here. Directly emit the previous text block.
                                if self.state.current_block_type() != BlockType::Text {
                                    chunks.extend(self.state.start_block(
                                        BlockType::Text,
                                        json!({ "type": "text", "text": "" }),
                                    ));
                                }
                                chunks.push(
                                    self.state
                                        .emit_delta("text_delta", json!({ "text": prefix_text })),
                                );
                            }

                            chunks.extend(tool_chunks);

                            // Handle possible non-XML text after the tag
                            let suffix = &buffer[close_idx + end_tag.len()..];
                            if !suffix.is_empty() {
                                // Recursively handle suffix content
                                chunks.extend(self.process_text(suffix, None));
                            }

                            return chunks;
                        }
                    }
                }
            }
            // While in XML, don't emit text deltas
            return vec![];
        }

        if self.state.current_block_type() != BlockType::Text {
            chunks.extend(
                self.state
                    .start_block(BlockType::Text, json!({ "type": "text", "text": "" })),
            );
        }

        chunks.push(self.state.emit_delta("text_delta", json!({ "text": text })));

        chunks
    }

    // Process FunctionCall and capture signature for global storage
    fn process_function_call(
        &mut self,
        fc: &FunctionCall,
        signature: Option<String>,
    ) -> Vec<Bytes> {
        let mut chunks = Vec::new();

        self.state.mark_tool_used();

        let tool_id = fc.id.clone().unwrap_or_else(|| {
            format!(
                "{}-{}",
                fc.name,
                crate::proxy::common::utils::generate_random_id()
            )
        });

        let mut tool_name = fc.name.clone();
        if tool_name.to_lowercase() == "search" {
            tool_name = "grep".to_string();
            tracing::debug!("[Streaming] Normalizing tool name: Search → grep");
        }

        // 1. Send content_block_start (input is an empty object)
        let mut tool_use = json!({
            "type": "tool_use",
            "id": tool_id,
            "name": tool_name,
            "input": {} // Must be empty, parameters are sent via delta
        });

        if let Some(ref sig) = signature {
            tool_use["signature"] = json!(sig);

            // 2. Cache tool signature (Layer 1 recovery)
            SignatureCache::global().cache_tool_signature(&tool_id, sig.clone());

            // 3. [NEW v3.3.17] Cache to session-based storage
            if let Some(session_id) = &self.state.session_id {
                SignatureCache::global().cache_session_signature(
                    session_id, 
                    sig.clone(),
                    self.state.message_count
                );
            }

            tracing::debug!(
                "[Claude-SSE] Captured thought_signature for function call (length: {})",
                sig.len()
            );
        }

        chunks.extend(self.state.start_block(BlockType::Function, tool_use));

        // 2. Send input_json_delta (complete parameter JSON string)
        //  Remap args before serialization for Gemini → Claude compatibility
        if let Some(args) = &fc.args {
            let mut remapped_args = args.clone();

            let tool_name_title = fc.name.clone();
            // [OPTIMIZED] Only rename if it's "search" which is a known hallucination.
            // Avoid renaming "grep" to "Grep" if possible to protect signature,
            // unless we're sure Grep is the standard.
            let mut final_tool_name = tool_name_title;
            if final_tool_name.to_lowercase() == "search" {
                final_tool_name = "Grep".to_string();
            }
            remap_function_call_args(&final_tool_name, &mut remapped_args);

            let json_str =
                serde_json::to_string(&remapped_args).unwrap_or_else(|_| "{}".to_string());
            chunks.push(
                self.state
                    .emit_delta("input_json_delta", json!({ "partial_json": json_str })),
            );
        }

        // 3. End block
        chunks.extend(self.state.end_block());

        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_manager() {
        let mut mgr = SignatureManager::new();
        assert!(!mgr.has_pending());

        mgr.store(Some("sig123".to_string()));
        assert!(mgr.has_pending());

        let sig = mgr.consume();
        assert_eq!(sig, Some("sig123".to_string()));
        assert!(!mgr.has_pending());
    }

    #[test]
    fn test_streaming_state_emit() {
        let state = StreamingState::new();
        let chunk = state.emit("test_event", json!({"foo": "bar"}));

        let s = String::from_utf8(chunk.to_vec()).unwrap();
        assert!(s.contains("event: test_event"));
        assert!(s.contains("\"foo\":\"bar\""));
    }

    #[test]
    fn test_process_function_call_deltas() {
        let mut state = StreamingState::new();
        let mut processor = PartProcessor::new(&mut state);

        let fc = FunctionCall {
            name: "test_tool".to_string(),
            args: Some(json!({"arg": "value"})),
            id: Some("call_123".to_string()),
        };

        // Create a dummy GeminiPart with function_call
        let part = GeminiPart {
            text: None,
            function_call: Some(fc),
            inline_data: None,
            thought: None,
            thought_signature: None,
            function_response: None,
        };

        let chunks = processor.process(&part);
        let output = chunks
            .iter()
            .map(|b| String::from_utf8(b.to_vec()).unwrap())
            .collect::<Vec<_>>()
            .join("");

        // Verify sequence:
        // 1. content_block_start with empty input
        assert!(output.contains(r#""type":"content_block_start""#));
        assert!(output.contains(r#""name":"test_tool""#));
        assert!(output.contains(r#""input":{}"#));

        // 2. input_json_delta with serialized args
        assert!(output.contains(r#""type":"content_block_delta""#));
        assert!(output.contains(r#""type":"input_json_delta""#));
        // partial_json should contain escaped JSON string
        assert!(output.contains(r#"partial_json":"{\"arg\":\"value\"}"#));

        // 3. content_block_stop
        assert!(output.contains(r#""type":"content_block_stop""#));
    }
}
