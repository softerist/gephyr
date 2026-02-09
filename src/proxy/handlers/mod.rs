pub mod claude;
pub mod common;
pub mod errors;
pub mod gemini;
pub mod openai;
pub mod retry;
pub mod streaming;

// PR-19 decision: keep handlers function-oriented for now.
// Shared behavior is already centralized in retry/errors/streaming modules, and
// introducing a cross-protocol trait layer here would add indirection without
// reducing meaningful complexity in current call paths.
