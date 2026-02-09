#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerProtocol {
    Claude,
    OpenAI,
    Gemini,
}

pub trait LlmHandler {
    fn protocol(&self) -> HandlerProtocol;
}

impl LlmHandler for HandlerProtocol {
    fn protocol(&self) -> HandlerProtocol {
        *self
    }
}

pub fn protocol_name<H: LlmHandler>(handler: &H) -> &'static str {
    match handler.protocol() {
        HandlerProtocol::Claude => "claude",
        HandlerProtocol::OpenAI => "openai",
        HandlerProtocol::Gemini => "gemini",
    }
}

pub fn all_handler_protocols() -> [HandlerProtocol; 3] {
    [
        HandlerProtocol::Claude,
        HandlerProtocol::OpenAI,
        HandlerProtocol::Gemini,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_name_mapping_is_stable() {
        assert_eq!(protocol_name(&HandlerProtocol::Claude), "claude");
        assert_eq!(protocol_name(&HandlerProtocol::OpenAI), "openai");
        assert_eq!(protocol_name(&HandlerProtocol::Gemini), "gemini");
    }

    #[test]
    fn all_protocols_contains_three_values() {
        let all = all_handler_protocols();
        assert_eq!(all.len(), 3);
    }
}
