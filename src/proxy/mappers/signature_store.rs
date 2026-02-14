use std::sync::{Mutex, OnceLock};

static GLOBAL_THOUGHT_SIG: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn get_thought_sig_storage() -> &'static Mutex<Option<String>> {
    GLOBAL_THOUGHT_SIG.get_or_init(|| Mutex::new(None))
}
pub fn store_thought_signature(sig: &str) {
    if let Ok(mut guard) = get_thought_sig_storage().lock() {
        let should_store = match &*guard {
            None => true,
            Some(existing) => sig.len() > existing.len(),
        };

        if should_store {
            tracing::debug!(
                "[ThoughtSig] Storing new signature (length: {}, replacing old length: {:?})",
                sig.len(),
                guard.as_ref().map(|s| s.len())
            );
            *guard = Some(sig.to_string());
        } else {
            tracing::debug!(
                "[ThoughtSig] Skipping shorter signature (new length: {}, existing length: {})",
                sig.len(),
                guard.as_ref().map(|s| s.len()).unwrap_or(0)
            );
        }
    }
}
pub fn get_thought_signature() -> Option<String> {
    if let Ok(guard) = get_thought_sig_storage().lock() {
        guard.clone()
    } else {
        None
    }
}
#[cfg(test)]
pub fn take_thought_signature() -> Option<String> {
    if let Ok(mut guard) = get_thought_sig_storage().lock() {
        guard.take()
    } else {
        None
    }
}
#[cfg(test)]
pub fn clear_thought_signature() {
    if let Ok(mut guard) = get_thought_sig_storage().lock() {
        *guard = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_storage() {
        clear_thought_signature();
        assert!(get_thought_signature().is_none());
        store_thought_signature("test_signature_1234");
        assert_eq!(
            get_thought_signature(),
            Some("test_signature_1234".to_string())
        );
        store_thought_signature("short");
        assert_eq!(
            get_thought_signature(),
            Some("test_signature_1234".to_string())
        );
        store_thought_signature("test_signature_1234_longer_version");
        assert_eq!(
            get_thought_signature(),
            Some("test_signature_1234_longer_version".to_string())
        );
        let taken = take_thought_signature();
        assert_eq!(
            taken,
            Some("test_signature_1234_longer_version".to_string())
        );
        assert!(get_thought_signature().is_none());
    }
}