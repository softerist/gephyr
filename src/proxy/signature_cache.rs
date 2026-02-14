use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};
const SIGNATURE_TTL: Duration = Duration::from_secs(2 * 60 * 60);
const MIN_SIGNATURE_LENGTH: usize = 50;
const TOOL_CACHE_LIMIT: usize = 500;
const FAMILY_CACHE_LIMIT: usize = 200;
const SESSION_CACHE_LIMIT: usize = 1000;
#[derive(Clone, Debug)]
struct CacheEntry<T> {
    data: T,
    timestamp: SystemTime,
}
#[derive(Clone, Debug)]
struct SessionSignatureEntry {
    signature: String,
    message_count: usize,
}

impl<T> CacheEntry<T> {
    fn new(data: T) -> Self {
        Self {
            data,
            timestamp: SystemTime::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.timestamp.elapsed().unwrap_or(Duration::ZERO) > SIGNATURE_TTL
    }
}

fn enforce_cache_limit<K, T>(
    cache: &mut HashMap<K, CacheEntry<T>>,
    limit: usize,
    cache_name: &str,
    log_level_info: bool,
) where
    K: Eq + Hash + Clone,
{
    if cache.len() <= limit {
        return;
    }

    let before = cache.len();
    cache.retain(|_, entry| !entry.is_expired());

    if cache.len() > limit {
        let now = SystemTime::now();
        let mut oldest_first: Vec<(K, Duration)> = cache
            .iter()
            .map(|(k, entry)| {
                (
                    k.clone(),
                    now.duration_since(entry.timestamp)
                        .unwrap_or(Duration::ZERO),
                )
            })
            .collect();
        oldest_first.sort_by(|a, b| b.1.cmp(&a.1));

        let to_remove = cache.len() - limit;
        for (key, _) in oldest_first.into_iter().take(to_remove) {
            cache.remove(&key);
        }
    }

    let after = cache.len();
    if before != after {
        if log_level_info {
            tracing::info!(
                "[SignatureCache] {} cleanup: {} -> {} entries (limit: {})",
                cache_name,
                before,
                after,
                limit
            );
        } else {
            tracing::debug!(
                "[SignatureCache] {} cleanup: {} -> {} entries (limit: {})",
                cache_name,
                before,
                after,
                limit
            );
        }
    }
}

pub struct SignatureCache {
    tool_signatures: Mutex<HashMap<String, CacheEntry<String>>>,
    thinking_families: Mutex<HashMap<String, CacheEntry<String>>>,
    session_signatures: Mutex<HashMap<String, CacheEntry<SessionSignatureEntry>>>,
}

impl SignatureCache {
    fn new() -> Self {
        Self {
            tool_signatures: Mutex::new(HashMap::new()),
            thinking_families: Mutex::new(HashMap::new()),
            session_signatures: Mutex::new(HashMap::new()),
        }
    }
    pub fn global() -> &'static SignatureCache {
        static INSTANCE: OnceLock<SignatureCache> = OnceLock::new();
        INSTANCE.get_or_init(SignatureCache::new)
    }
    pub fn cache_tool_signature(&self, tool_use_id: &str, signature: String) {
        if signature.len() < MIN_SIGNATURE_LENGTH {
            return;
        }

        if let Ok(mut cache) = self.tool_signatures.lock() {
            tracing::debug!(
                "[SignatureCache] Caching tool signature for id: {}",
                tool_use_id
            );
            cache.insert(tool_use_id.to_string(), CacheEntry::new(signature));
            enforce_cache_limit(&mut cache, TOOL_CACHE_LIMIT, "Tool cache", false);
        }
    }
    pub fn get_tool_signature(&self, tool_use_id: &str) -> Option<String> {
        if let Ok(cache) = self.tool_signatures.lock() {
            if let Some(entry) = cache.get(tool_use_id) {
                if !entry.is_expired() {
                    tracing::debug!(
                        "[SignatureCache] Hit tool signature for id: {}",
                        tool_use_id
                    );
                    return Some(entry.data.clone());
                }
            }
        }
        None
    }
    pub fn cache_thinking_family(&self, signature: String, family: String) {
        if signature.len() < MIN_SIGNATURE_LENGTH {
            return;
        }

        if let Ok(mut cache) = self.thinking_families.lock() {
            tracing::debug!(
                "[SignatureCache] Caching thinking family for sig (len={}): {}",
                signature.len(),
                family
            );
            cache.insert(signature, CacheEntry::new(family));
            enforce_cache_limit(&mut cache, FAMILY_CACHE_LIMIT, "Family cache", false);
        }
    }
    pub fn get_signature_family(&self, signature: &str) -> Option<String> {
        if let Ok(cache) = self.thinking_families.lock() {
            if let Some(entry) = cache.get(signature) {
                if !entry.is_expired() {
                    return Some(entry.data.clone());
                } else {
                    tracing::debug!("[SignatureCache] Signature family entry expired");
                }
            }
        }
        None
    }
    pub fn cache_session_signature(
        &self,
        session_id: &str,
        signature: String,
        message_count: usize,
    ) {
        if signature.len() < MIN_SIGNATURE_LENGTH {
            return;
        }

        if let Ok(mut cache) = self.session_signatures.lock() {
            let should_store = match cache.get(session_id) {
                None => true,
                Some(existing) => {
                    if existing.is_expired() {
                        true
                    } else if message_count < existing.data.message_count {
                        tracing::info!(
                            "[SignatureCache] Rewind detected for {}: {} -> {} messages. Forcing signature update.",
                            session_id,
                            existing.data.message_count,
                            message_count
                        );
                        true
                    } else if message_count == existing.data.message_count {
                        signature.len() > existing.data.signature.len()
                    } else {
                        true
                    }
                }
            };

            if should_store {
                tracing::debug!(
                    "[SignatureCache] Session {} (msg_count={}) -> storing signature (len={})",
                    session_id,
                    message_count,
                    signature.len()
                );
                cache.insert(
                    session_id.to_string(),
                    CacheEntry::new(SessionSignatureEntry {
                        signature,
                        message_count,
                    }),
                );
            }
            enforce_cache_limit(&mut cache, SESSION_CACHE_LIMIT, "Session cache", true);
        }
    }
    pub fn get_session_signature(&self, session_id: &str) -> Option<String> {
        if let Ok(cache) = self.session_signatures.lock() {
            if let Some(entry) = cache.get(session_id) {
                if !entry.is_expired() {
                    tracing::debug!(
                        "[SignatureCache] Session {} -> HIT (len={})",
                        session_id,
                        entry.data.signature.len()
                    );
                    return Some(entry.data.signature.clone());
                } else {
                    tracing::debug!("[SignatureCache] Session {} -> EXPIRED", session_id);
                }
            }
        }
        None
    }
    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut cache) = self.tool_signatures.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.thinking_families.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.session_signatures.lock() {
            cache.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_signature_cache() {
        let cache = SignatureCache::new();
        let sig = "x".repeat(60);

        cache.cache_tool_signature("tool_1", sig.clone());
        assert_eq!(cache.get_tool_signature("tool_1"), Some(sig));
        assert_eq!(cache.get_tool_signature("tool_2"), None);
    }

    #[test]
    fn test_min_length() {
        let cache = SignatureCache::new();
        cache.cache_tool_signature("tool_short", "short".to_string());
        assert_eq!(cache.get_tool_signature("tool_short"), None);
    }

    #[test]
    fn test_thinking_family() {
        let cache = SignatureCache::new();
        let sig = "y".repeat(60);

        cache.cache_thinking_family(sig.clone(), "claude".to_string());
        assert_eq!(cache.get_signature_family(&sig), Some("claude".to_string()));
    }

    #[test]
    fn test_session_signature() {
        let cache = SignatureCache::new();
        let sig1 = "a".repeat(60);
        let sig2 = "b".repeat(80);
        let sig3 = "c".repeat(40);
        assert!(cache.get_session_signature("sid-test123").is_none());
        cache.cache_session_signature("sid-test123", sig1.clone(), 5);
        assert_eq!(
            cache.get_session_signature("sid-test123"),
            Some(sig1.clone())
        );
        cache.cache_session_signature("sid-test123", sig2.clone(), 5);
        assert_eq!(
            cache.get_session_signature("sid-test123"),
            Some(sig2.clone())
        );
        cache.cache_session_signature("sid-test123", sig1.clone(), 5);
        assert_eq!(
            cache.get_session_signature("sid-test123"),
            Some(sig2.clone())
        );
        cache.cache_session_signature("sid-test123", sig1.clone(), 3);
        assert_eq!(
            cache.get_session_signature("sid-test123"),
            Some(sig1.clone())
        );
        cache.cache_session_signature("sid-test123", sig3, 1);
        assert_eq!(cache.get_session_signature("sid-test123"), Some(sig1));
        assert!(cache.get_session_signature("sid-other").is_none());
    }

    #[test]
    fn test_clear_all_caches() {
        let cache = SignatureCache::new();
        let sig = "x".repeat(60);

        cache.cache_tool_signature("tool_1", sig.clone());
        cache.cache_thinking_family(sig.clone(), "model".to_string());
        cache.cache_session_signature("sid-1", sig.clone(), 1);

        assert!(cache.get_tool_signature("tool_1").is_some());
        assert!(cache.get_signature_family(&sig).is_some());
        assert!(cache.get_session_signature("sid-1").is_some());

        cache.clear();

        assert!(cache.get_tool_signature("tool_1").is_none());
        assert!(cache.get_signature_family(&sig).is_none());
        assert!(cache.get_session_signature("sid-1").is_none());
    }

    #[test]
    fn test_cache_limits_are_enforced_even_without_expiry() {
        let cache = SignatureCache::new();

        for i in 0..(TOOL_CACHE_LIMIT + 50) {
            cache.cache_tool_signature(
                &format!("tool-{}", i),
                format!("sig-tool-{}-{}", i, "x".repeat(60)),
            );
        }
        let tool_len = cache.tool_signatures.lock().expect("tool cache lock").len();
        assert!(tool_len <= TOOL_CACHE_LIMIT);

        for i in 0..(FAMILY_CACHE_LIMIT + 50) {
            cache.cache_thinking_family(
                format!("sig-family-{}-{}", i, "y".repeat(60)),
                "claude".to_string(),
            );
        }
        let family_len = cache
            .thinking_families
            .lock()
            .expect("family cache lock")
            .len();
        assert!(family_len <= FAMILY_CACHE_LIMIT);

        for i in 0..(SESSION_CACHE_LIMIT + 50) {
            cache.cache_session_signature(
                &format!("sid-{}", i),
                format!("sig-session-{}-{}", i, "z".repeat(60)),
                i,
            );
        }
        let session_len = cache
            .session_signatures
            .lock()
            .expect("session cache lock")
            .len();
        assert!(session_len <= SESSION_CACHE_LIMIT);
    }
}