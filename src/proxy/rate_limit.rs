use dashmap::DashMap;
use std::time::{SystemTime, Duration};
use regex::Regex;

// Rate limit reason type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RateLimitReason {
    // Quota exhausted (QUOTA_EXHAUSTED)
    QuotaExhausted,
    // Rate limit exceeded (RATE_LIMIT_EXCEEDED)
    RateLimitExceeded,
    // Model capacity exhausted (MODEL_CAPACITY_EXHAUSTED)
    ModelCapacityExhausted,
    // Server error (5xx)
    ServerError,
    // Unknown reason
    Unknown,
}

// Rate limit information
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    // Rate limit reset time
    pub reset_time: SystemTime,
    // Retry interval (seconds)
    #[allow(dead_code)]
    pub retry_after_sec: u64,
    // Detection time
    #[allow(dead_code)]
    pub detected_at: SystemTime,
    // Rate limit reason
    #[allow(dead_code)] // Used for logging and diagnostics
    pub reason: RateLimitReason,
    // Associated model (for model-level rate limiting)
    // None means account-level rate limiting, Some(model) means specific model rate limiting
    #[allow(dead_code)] // Used for model-level rate limiting
    pub model: Option<String>,
}

// Failure count expiry time: 1 hour (reset count if no failure within this time)
const FAILURE_COUNT_EXPIRY_SECONDS: u64 = 3600;

// Rate limit tracker
pub struct RateLimitTracker {
    limits: DashMap<String, RateLimitInfo>,
    // Consecutive failure count (for intelligent exponential backoff), with timestamp for automatic expiration
    failure_counts: DashMap<String, (u32, SystemTime)>,
}

impl RateLimitTracker {
    pub fn new() -> Self {
        Self {
            limits: DashMap::new(),
            failure_counts: DashMap::new(),
        }
    }
    
    // Generate rate limit Key
    // - Account level: "account_id"
    // - Model level: "account_id:model_id"
    fn get_limit_key(&self, account_id: &str, model: Option<&str>) -> String {
        match model {
            Some(m) if !m.is_empty() => format!("{}:{}", account_id, m),
            _ => account_id.to_string(),
        }
    }

    // Get remaining wait time for account (seconds)
    // Supports checking both account-level and model-level locks
    pub fn get_remaining_wait(&self, account_id: &str, model: Option<&str>) -> u64 {
        let now = SystemTime::now();
        
        // 1. Check global account lock
        if let Some(info) = self.limits.get(account_id) {
            if info.reset_time > now {
                return info.reset_time.duration_since(now).unwrap_or(Duration::from_secs(0)).as_secs();
            }
        }

        // 2. If model is specified, check model-level lock
        if let Some(m) = model {
             let key = self.get_limit_key(account_id, Some(m));
             if let Some(info) = self.limits.get(&key) {
                 if info.reset_time > now {
                     return info.reset_time.duration_since(now).unwrap_or(Duration::from_secs(0)).as_secs();
                 }
             }
        }

        0
    }
    
    // Mark account request as successful, reset consecutive failure count
    // 
    // This method is called when an account successfully completes a request,
    // resetting its failure count to zero, so requested failures start from the
    // shortest lockout time (60 seconds).
    pub fn mark_success(&self, account_id: &str) {
        if self.failure_counts.remove(account_id).is_some() {
            tracing::debug!("Account {} request successful, failure count reset", account_id);
        }
        // Clear account-level rate limit
        self.limits.remove(account_id);
        // Note: We currently cannot clear all model-level locks for this account as we don't know which models are locked
        // unless we iterate through limits. Considering model-level locks are usually QuotaExhausted, letting them expire naturally is acceptable.
        // Or we could introduce an index, but for simplicity, we only clear Account-level locks for now.
    }
    
    // Precisely lock the account until a specific point in time
    // 
    // Uses the reset_time from the account quota to precisely lock the account,
    // which is more accurate than exponential backoff.
    // 
    // # Parameters
    // - `model`: Optional model name for model-level rate limiting. None means account-level rate limit.
    pub fn set_lockout_until(&self, account_id: &str, reset_time: SystemTime, reason: RateLimitReason, model: Option<String>) {
        let now = SystemTime::now();
        let retry_sec = reset_time
            .duration_since(now)
            .map(|d| d.as_secs())
            .unwrap_or(60); // If time has passed, use default 60 seconds
        
        let info = RateLimitInfo {
            reset_time,
            retry_after_sec: retry_sec,
            detected_at: now,
            reason,
            model: model.clone(),  //  Support model-level rate limiting
        };
        
        let key = self.get_limit_key(account_id, model.as_deref());
        self.limits.insert(key, info);
        
        if let Some(m) = &model {
            tracing::info!(
                "Account {} model {} precisely locked until quota refresh, {} seconds remaining",
                account_id,
                m,
                retry_sec
            );
        } else {
            tracing::info!(
                "Account {} precisely locked until quota refresh, {} seconds remaining",
                account_id,
                retry_sec
            );
        }
    }
    
    // Precisely lock account using ISO 8601 time string
    // 
    // Parses time strings like "2026-01-08T17:00:00Z"
    // 
    // # Parameters
    // - `model`: Optional model name for model-level rate limiting
    pub fn set_lockout_until_iso(&self, account_id: &str, reset_time_str: &str, reason: RateLimitReason, model: Option<String>) -> bool {
        // Try parsing ISO 8601 format
        match chrono::DateTime::parse_from_rfc3339(reset_time_str) {
            Ok(dt) => {
                let reset_time = SystemTime::UNIX_EPOCH + 
                    std::time::Duration::from_secs(dt.timestamp() as u64);
                self.set_lockout_until(account_id, reset_time, reason, model);
                true
            },
            Err(e) => {
                tracing::warn!(
                    "Failed to parse quota refresh time '{}': {}, falling back to default backoff strategy",
                    reset_time_str, e
                );
                false
            }
        }
    }
    
    // Parse rate limit information from error response
    // 
    // # Arguments
    // * `account_id` - Account ID
    // * `status` - HTTP status code
    // * `retry_after_header` - Retry-After header value
    // * `body` - Error response body
    pub fn parse_from_error(
        &self,
        account_id: &str,
        status: u16,
        retry_after_header: Option<&str>,
        body: &str,
        model: Option<String>,
        backoff_steps: &[u64], //  Pass in backoff configuration
    ) -> Option<RateLimitInfo> {
        // Support 429 (rate limit) and 500/503/529 (backend failure soft avoidance)
        if status != 429 && status != 500 && status != 503 && status != 529 {
            return None;
        }
        
        // 1. Parse rate limit reason type
        let reason = if status == 429 {
            tracing::warn!("Google 429 Error Body: {}", body);
            self.parse_rate_limit_reason(body)
        } else {
            RateLimitReason::ServerError
        };
        
        let mut retry_after_sec = None;
        
        // 2. Extract from Retry-After header
        if let Some(retry_after) = retry_after_header {
            if let Ok(seconds) = retry_after.parse::<u64>() {
                retry_after_sec = Some(seconds);
            }
        }
        
        // 3. Extract from error message (prioritize JSON parsing, then regex)
        if retry_after_sec.is_none() {
            retry_after_sec = self.parse_retry_time_from_body(body);
        }
        
        // 4. Handle default values and soft avoidance logic (set different default values according to rate limit type)
        let retry_sec = match retry_after_sec {
            Some(s) => {
                // Set safety buffer: minimum 2 seconds to prevent extremely high-frequency invalid retries
                if s < 2 { 2 } else { s }
            },
            None => {
                // Get consecutive failure count for exponential backoff (with automatic expiration logic)
                //  ServerError (5xx) does not accumulate failure_count to avoid polluting the backoff ladder for 429
                let failure_count = if reason != RateLimitReason::ServerError {
                    // Only non-ServerError accumulates failure count (used for exponential backoff)
                    let now = SystemTime::now();
                    // Here we use account_id as the key, regardless of the model,
                    // since this is intended to calculate backoff for consecutive "account-level" issues.
                    // If model-specific failure counts are needed, the failure_counts key would need to change.
                    // Keep account_id for now, so if a single model is consistently down, it also increases the count, which is logical.
                    let mut entry = self.failure_counts.entry(account_id.to_string()).or_insert((0, now));

                    let elapsed = now.duration_since(entry.1).unwrap_or(Duration::from_secs(0)).as_secs();
                    if elapsed > FAILURE_COUNT_EXPIRY_SECONDS {
                        tracing::debug!("Account {} failure count expired ({}s), resetting to 0", account_id, elapsed);
                        *entry = (0, now);
                    }
                    entry.0 += 1;
                    entry.1 = now;
                    entry.0
                } else {
                    // ServerError (5xx) uses a fixed value of 1, does not accumulate, to avoid polluting the 429 backoff ladder
                    1
                };
                
                match reason {
                    RateLimitReason::QuotaExhausted => {
                        // [Intelligent Rate Limiting] Calculate according to failure_count and configured backoff_steps
                        let index = (failure_count as usize).saturating_sub(1);
                        let lockout = if index < backoff_steps.len() {
                            backoff_steps[index]
                        } else {
                            *backoff_steps.last().unwrap_or(&7200)
                        };

                        tracing::warn!(
                            "Quota exhausted (QUOTA_EXHAUSTED) detected, {} consecutive failures, locking for {} seconds as configured", 
                            failure_count, lockout
                        );
                        lockout
                    },
                    RateLimitReason::RateLimitExceeded => {
                        // Rate limit (TPM/RPM)
                        tracing::debug!("Rate limit exceeded (RATE_LIMIT_EXCEEDED) detected, using default 5s");
                        5
                    },
                    RateLimitReason::ModelCapacityExhausted => {
                        // Model capacity exhausted
                        let lockout = match failure_count {
                            1 => 5,
                            2 => 10,
                            _ => 15,
                        };
                        tracing::warn!("Model capacity exhausted (MODEL_CAPACITY_EXHAUSTED) detected, failure #{}, retrying in {}s", failure_count, lockout);
                        lockout
                    },
                    RateLimitReason::ServerError => {
                        // 5xx error
                        tracing::warn!("ServerError (5xx) detected ({}), performing 8s soft avoidance...", status);
                        8
                    },
                    RateLimitReason::Unknown => {
                        // Unknown reason
                        tracing::debug!("Unable to parse 429 rate limit reason, using default 60s");
                        60
                    }
                }
            }
        };
        
        let info = RateLimitInfo {
            reset_time: SystemTime::now() + Duration::from_secs(retry_sec),
            retry_after_sec: retry_sec,
            detected_at: SystemTime::now(),
            reason,
            model: model.clone(),
        };
        
        //  Use compound Key for storage (if Quota and has Model)
        // Only QuotaExhausted is suitable for model isolation; others like RateLimitExceeded are typically account-wide TPM
        let use_model_key = matches!(reason, RateLimitReason::QuotaExhausted) && model.is_some();
        let key = if use_model_key { 
            self.get_limit_key(account_id, model.as_deref())
        } else {
            // Other cases (e.g., RateLimitExceeded, ServerError) typically affect the entire account
            // Or we could decide whether to isolate based on configuration.
            // For simplicity, only QuotaExhausted does fine-grained isolation.
            account_id.to_string()
        };

        self.limits.insert(key, info.clone());
        
        tracing::warn!(
            "Account {} [{}] Rate Limit Type: {:?}, Reset Delay: {}s",
            account_id,
            status,
            reason,
            retry_sec
        );
        
        Some(info)
    }
    
    // Parse rate limit reason type
    fn parse_rate_limit_reason(&self, body: &str) -> RateLimitReason {
        // Try to extract reason field from JSON
        let trimmed = body.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(reason_str) = json.get("error")
                    .and_then(|e| e.get("details"))
                    .and_then(|d| d.as_array())
                    .and_then(|a| a.get(0))
                    .and_then(|o| o.get("reason"))
                    .and_then(|v| v.as_str()) {
                    
                    return match reason_str {
                        "QUOTA_EXHAUSTED" => RateLimitReason::QuotaExhausted,
                        "RATE_LIMIT_EXCEEDED" => RateLimitReason::RateLimitExceeded,
                        "MODEL_CAPACITY_EXHAUSTED" => RateLimitReason::ModelCapacityExhausted,
                        _ => RateLimitReason::Unknown,
                    };
                }
                //  Try text matching from message field (prevent missed reason)
                 if let Some(msg) = json.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|v| v.as_str()) {
                    let msg_lower = msg.to_lowercase();
                    if msg_lower.contains("per minute") || msg_lower.contains("rate limit") {
                        return RateLimitReason::RateLimitExceeded;
                    }
                 }
            }
        }
        
        // If cannot parse from JSON, try determining from message text
        let body_lower = body.to_lowercase();
        //  Prioritize minute-level limits to avoid misjudging TPM as Quota
        if body_lower.contains("per minute") || body_lower.contains("rate limit") || body_lower.contains("too many requests") {
             RateLimitReason::RateLimitExceeded
        } else if body_lower.contains("exhausted") || body_lower.contains("quota") {
            RateLimitReason::QuotaExhausted
        } else {
            RateLimitReason::Unknown
        }
    }
    
    // Generic duration parsing function: supports all format combinations like "2h1m1s"
    fn parse_duration_string(&self, s: &str) -> Option<u64> {
        tracing::debug!("[Duration Parsing] Attempting to parse: '{}'", s);

        // Use regex to extract hours, minutes, seconds, and milliseconds
        // Supported formats: "2h1m1s", "1h30m", "5m", "30s", "500ms", "510.790006ms", etc.
        //  Modify ms part to support decimals: (\d+)ms -> (\d+(?:\.\d+)?)ms
        let re = Regex::new(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?").ok()?;
        let caps = match re.captures(s) {
            Some(c) => c,
            None => {
                tracing::warn!("[Duration Parsing] Regex no match: '{}'", s);
                return None;
            }
        };

        let hours = caps.get(1)
            .and_then(|m| m.as_str().parse::<u64>().ok())
            .unwrap_or(0);
        let minutes = caps.get(2)
            .and_then(|m| m.as_str().parse::<u64>().ok())
            .unwrap_or(0);
        let seconds = caps.get(3)
            .and_then(|m| m.as_str().parse::<f64>().ok())
            .unwrap_or(0.0);
        //  Milliseconds also support decimal parsing
        let milliseconds = caps.get(4)
            .and_then(|m| m.as_str().parse::<f64>().ok())
            .unwrap_or(0.0);

        tracing::debug!("[Duration Parsing] Extraction result: {}h {}m {:.3}s {:.3}ms", hours, minutes, seconds, milliseconds);

        //  Calculate total seconds, round up the millisecond part
        let total_seconds = hours * 3600 + minutes * 60 + seconds.ceil() as u64 + (milliseconds / 1000.0).ceil() as u64;

        // If total seconds is 0, parsing failed
        if total_seconds == 0 {
            tracing::warn!("[Duration Parsing] Failed: '{}' (total seconds is 0)", s);
            None
        } else {
            tracing::info!("[Duration Parsing] ✓ Success: '{}' => {} seconds ({}h {}m {:.1}s {:.1}ms)",
                s, total_seconds, hours, minutes, seconds, milliseconds);
            Some(total_seconds)
        }
    }
    
    // Parse reset time from error message body
    fn parse_retry_time_from_body(&self, body: &str) -> Option<u64> {
        // A. Prioritize precise JSON parsing
        let trimmed = body.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
                // 1. Common Google quotaResetDelay format (supports all formats: "2h1m1s", "1h30m", "42s", "500ms", etc.)
                // Path: error.details[0].metadata.quotaResetDelay
                if let Some(delay_str) = json.get("error")
                    .and_then(|e| e.get("details"))
                    .and_then(|d| d.as_array())
                    .and_then(|a| a.get(0))
                    .and_then(|o| o.get("metadata"))  // Add metadata level
                    .and_then(|m| m.get("quotaResetDelay"))
                    .and_then(|v| v.as_str()) {
                    
                    tracing::debug!("[JSON Parsing] Found quotaResetDelay: '{}'", delay_str);
                    
                    // Use generic duration parsing function
                    if let Some(seconds) = self.parse_duration_string(delay_str) {
                        return Some(seconds);
                    }
                }
                
                // 2. Common OpenAI retry_after field (number)
                if let Some(retry) = json.get("error")
                    .and_then(|e| e.get("retry_after"))
                    .and_then(|v| v.as_u64()) {
                    return Some(retry);
                }
            }
        }

        // B. Regex matching patterns (fallback)
        // Pattern 1: "Try again in 2m 30s"
        if let Ok(re) = Regex::new(r"(?i)try again in (\d+)m\s*(\d+)s") {
            if let Some(caps) = re.captures(body) {
                if let (Ok(m), Ok(s)) = (caps[1].parse::<u64>(), caps[2].parse::<u64>()) {
                    return Some(m * 60 + s);
                }
            }
        }
        
        // Pattern 2: "Try again in 30s" or "backoff for 42s"
        if let Ok(re) = Regex::new(r"(?i)(?:try again in|backoff for|wait)\s*(\d+)s") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }
        
        // Pattern 3: "quota will reset in X seconds"
        if let Ok(re) = Regex::new(r"(?i)quota will reset in (\d+) second") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }
        
        // Pattern 4: OpenAI style "Retry after (\d+) seconds"
        if let Ok(re) = Regex::new(r"(?i)retry after (\d+) second") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }

        // Pattern 5: Parentheses format "(wait (\d+)s)"
        if let Ok(re) = Regex::new(r"\(wait (\d+)s\)") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }
        
        None
    }
    
    // Get rate limit info for an account
    pub fn get(&self, account_id: &str) -> Option<RateLimitInfo> {
        self.limits.get(account_id).map(|r| r.clone())
    }
    
    // Check if account is still rate limited (supports model level)
    pub fn is_rate_limited(&self, account_id: &str, model: Option<&str>) -> bool {
        // Checking using get_remaining_wait which handles both global and model keys
        self.get_remaining_wait(account_id, model) > 0
    }
    
    // Get how many seconds until rate limit resets
    pub fn get_reset_seconds(&self, account_id: &str) -> Option<u64> {
        if let Some(info) = self.get(account_id) {
            info.reset_time
                .duration_since(SystemTime::now())
                .ok()
                .map(|d| d.as_secs())
        } else {
            None
        }
    }
    
    // Clear expired rate limit records
    #[allow(dead_code)]
    pub fn cleanup_expired(&self) -> usize {
        let now = SystemTime::now();
        let mut count = 0;
        
        self.limits.retain(|_k, v| {
            if v.reset_time <= now {
                count += 1;
                false
            } else {
                true
            }
        });
        
        if count > 0 {
            tracing::debug!("Cleared {} expired rate limit records", count);
        }
        
        count
    }
    
    // Clear rate limit record for a specific account
    pub fn clear(&self, account_id: &str) -> bool {
        self.limits.remove(account_id).is_some()
    }
    
    // Clear all rate limit records (optimistic reset strategy)
    // 
    // Used for optimistic reset mechanism when all accounts are rate limited but wait times are short,
    // clearing all rate limit records to resolve timing race conditions.
    pub fn clear_all(&self) {
        let count = self.limits.len();
        self.limits.clear();
        tracing::warn!("🔄 Optimistic reset: Cleared all {} rate limit record(s)", count);
    }
}

impl Default for RateLimitTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_retry_time_minutes_seconds() {
        let tracker = RateLimitTracker::new();
        let body = "Rate limit exceeded. Try again in 2m 30s";
        let time = tracker.parse_retry_time_from_body(body);
        assert_eq!(time, Some(150)); 
    }
    
    #[test]
    fn test_parse_google_json_delay() {
        let tracker = RateLimitTracker::new();
        let body = r#"{
            "error": {
                "details": [
                    { 
                        "metadata": {
                            "quotaResetDelay": "42s" 
                        }
                    }
                ]
            }
        }"#;
        let time = tracker.parse_retry_time_from_body(body);
        assert_eq!(time, Some(42));
    }

    #[test]
    fn test_parse_retry_after_ignore_case() {
        let tracker = RateLimitTracker::new();
        let body = "Quota limit hit. Retry After 99 Seconds";
        let time = tracker.parse_retry_time_from_body(body);
        assert_eq!(time, Some(99));
    }

    #[test]
    fn test_get_remaining_wait() {
        let tracker = RateLimitTracker::new();
        tracker.parse_from_error("acc1", 429, Some("30"), "", None, &[]);
        let wait = tracker.get_remaining_wait("acc1", None);
        assert!(wait > 25 && wait <= 30);
    }

    #[test]
    fn test_safety_buffer() {
        let tracker = RateLimitTracker::new();
        // If API returns 1s, we force it to 2s
        tracker.parse_from_error("acc1", 429, Some("1"), "", None, &[]);
        let wait = tracker.get_remaining_wait("acc1", None);
        // Due to time passing, it might be 1 or 2
        assert!(wait >= 1 && wait <= 2);
    }

    #[test]
    fn test_tpm_exhausted_is_rate_limit_exceeded() {
        let tracker = RateLimitTracker::new();
        // Simulate real-world TPM error containing both "Resource exhausted" and "per minute"
        let body = "Resource has been exhausted (e.g. check quota). Quota limit 'Tokens per minute' exceeded.";
        let reason = tracker.parse_rate_limit_reason(body);
        // Should be identified as RateLimitExceeded, not QuotaExhausted
        assert_eq!(reason, RateLimitReason::RateLimitExceeded);
    }

    #[test]
    fn test_server_error_does_not_accumulate_failure_count() {
        let tracker = RateLimitTracker::new();
        let backoff_steps = vec![60, 300, 1800, 7200];

        // Simulate 5 consecutive 5xx errors
        for i in 1..=5 {
            let info = tracker.parse_from_error("acc1", 503, None, "Service Unavailable", None, &backoff_steps);
            assert!(info.is_some(), "5xx attempt #{} should return RateLimitInfo", i);
            let info = info.unwrap();
            // 5xx should always lock for 8 seconds, unaffected by failure_count
            assert_eq!(info.retry_after_sec, 8, "5xx attempt #{} should lock for 8 seconds", i);
        }

        // Now trigger a 429 QuotaExhausted (without quotaResetDelay)
        let quota_body = r#"{"error":{"details":[{"reason":"QUOTA_EXHAUSTED"}]}}"#;
        let info = tracker.parse_from_error("acc1", 429, None, quota_body, None, &backoff_steps);
        assert!(info.is_some());
        let info = info.unwrap();

        // Key assertion: 429 should start from attempt #1 (lock 60s), not inherit the 5xx count
        assert_eq!(info.retry_after_sec, 60, "429 should start from backoff #1 (60s), not be polluted by 5xx");
    }

    #[test]
    fn test_quota_exhausted_does_accumulate_failure_count() {
        let tracker = RateLimitTracker::new();
        let backoff_steps = vec![60, 300, 1800, 7200];
        let quota_body = r#"{"error":{"details":[{"reason":"QUOTA_EXHAUSTED"}]}}"#;

        // #1 429 → 60s
        let info = tracker.parse_from_error("acc2", 429, None, quota_body, None, &backoff_steps);
        assert_eq!(info.unwrap().retry_after_sec, 60);

        // #2 429 → 300s
        let info = tracker.parse_from_error("acc2", 429, None, quota_body, None, &backoff_steps);
        assert_eq!(info.unwrap().retry_after_sec, 300);

        // #3 429 → 1800s
        let info = tracker.parse_from_error("acc2", 429, None, quota_body, None, &backoff_steps);
        assert_eq!(info.unwrap().retry_after_sec, 1800);

        // #4 429 → 7200s
        let info = tracker.parse_from_error("acc2", 429, None, quota_body, None, &backoff_steps);
        assert_eq!(info.unwrap().retry_after_sec, 7200);
    }
}
