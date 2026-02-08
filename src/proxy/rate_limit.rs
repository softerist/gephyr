use dashmap::DashMap;
use regex::Regex;
use std::time::{Duration, SystemTime};
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RateLimitReason {
    QuotaExhausted,
    RateLimitExceeded,
    ModelCapacityExhausted,
    ServerError,
    Unknown,
}
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub reset_time: SystemTime,
    #[allow(dead_code)]
    pub retry_after_sec: u64,
    #[allow(dead_code)]
    pub detected_at: SystemTime,
    #[allow(dead_code)]
    pub reason: RateLimitReason,
    #[allow(dead_code)]
    pub model: Option<String>,
}
const FAILURE_COUNT_EXPIRY_SECONDS: u64 = 3600;
pub struct RateLimitTracker {
    limits: DashMap<String, RateLimitInfo>,
    failure_counts: DashMap<String, (u32, SystemTime)>,
}

impl RateLimitTracker {
    pub fn new() -> Self {
        Self {
            limits: DashMap::new(),
            failure_counts: DashMap::new(),
        }
    }
    fn get_limit_key(&self, account_id: &str, model: Option<&str>) -> String {
        match model {
            Some(m) if !m.is_empty() => format!("{}:{}", account_id, m),
            _ => account_id.to_string(),
        }
    }
    pub fn get_remaining_wait(&self, account_id: &str, model: Option<&str>) -> u64 {
        let now = SystemTime::now();
        if let Some(info) = self.limits.get(account_id) {
            if info.reset_time > now {
                return info
                    .reset_time
                    .duration_since(now)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();
            }
        }
        if let Some(m) = model {
            let key = self.get_limit_key(account_id, Some(m));
            if let Some(info) = self.limits.get(&key) {
                if info.reset_time > now {
                    return info
                        .reset_time
                        .duration_since(now)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs();
                }
            }
        }

        0
    }
    pub fn mark_success(&self, account_id: &str) {
        if self.failure_counts.remove(account_id).is_some() {
            tracing::debug!(
                "Account {} request successful, failure count reset",
                account_id
            );
        }
        self.limits.remove(account_id);
    }
    pub fn set_lockout_until(
        &self,
        account_id: &str,
        reset_time: SystemTime,
        reason: RateLimitReason,
        model: Option<String>,
    ) {
        let now = SystemTime::now();
        let retry_sec = reset_time
            .duration_since(now)
            .map(|d| d.as_secs())
            .unwrap_or(60);

        let info = RateLimitInfo {
            reset_time,
            retry_after_sec: retry_sec,
            detected_at: now,
            reason,
            model: model.clone(),
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
    pub fn set_lockout_until_iso(
        &self,
        account_id: &str,
        reset_time_str: &str,
        reason: RateLimitReason,
        model: Option<String>,
    ) -> bool {
        match chrono::DateTime::parse_from_rfc3339(reset_time_str) {
            Ok(dt) => {
                let reset_time =
                    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(dt.timestamp() as u64);
                self.set_lockout_until(account_id, reset_time, reason, model);
                true
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to parse quota refresh time '{}': {}, falling back to default backoff strategy",
                    reset_time_str, e
                );
                false
            }
        }
    }
    pub fn parse_from_error(
        &self,
        account_id: &str,
        status: u16,
        retry_after_header: Option<&str>,
        body: &str,
        model: Option<String>,
        backoff_steps: &[u64],
    ) -> Option<RateLimitInfo> {
        if status != 429 && status != 500 && status != 503 && status != 529 {
            return None;
        }
        let reason = if status == 429 {
            tracing::warn!("Google 429 Error Body: {}", body);
            self.parse_rate_limit_reason(body)
        } else {
            RateLimitReason::ServerError
        };

        let mut retry_after_sec = None;
        if let Some(retry_after) = retry_after_header {
            if let Ok(seconds) = retry_after.parse::<u64>() {
                retry_after_sec = Some(seconds);
            }
        }
        if retry_after_sec.is_none() {
            retry_after_sec = self.parse_retry_time_from_body(body);
        }
        let retry_sec = match retry_after_sec {
            Some(s) => {
                if s < 2 {
                    2
                } else {
                    s
                }
            }
            None => {
                let failure_count = if reason != RateLimitReason::ServerError {
                    let now = SystemTime::now();
                    let mut entry = self
                        .failure_counts
                        .entry(account_id.to_string())
                        .or_insert((0, now));

                    let elapsed = now
                        .duration_since(entry.1)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs();
                    if elapsed > FAILURE_COUNT_EXPIRY_SECONDS {
                        tracing::debug!(
                            "Account {} failure count expired ({}s), resetting to 0",
                            account_id,
                            elapsed
                        );
                        *entry = (0, now);
                    }
                    entry.0 += 1;
                    entry.1 = now;
                    entry.0
                } else {
                    1
                };

                match reason {
                    RateLimitReason::QuotaExhausted => {
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
                    }
                    RateLimitReason::RateLimitExceeded => {
                        tracing::debug!(
                            "Rate limit exceeded (RATE_LIMIT_EXCEEDED) detected, using default 5s"
                        );
                        5
                    }
                    RateLimitReason::ModelCapacityExhausted => {
                        let lockout = match failure_count {
                            1 => 5,
                            2 => 10,
                            _ => 15,
                        };
                        tracing::warn!("Model capacity exhausted (MODEL_CAPACITY_EXHAUSTED) detected, failure #{}, retrying in {}s", failure_count, lockout);
                        lockout
                    }
                    RateLimitReason::ServerError => {
                        tracing::warn!(
                            "ServerError (5xx) detected ({}), performing 8s soft avoidance...",
                            status
                        );
                        8
                    }
                    RateLimitReason::Unknown => {
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
        let use_model_key = matches!(reason, RateLimitReason::QuotaExhausted) && model.is_some();
        let key = if use_model_key {
            self.get_limit_key(account_id, model.as_deref())
        } else {
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
    fn parse_rate_limit_reason(&self, body: &str) -> RateLimitReason {
        let trimmed = body.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(reason_str) = json
                    .get("error")
                    .and_then(|e| e.get("details"))
                    .and_then(|d| d.as_array())
                    .and_then(|a| a.first())
                    .and_then(|o| o.get("reason"))
                    .and_then(|v| v.as_str())
                {
                    return match reason_str {
                        "QUOTA_EXHAUSTED" => RateLimitReason::QuotaExhausted,
                        "RATE_LIMIT_EXCEEDED" => RateLimitReason::RateLimitExceeded,
                        "MODEL_CAPACITY_EXHAUSTED" => RateLimitReason::ModelCapacityExhausted,
                        _ => RateLimitReason::Unknown,
                    };
                }
                if let Some(msg) = json
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|v| v.as_str())
                {
                    let msg_lower = msg.to_lowercase();
                    if msg_lower.contains("per minute") || msg_lower.contains("rate limit") {
                        return RateLimitReason::RateLimitExceeded;
                    }
                }
            }
        }
        let body_lower = body.to_lowercase();
        if body_lower.contains("per minute")
            || body_lower.contains("rate limit")
            || body_lower.contains("too many requests")
        {
            RateLimitReason::RateLimitExceeded
        } else if body_lower.contains("exhausted") || body_lower.contains("quota") {
            RateLimitReason::QuotaExhausted
        } else {
            RateLimitReason::Unknown
        }
    }
    fn parse_duration_string(&self, s: &str) -> Option<u64> {
        tracing::debug!("[Duration Parsing] Attempting to parse: '{}'", s);
        let re = Regex::new(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?")
            .ok()?;
        let caps = match re.captures(s) {
            Some(c) => c,
            None => {
                tracing::warn!("[Duration Parsing] Regex no match: '{}'", s);
                return None;
            }
        };

        let hours = caps
            .get(1)
            .and_then(|m| m.as_str().parse::<u64>().ok())
            .unwrap_or(0);
        let minutes = caps
            .get(2)
            .and_then(|m| m.as_str().parse::<u64>().ok())
            .unwrap_or(0);
        let seconds = caps
            .get(3)
            .and_then(|m| m.as_str().parse::<f64>().ok())
            .unwrap_or(0.0);
        let milliseconds = caps
            .get(4)
            .and_then(|m| m.as_str().parse::<f64>().ok())
            .unwrap_or(0.0);

        tracing::debug!(
            "[Duration Parsing] Extraction result: {}h {}m {:.3}s {:.3}ms",
            hours,
            minutes,
            seconds,
            milliseconds
        );
        let total_seconds = hours * 3600
            + minutes * 60
            + seconds.ceil() as u64
            + (milliseconds / 1000.0).ceil() as u64;
        if total_seconds == 0 {
            tracing::warn!("[Duration Parsing] Failed: '{}' (total seconds is 0)", s);
            None
        } else {
            tracing::info!(
                "[Duration Parsing] ✓ Success: '{}' => {} seconds ({}h {}m {:.1}s {:.1}ms)",
                s,
                total_seconds,
                hours,
                minutes,
                seconds,
                milliseconds
            );
            Some(total_seconds)
        }
    }
    fn parse_retry_time_from_body(&self, body: &str) -> Option<u64> {
        let trimmed = body.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(delay_str) = json
                    .get("error")
                    .and_then(|e| e.get("details"))
                    .and_then(|d| d.as_array())
                    .and_then(|a| a.first())
                    .and_then(|o| o.get("metadata"))
                    .and_then(|m| m.get("quotaResetDelay"))
                    .and_then(|v| v.as_str())
                {
                    tracing::debug!("[JSON Parsing] Found quotaResetDelay: '{}'", delay_str);
                    if let Some(seconds) = self.parse_duration_string(delay_str) {
                        return Some(seconds);
                    }
                }
                if let Some(retry) = json
                    .get("error")
                    .and_then(|e| e.get("retry_after"))
                    .and_then(|v| v.as_u64())
                {
                    return Some(retry);
                }
            }
        }
        if let Ok(re) = Regex::new(r"(?i)try again in (\d+)m\s*(\d+)s") {
            if let Some(caps) = re.captures(body) {
                if let (Ok(m), Ok(s)) = (caps[1].parse::<u64>(), caps[2].parse::<u64>()) {
                    return Some(m * 60 + s);
                }
            }
        }
        if let Ok(re) = Regex::new(r"(?i)(?:try again in|backoff for|wait)\s*(\d+)s") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }
        if let Ok(re) = Regex::new(r"(?i)quota will reset in (\d+) second") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }
        if let Ok(re) = Regex::new(r"(?i)retry after (\d+) second") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }
        if let Ok(re) = Regex::new(r"\(wait (\d+)s\)") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }

        None
    }
    pub fn get(&self, account_id: &str) -> Option<RateLimitInfo> {
        self.limits.get(account_id).map(|r| r.clone())
    }
    pub fn is_rate_limited(&self, account_id: &str, model: Option<&str>) -> bool {
        self.get_remaining_wait(account_id, model) > 0
    }
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
    pub fn clear(&self, account_id: &str) -> bool {
        self.limits.remove(account_id).is_some()
    }
    pub fn clear_all(&self) {
        let count = self.limits.len();
        self.limits.clear();
        tracing::warn!(
            "🔄 Optimistic reset: Cleared all {} rate limit record(s)",
            count
        );
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
        tracker.parse_from_error("acc1", 429, Some("1"), "", None, &[]);
        let wait = tracker.get_remaining_wait("acc1", None);
        assert!(wait >= 1 && wait <= 2);
    }

    #[test]
    fn test_tpm_exhausted_is_rate_limit_exceeded() {
        let tracker = RateLimitTracker::new();
        let body = "Resource has been exhausted (e.g. check quota). Quota limit 'Tokens per minute' exceeded.";
        let reason = tracker.parse_rate_limit_reason(body);
        assert_eq!(reason, RateLimitReason::RateLimitExceeded);
    }

    #[test]
    fn test_server_error_does_not_accumulate_failure_count() {
        let tracker = RateLimitTracker::new();
        let backoff_steps = vec![60, 300, 1800, 7200];
        for i in 1..=5 {
            let info = tracker.parse_from_error(
                "acc1",
                503,
                None,
                "Service Unavailable",
                None,
                &backoff_steps,
            );
            assert!(
                info.is_some(),
                "5xx attempt #{} should return RateLimitInfo",
                i
            );
            let info = info.unwrap();
            assert_eq!(
                info.retry_after_sec, 8,
                "5xx attempt #{} should lock for 8 seconds",
                i
            );
        }
        let quota_body = r#"{"error":{"details":[{"reason":"QUOTA_EXHAUSTED"}]}}"#;
        let info = tracker.parse_from_error("acc1", 429, None, quota_body, None, &backoff_steps);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(
            info.retry_after_sec, 60,
            "429 should start from backoff #1 (60s), not be polluted by 5xx"
        );
    }

    #[test]
    fn test_quota_exhausted_does_accumulate_failure_count() {
        let tracker = RateLimitTracker::new();
        let backoff_steps = vec![60, 300, 1800, 7200];
        let quota_body = r#"{"error":{"details":[{"reason":"QUOTA_EXHAUSTED"}]}}"#;
        let info = tracker.parse_from_error("acc2", 429, None, quota_body, None, &backoff_steps);
        assert_eq!(info.unwrap().retry_after_sec, 60);
        let info = tracker.parse_from_error("acc2", 429, None, quota_body, None, &backoff_steps);
        assert_eq!(info.unwrap().retry_after_sec, 300);
        let info = tracker.parse_from_error("acc2", 429, None, quota_body, None, &backoff_steps);
        assert_eq!(info.unwrap().retry_after_sec, 1800);
        let info = tracker.parse_from_error("acc2", 429, None, quota_body, None, &backoff_steps);
        assert_eq!(info.unwrap().retry_after_sec, 7200);
    }
}
