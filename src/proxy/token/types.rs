use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProxyToken {
    pub account_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub timestamp: i64,
    pub email: String,
    pub account_path: PathBuf, // Account file path, used for updates
    pub project_id: Option<String>,
    pub subscription_tier: Option<String>, // "FREE" | "PRO" | "ULTRA"
    pub remaining_quota: Option<i32>, // Remaining quota for priority sorting
    pub protected_models: HashSet<String>,
    pub health_score: f32, // Health score (0.0 - 1.0)
    pub reset_time: Option<i64>, // Quota reset timestamp (for sorting optimization)
    pub validation_blocked: bool, // Check for validation block (VALIDATION_REQUIRED temporary block)
    pub validation_blocked_until: i64, // Timestamp until which the account is blocked
    pub model_quotas: HashMap<String, i32>, // In-memory cache for model-specific quotas
}
