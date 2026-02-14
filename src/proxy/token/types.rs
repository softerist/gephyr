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
    pub account_path: PathBuf,
    pub project_id: Option<String>,
    pub subscription_tier: Option<String>,
    pub remaining_quota: Option<i32>,
    pub protected_models: HashSet<String>,
    pub health_score: f32,
    pub reset_time: Option<i64>,
    pub validation_blocked: bool,
    pub validation_blocked_until: i64,
    pub model_quotas: HashMap<String, i32>,
}