use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use super::{token::TokenData, quota::QuotaData};

// Account data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub token: TokenData,
    // Optional device profile, used to fix machine info when switching accounts
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_profile: Option<DeviceProfile>,
    // Device profile history (recorded when generated/collected), excluding baseline
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_history: Vec<DeviceProfileVersion>,
    pub quota: Option<QuotaData>,
    // Disabled accounts are ignored by the proxy token pool (e.g. revoked refresh_token -> invalid_grant).
    #[serde(default)]
    pub disabled: bool,
    // Optional human-readable reason for disabling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    // Unix timestamp when the account was disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<i64>,
    // User manually disabled proxy feature (does not affect app usage).
    #[serde(default)]
    pub proxy_disabled: bool,
    // Optional human-readable reason for proxy disabling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_disabled_reason: Option<String>,
    // Unix timestamp when the proxy was disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_disabled_at: Option<i64>,
    // List of models disabled by quota protection [NEW #621]
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub protected_models: HashSet<String>,
    //  403 Validation required/blocked status
    #[serde(default)]
    pub validation_blocked: bool,
    //  Validation blocked until timestamp
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_blocked_until: Option<i64>,
    //  Validation blocked reason
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_blocked_reason: Option<String>,
    pub created_at: i64,
    pub last_used: i64,
    // Bound proxy ID (None = use global proxy pool)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    // Proxy binding time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_bound_at: Option<i64>,
    // User custom label
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
}

impl Account {
    pub fn new(id: String, email: String, token: TokenData) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id,
            email,
            name: None,
            token,
            device_profile: None,
            device_history: Vec::new(),
            quota: None,
            disabled: false,
            disabled_reason: None,
            disabled_at: None,
            proxy_disabled: false,
            proxy_disabled_reason: None,
            proxy_disabled_at: None,
            protected_models: HashSet::new(),
            validation_blocked: false,
            validation_blocked_until: None,
            validation_blocked_reason: None,
            created_at: now,
            last_used: now,
            proxy_id: None,
            proxy_bound_at: None,
            custom_label: None,
        }
    }

    pub fn update_last_used(&mut self) {
        self.last_used = chrono::Utc::now().timestamp();
    }

    pub fn update_quota(&mut self, quota: QuotaData) {
        self.quota = Some(quota);
    }
}

// Account index data (accounts.json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountIndex {
    pub version: String,
    pub accounts: Vec<AccountSummary>,
    pub current_account_id: Option<String>,
}

// Account summary information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub proxy_disabled: bool,
    pub created_at: i64,
    pub last_used: i64,
}

impl AccountIndex {
    pub fn new() -> Self {
        Self {
            version: "2.0".to_string(),
            accounts: Vec::new(),
            current_account_id: None,
        }
    }
}

impl Default for AccountIndex {
    fn default() -> Self {
        Self::new()
    }
}

// Device profile (telemetry-related fields in storage.json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub machine_id: String,
    pub mac_machine_id: String,
    pub dev_device_id: String,
    pub sqm_id: String,
}

// Device profile history version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfileVersion {
    pub id: String,
    pub created_at: i64,
    pub label: String,
    pub profile: DeviceProfile,
    #[serde(default)]
    pub is_current: bool,
}

// Export account items (for backup/migration)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportItem {
    pub email: String,
    pub refresh_token: String,
}

// Export accounts response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportResponse {
    pub accounts: Vec<AccountExportItem>,
}
