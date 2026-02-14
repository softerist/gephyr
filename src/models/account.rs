use super::{quota::QuotaData, token::TokenData};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_sub: Option<String>,
    pub name: Option<String>,
    pub token: TokenData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_profile: Option<DeviceProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_history: Vec<DeviceProfileVersion>,
    pub quota: Option<QuotaData>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<i64>,
    #[serde(default)]
    pub proxy_disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_disabled_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_disabled_at: Option<i64>,
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub protected_models: HashSet<String>,
    #[serde(default)]
    pub validation_blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_blocked_until: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_blocked_reason: Option<String>,
    pub created_at: i64,
    pub last_used: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_bound_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_label: Option<String>,
}

impl Account {
    pub fn new(id: String, email: String, token: TokenData) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id,
            email,
            google_sub: None,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountIndex {
    pub version: String,
    pub accounts: Vec<AccountSummary>,
    pub current_account_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_sub: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sqm_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfileVersion {
    pub id: String,
    pub created_at: i64,
    pub label: String,
    pub profile: DeviceProfile,
    #[serde(default)]
    pub is_current: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportItem {
    pub email: String,
    pub refresh_token: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportResponse {
    pub accounts: Vec<AccountExportItem>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_token(email: &str) -> TokenData {
        TokenData::new(
            "access-token".to_string(),
            "refresh-token".to_string(),
            3600,
            Some(email.to_string()),
            None,
            None,
        )
    }

    #[test]
    fn account_deserialize_without_google_sub_is_ok() {
        let account = Account::new(
            "acc-1".to_string(),
            "user@example.com".to_string(),
            sample_token("user@example.com"),
        );
        let mut value = serde_json::to_value(account).expect("serialize account");
        value
            .as_object_mut()
            .expect("account must serialize as object")
            .remove("google_sub");

        let parsed: Account =
            serde_json::from_value(value).expect("deserialize without google_sub");
        assert!(parsed.google_sub.is_none());
        assert_eq!(parsed.email, "user@example.com");
    }

    #[test]
    fn account_serialize_with_google_sub() {
        let mut account = Account::new(
            "acc-2".to_string(),
            "user2@example.com".to_string(),
            sample_token("user2@example.com"),
        );
        account.google_sub = Some("google-sub-2".to_string());

        let value = serde_json::to_value(account).expect("serialize account with google_sub");
        assert_eq!(
            value.get("google_sub").and_then(|v| v.as_str()),
            Some("google-sub-2")
        );
    }
}