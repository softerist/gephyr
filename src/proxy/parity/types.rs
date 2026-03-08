use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PARITY_SCHEMA_VERSION: &str = "v1";

fn default_schema_version() -> String {
    PARITY_SCHEMA_VERSION.to_string()
}

/// Source of a fingerprinted request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestSource {
    Gephyr,
    KnownGood,
    AntigravityExe,
    LanguageServerWindowsX64,
    Unknown,
}

impl RequestSource {
    pub fn compare_bucket(&self) -> &'static str {
        match self {
            RequestSource::Gephyr => "gephyr",
            RequestSource::KnownGood
            | RequestSource::AntigravityExe
            | RequestSource::LanguageServerWindowsX64 => "official",
            RequestSource::Unknown => "unknown",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RequestSource::Gephyr => "gephyr",
            RequestSource::KnownGood => "known_good",
            RequestSource::AntigravityExe => "antigravity_exe",
            RequestSource::LanguageServerWindowsX64 => "language_server_windows_x64",
            RequestSource::Unknown => "unknown",
        }
    }
}

/// Recursive JSON structural skeleton (keys and JSON shape, no values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyShape {
    Null,
    Bool,
    Number,
    String,
    Array(Box<BodyShape>),
    Object(BTreeMap<String, BodyShape>),
}

impl BodyShape {
    pub fn from_value(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => BodyShape::Null,
            serde_json::Value::Bool(_) => BodyShape::Bool,
            serde_json::Value::Number(_) => BodyShape::Number,
            serde_json::Value::String(_) => BodyShape::String,
            serde_json::Value::Array(arr) => {
                let element = arr
                    .first()
                    .map(BodyShape::from_value)
                    .unwrap_or(BodyShape::Null);
                BodyShape::Array(Box::new(element))
            }
            serde_json::Value::Object(map) => {
                let children: BTreeMap<String, BodyShape> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), BodyShape::from_value(v)))
                    .collect();
                BodyShape::Object(children)
            }
        }
    }
}

/// Canonical fingerprint schema v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFingerprint {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub capture_session_id: Option<String>,
    pub source: RequestSource,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub normalized_endpoint: String,
    /// Header names lowercased and sorted.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body_shape: Option<BodyShape>,
    #[serde(default)]
    pub timestamp_ms: Option<u64>,
    #[serde(default)]
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub status_code: Option<u16>,
}

impl RequestFingerprint {
    pub fn new(
        source: RequestSource,
        method: String,
        url: String,
        normalized_endpoint: String,
        headers: Vec<(String, String)>,
        body_shape: Option<BodyShape>,
        timestamp_ms: Option<u64>,
        latency_ms: Option<u64>,
        status_code: Option<u16>,
        capture_session_id: Option<String>,
    ) -> Self {
        Self {
            schema_version: default_schema_version(),
            capture_session_id,
            source,
            method,
            url,
            normalized_endpoint,
            headers,
            body_shape,
            timestamp_ms,
            latency_ms,
            status_code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityRule {
    MustMatch,
    AllowedDrift { max_delta_ms: Option<u64> },
    Ignore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRule {
    pub endpoint_pattern: String,
    #[serde(default)]
    pub header_rules: BTreeMap<String, ParityRule>,
    #[serde(default)]
    pub default_header_rule: Option<ParityRule>,
    #[serde(default)]
    pub body_shape_rule: Option<ParityRule>,
    #[serde(default)]
    pub timing_rule: Option<ParityRule>,
    #[serde(default)]
    pub status_code_rule: Option<ParityRule>,
}

impl EndpointRule {
    pub fn matches(&self, endpoint: &str) -> bool {
        wildcard_match(
            &self.endpoint_pattern.to_ascii_lowercase(),
            &endpoint.to_ascii_lowercase(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalizationConfig {
    #[serde(default = "default_true")]
    pub collapse_daily_cloudcode_host: bool,
    #[serde(default = "default_true")]
    pub collapse_local_mock_google_hosts: bool,
    #[serde(default = "default_true")]
    pub normalize_antigravity_user_agent_version: bool,
    #[serde(default = "default_true")]
    pub normalize_header_keys: bool,
    #[serde(default = "default_true")]
    pub normalize_header_order: bool,
    #[serde(default = "default_true")]
    pub normalize_query_order: bool,
    #[serde(default = "default_true")]
    pub redact_sensitive_values: bool,
    #[serde(default = "default_true")]
    pub normalize_volatile_ids: bool,
    #[serde(default = "default_true")]
    pub treat_null_body_shape_as_missing: bool,
    #[serde(default = "default_true")]
    pub ignore_missing_body_shape: bool,
    #[serde(default = "default_true")]
    pub ignore_missing_status_code: bool,
    #[serde(default = "default_true")]
    pub ignore_missing_latency: bool,
    #[serde(default = "default_timing_bucket_ms")]
    pub timing_bucket_ms: Option<u64>,
}

impl Default for CanonicalizationConfig {
    fn default() -> Self {
        Self {
            collapse_daily_cloudcode_host: true,
            collapse_local_mock_google_hosts: true,
            normalize_antigravity_user_agent_version: true,
            normalize_header_keys: true,
            normalize_header_order: true,
            normalize_query_order: true,
            redact_sensitive_values: true,
            normalize_volatile_ids: true,
            treat_null_body_shape_as_missing: true,
            ignore_missing_body_shape: true,
            ignore_missing_status_code: true,
            ignore_missing_latency: true,
            timing_bucket_ms: default_timing_bucket_ms(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_timing_bucket_ms() -> Option<u64> {
    Some(100)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityRuleSet {
    #[serde(default)]
    pub header_rules: BTreeMap<String, ParityRule>,
    #[serde(default)]
    pub endpoint_rules: Vec<EndpointRule>,
    pub timing_rule: ParityRule,
    pub body_shape_rule: ParityRule,
    pub status_code_rule: ParityRule,
    pub default_header_rule: ParityRule,
    #[serde(default)]
    pub canonicalization: CanonicalizationConfig,
}

impl Default for ParityRuleSet {
    fn default() -> Self {
        Self::with_standard_rules()
    }
}

impl ParityRuleSet {
    pub fn with_standard_rules() -> Self {
        let mut header_rules = BTreeMap::new();

        for name in &[
            "authorization",
            "user-agent",
            "x-goog-api-client",
            "content-type",
            "accept-encoding",
            "x-machine-id",
            "x-mac-machine-id",
            "x-dev-device-id",
            "x-sqm-id",
            "host",
        ] {
            header_rules.insert((*name).to_string(), ParityRule::MustMatch);
        }

        for name in &[
            "content-length",
            "connection",
            "date",
            "transfer-encoding",
            "x-request-id",
            "x-correlation-id",
        ] {
            header_rules.insert((*name).to_string(), ParityRule::Ignore);
        }

        Self {
            header_rules,
            endpoint_rules: Vec::new(),
            timing_rule: ParityRule::AllowedDrift {
                max_delta_ms: Some(5000),
            },
            body_shape_rule: ParityRule::MustMatch,
            status_code_rule: ParityRule::MustMatch,
            default_header_rule: ParityRule::MustMatch,
            canonicalization: CanonicalizationConfig::default(),
        }
    }

    fn endpoint_rule_for(&self, endpoint: &str) -> Option<&EndpointRule> {
        self.endpoint_rules
            .iter()
            .find(|rule| rule.matches(endpoint))
    }

    pub fn rule_for_header(&self, endpoint: &str, name: &str) -> ParityRule {
        let header_name = name.to_ascii_lowercase();

        if let Some(endpoint_rule) = self.endpoint_rule_for(endpoint) {
            if let Some(rule) = endpoint_rule.header_rules.get(&header_name) {
                return rule.clone();
            }
            if let Some(rule) = endpoint_rule.default_header_rule.clone() {
                return rule;
            }
        }

        self.header_rules
            .get(&header_name)
            .cloned()
            .unwrap_or_else(|| self.default_header_rule.clone())
    }

    pub fn body_shape_rule_for(&self, endpoint: &str) -> ParityRule {
        self.endpoint_rule_for(endpoint)
            .and_then(|rule| rule.body_shape_rule.clone())
            .unwrap_or_else(|| self.body_shape_rule.clone())
    }

    pub fn timing_rule_for(&self, endpoint: &str) -> ParityRule {
        self.endpoint_rule_for(endpoint)
            .and_then(|rule| rule.timing_rule.clone())
            .unwrap_or_else(|| self.timing_rule.clone())
    }

    pub fn status_code_rule_for(&self, endpoint: &str) -> ParityRule {
        self.endpoint_rule_for(endpoint)
            .and_then(|rule| rule.status_code_rule.clone())
            .unwrap_or_else(|| self.status_code_rule.clone())
    }
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern == "*" {
        return true;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut cursor = 0usize;
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');

    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if idx == 0 && anchored_start {
            if !text[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
            continue;
        }

        if let Some(found) = text[cursor..].find(*part) {
            cursor += found + part.len();
        } else {
            return false;
        }
    }

    if anchored_end {
        if let Some(last) = parts.iter().rev().find(|part| !part.is_empty()) {
            return text.ends_with(last);
        }
    }

    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatePolicy {
    AnyDifferenceFails,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self::AnyDifferenceFails
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchSeverity {
    Fail,
    Drift,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMismatch {
    pub group: String,
    pub field: String,
    pub severity: MismatchSeverity,
    pub rule: String,
    pub gephyr_value: Option<String>,
    pub known_good_value: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Drift,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointVerdict {
    pub endpoint: String,
    pub method: String,
    pub source_bucket: String,
    pub verdict: Verdict,
    pub gephyr_count: usize,
    pub known_good_count: usize,
    pub mismatches: Vec<FieldMismatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityDiffReport {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub generated_at: String,
    pub gate_policy: GatePolicy,
    pub gate_pass: bool,
    pub gephyr_fingerprints_count: usize,
    pub known_good_fingerprints_count: usize,
    pub endpoint_count: usize,
    pub endpoints: Vec<EndpointVerdict>,
    pub overall_verdict: Verdict,
    pub compliance_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityCaptureStatus {
    pub enabled: bool,
    pub session_id: Option<String>,
    pub started_at: Option<String>,
    pub captured_count: usize,
    pub ring_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityExportResult {
    pub raw_path: String,
    pub redacted_path: String,
    pub count: usize,
    pub session_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn body_shape_extracts_json_key_skeleton() {
        let value = json!({
            "project": "test",
            "metadata": {
                "ideType": "ANTIGRAVITY",
                "platform": "PLATFORM_UNSPECIFIED"
            }
        });
        let shape = BodyShape::from_value(&value);
        match &shape {
            BodyShape::Object(map) => {
                assert!(map.contains_key("project"));
                assert!(map.contains_key("metadata"));
            }
            other => panic!("expected Object, got {:?}", other),
        }
    }

    #[test]
    fn fingerprint_serializes_schema_v1() {
        let fp = RequestFingerprint::new(
            RequestSource::Gephyr,
            "POST".to_string(),
            "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist".to_string(),
            "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist".to_string(),
            vec![("content-type".to_string(), "application/json".to_string())],
            Some(BodyShape::from_value(&json!({"project": "x"}))),
            Some(1),
            Some(2),
            Some(200),
            Some("session-1".to_string()),
        );
        let serialized = serde_json::to_string(&fp).expect("serialize");
        assert!(serialized.contains(PARITY_SCHEMA_VERSION));
        assert!(serialized.contains("loadCodeAssist"));
    }

    #[test]
    fn wildcard_endpoint_rule_match_works() {
        let rule = EndpointRule {
            endpoint_pattern: "https://*.googleapis.com/*loadCodeAssist*".to_string(),
            header_rules: BTreeMap::new(),
            default_header_rule: None,
            body_shape_rule: None,
            timing_rule: None,
            status_code_rule: None,
        };
        assert!(
            rule.matches("https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist?alt=sse")
        );
        assert!(!rule.matches("https://example.com/a"));
    }

    #[test]
    fn default_rules_match_expected_header_classes() {
        let rules = ParityRuleSet::default();
        assert_eq!(
            rules.rule_for_header("https://x.googleapis.com", "user-agent"),
            ParityRule::MustMatch
        );
        assert_eq!(
            rules.rule_for_header("https://x.googleapis.com", "content-length"),
            ParityRule::Ignore
        );
    }

    #[test]
    fn report_serializes_gate_policy() {
        let report = ParityDiffReport {
            schema_version: PARITY_SCHEMA_VERSION.to_string(),
            generated_at: "2026-03-01T20:00:00Z".to_string(),
            gate_policy: GatePolicy::AnyDifferenceFails,
            gate_pass: true,
            gephyr_fingerprints_count: 1,
            known_good_fingerprints_count: 1,
            endpoint_count: 1,
            endpoints: vec![],
            overall_verdict: Verdict::Pass,
            compliance_score: 1.0,
        };
        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        assert!(json.contains("any_difference_fails"));
    }
}
