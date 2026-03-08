use std::collections::{BTreeMap, BTreeSet};

use super::ingest::{canonicalize_fingerprints, normalize_endpoint};
use super::types::{
    EndpointVerdict, FieldMismatch, GatePolicy, MismatchSeverity, ParityDiffReport, ParityRule,
    ParityRuleSet, RequestFingerprint, Verdict, PARITY_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EndpointMethodKey {
    endpoint: String,
    method: String,
}

#[derive(Default)]
struct ScoreCounters {
    total_checks: u32,
    pass_count: u32,
    drift_count: u32,
}

fn endpoint_from_fp(fp: &RequestFingerprint) -> String {
    if fp.normalized_endpoint.is_empty() {
        normalize_endpoint(&fp.url)
    } else {
        fp.normalized_endpoint.clone()
    }
}

fn group_by_endpoint_method<'a>(
    fingerprints: &'a [RequestFingerprint],
) -> BTreeMap<EndpointMethodKey, Vec<&'a RequestFingerprint>> {
    let mut grouped: BTreeMap<EndpointMethodKey, Vec<&RequestFingerprint>> = BTreeMap::new();
    for fp in fingerprints {
        let key = EndpointMethodKey {
            endpoint: endpoint_from_fp(fp),
            method: fp.method.to_ascii_uppercase(),
        };
        grouped.entry(key).or_default().push(fp);
    }
    grouped
}

fn split_by_source<'a>(
    fingerprints: &[&'a RequestFingerprint],
) -> BTreeMap<String, Vec<&'a RequestFingerprint>> {
    let mut grouped: BTreeMap<String, Vec<&RequestFingerprint>> = BTreeMap::new();
    for fp in fingerprints {
        grouped
            .entry(fp.source.as_str().to_string())
            .or_default()
            .push(*fp);
    }
    grouped
}

fn fingerprint_signature(fp: &RequestFingerprint) -> String {
    let headers_json = serde_json::to_string(&fp.headers).unwrap_or_default();
    let body_json = fp
        .body_shape
        .as_ref()
        .and_then(|v| serde_json::to_string(v).ok())
        .unwrap_or_default();

    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        fp.method.to_ascii_uppercase(),
        endpoint_from_fp(fp),
        fp.url,
        headers_json,
        body_json,
        fp.status_code
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        fp.latency_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<none>".to_string())
    )
}

fn headers_as_map(fp: &RequestFingerprint) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in &fp.headers {
        out.insert(name.to_ascii_lowercase(), value.clone());
    }
    out
}

fn rule_name(rule: &ParityRule) -> &'static str {
    match rule {
        ParityRule::MustMatch => "must_match",
        ParityRule::AllowedDrift { .. } => "allowed_drift",
        ParityRule::Ignore => "ignore",
    }
}

fn compare_latency_with_rule(
    rule: &ParityRule,
    gephyr: Option<u64>,
    known_good: Option<u64>,
) -> Option<(MismatchSeverity, String)> {
    if matches!(rule, ParityRule::Ignore) {
        return None;
    }

    if gephyr == known_good {
        return None;
    }

    match rule {
        ParityRule::MustMatch => Some((
            MismatchSeverity::Fail,
            "Latency mismatch under must_match rule".to_string(),
        )),
        ParityRule::AllowedDrift { max_delta_ms } => match (gephyr, known_good) {
            (Some(g), Some(k)) => {
                let delta = g.abs_diff(k);
                if max_delta_ms.map(|limit| delta <= limit).unwrap_or(true) {
                    None
                } else {
                    Some((
                        MismatchSeverity::Drift,
                        format!(
                            "Latency delta {}ms exceeded allowed drift {}ms",
                            delta,
                            max_delta_ms
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "<unbounded>".to_string())
                        ),
                    ))
                }
            }
            _ => Some((
                MismatchSeverity::Drift,
                "Latency present on only one side under allowed_drift rule".to_string(),
            )),
        },
        ParityRule::Ignore => None,
    }
}

fn compare_with_rule(
    counters: &mut ScoreCounters,
    mismatches: &mut Vec<FieldMismatch>,
    group: &str,
    field: String,
    rule: &ParityRule,
    gephyr_value: Option<String>,
    known_good_value: Option<String>,
    mismatch_detail: String,
) {
    if matches!(rule, ParityRule::Ignore) {
        return;
    }

    counters.total_checks += 1;

    if gephyr_value == known_good_value {
        counters.pass_count += 1;
        return;
    }

    match rule {
        ParityRule::MustMatch => mismatches.push(FieldMismatch {
            group: group.to_string(),
            field,
            severity: MismatchSeverity::Fail,
            rule: rule_name(rule).to_string(),
            gephyr_value,
            known_good_value,
            detail: mismatch_detail,
        }),
        ParityRule::AllowedDrift { .. } => {
            counters.drift_count += 1;
            mismatches.push(FieldMismatch {
                group: group.to_string(),
                field,
                severity: MismatchSeverity::Drift,
                rule: rule_name(rule).to_string(),
                gephyr_value,
                known_good_value,
                detail: mismatch_detail,
            });
        }
        ParityRule::Ignore => {}
    }
}

fn compare_group(
    key: &EndpointMethodKey,
    source: &str,
    gephyr_group: &[&RequestFingerprint],
    known_group: &[&RequestFingerprint],
    rules: &ParityRuleSet,
    counters: &mut ScoreCounters,
) -> EndpointVerdict {
    let mut mismatches = Vec::new();

    let mut gephyr_sorted = gephyr_group.to_vec();
    gephyr_sorted.sort_by_key(|fp| fingerprint_signature(fp));
    let mut known_sorted = known_group.to_vec();
    known_sorted.sort_by_key(|fp| fingerprint_signature(fp));

    if gephyr_sorted.len() != known_sorted.len() {
        counters.total_checks += 1;
        mismatches.push(FieldMismatch {
            group: "count".to_string(),
            field: "request_count".to_string(),
            severity: MismatchSeverity::Fail,
            rule: "must_match".to_string(),
            gephyr_value: Some(gephyr_sorted.len().to_string()),
            known_good_value: Some(known_sorted.len().to_string()),
            detail: format!(
                "Request count mismatch for ({}, {}, {}): gephyr={} known_good={}",
                key.endpoint,
                key.method,
                source,
                gephyr_sorted.len(),
                known_sorted.len()
            ),
        });
    }

    let pair_count = gephyr_sorted.len().min(known_sorted.len());
    for idx in 0..pair_count {
        let gephyr = gephyr_sorted[idx];
        let known = known_sorted[idx];

        let gephyr_headers = headers_as_map(gephyr);
        let known_headers = headers_as_map(known);

        let mut header_names = BTreeSet::new();
        header_names.extend(gephyr_headers.keys().cloned());
        header_names.extend(known_headers.keys().cloned());

        for header_name in header_names {
            let rule = rules.rule_for_header(&key.endpoint, &header_name);
            compare_with_rule(
                counters,
                &mut mismatches,
                "headers",
                format!("header:{}", header_name),
                &rule,
                gephyr_headers.get(&header_name).cloned(),
                known_headers.get(&header_name).cloned(),
                format!(
                    "Header '{}' mismatch at index {} for source {}",
                    header_name, idx, source
                ),
            );
        }

        let body_rule = rules.body_shape_rule_for(&key.endpoint);
        let gephyr_body = gephyr
            .body_shape
            .as_ref()
            .and_then(|v| serde_json::to_string(v).ok());
        let known_body = known
            .body_shape
            .as_ref()
            .and_then(|v| serde_json::to_string(v).ok());
        let body_one_sided_missing = gephyr_body.is_none() ^ known_body.is_none();
        if !(rules.canonicalization.ignore_missing_body_shape && body_one_sided_missing) {
            compare_with_rule(
                counters,
                &mut mismatches,
                "body",
                "body_shape".to_string(),
                &body_rule,
                gephyr_body,
                known_body,
                format!("Body shape mismatch at index {} for source {}", idx, source),
            );
        }

        let status_rule = rules.status_code_rule_for(&key.endpoint);
        let gephyr_status = gephyr.status_code.map(|v| v.to_string());
        let known_status = known.status_code.map(|v| v.to_string());
        let status_one_sided_missing = gephyr_status.is_none() ^ known_status.is_none();
        if !(rules.canonicalization.ignore_missing_status_code && status_one_sided_missing) {
            compare_with_rule(
                counters,
                &mut mismatches,
                "response",
                "status_code".to_string(),
                &status_rule,
                gephyr_status,
                known_status,
                format!(
                    "Status code mismatch at index {} for source {}",
                    idx, source
                ),
            );
        }

        let timing_rule = rules.timing_rule_for(&key.endpoint);
        let timing_one_sided_missing = gephyr.latency_ms.is_none() ^ known.latency_ms.is_none();
        if !(rules.canonicalization.ignore_missing_latency && timing_one_sided_missing) {
            if let Some((severity, detail)) =
                compare_latency_with_rule(&timing_rule, gephyr.latency_ms, known.latency_ms)
            {
                counters.total_checks += 1;
                if matches!(severity, MismatchSeverity::Drift) {
                    counters.drift_count += 1;
                }

                mismatches.push(FieldMismatch {
                    group: "timing".to_string(),
                    field: "latency_ms".to_string(),
                    severity,
                    rule: rule_name(&timing_rule).to_string(),
                    gephyr_value: gephyr.latency_ms.map(|v| v.to_string()),
                    known_good_value: known.latency_ms.map(|v| v.to_string()),
                    detail,
                });
            } else if !matches!(timing_rule, ParityRule::Ignore) {
                counters.total_checks += 1;
                counters.pass_count += 1;
            }
        }
    }

    let verdict = if mismatches
        .iter()
        .any(|m| m.severity == MismatchSeverity::Fail)
    {
        Verdict::Fail
    } else if !mismatches.is_empty() {
        Verdict::Drift
    } else {
        Verdict::Pass
    };

    EndpointVerdict {
        endpoint: key.endpoint.clone(),
        method: key.method.clone(),
        source_bucket: source.to_string(),
        verdict,
        gephyr_count: gephyr_group.len(),
        known_good_count: known_group.len(),
        mismatches,
    }
}

pub fn compare(
    gephyr: &[RequestFingerprint],
    known_good: &[RequestFingerprint],
    rules: &ParityRuleSet,
    gate_policy: GatePolicy,
) -> ParityDiffReport {
    let gephyr = canonicalize_fingerprints(gephyr, rules);
    let known_good = canonicalize_fingerprints(known_good, rules);

    let gephyr_grouped = group_by_endpoint_method(&gephyr);
    let known_grouped = group_by_endpoint_method(&known_good);

    let mut all_keys: BTreeSet<EndpointMethodKey> = BTreeSet::new();
    all_keys.extend(gephyr_grouped.keys().cloned());
    all_keys.extend(known_grouped.keys().cloned());

    let mut counters = ScoreCounters::default();
    let mut endpoints = Vec::new();

    for key in &all_keys {
        let gephyr_group = gephyr_grouped.get(key).cloned().unwrap_or_default();
        let known_group = known_grouped.get(key).cloned().unwrap_or_default();

        if known_group.is_empty() {
            counters.total_checks += 1;
            endpoints.push(EndpointVerdict {
                endpoint: key.endpoint.clone(),
                method: key.method.clone(),
                source_bucket: "gephyr_only".to_string(),
                verdict: Verdict::Fail,
                gephyr_count: gephyr_group.len(),
                known_good_count: 0,
                mismatches: vec![FieldMismatch {
                    group: "endpoint".to_string(),
                    field: "endpoint_coverage".to_string(),
                    severity: MismatchSeverity::Fail,
                    rule: "must_match".to_string(),
                    gephyr_value: Some(format!("{}:{}", key.method, key.endpoint)),
                    known_good_value: None,
                    detail: "Endpoint+method observed in gephyr but missing in known-good"
                        .to_string(),
                }],
            });
            continue;
        }

        let known_by_source = split_by_source(&known_group);
        for (source, source_group) in known_by_source {
            let endpoint_verdict = compare_group(
                key,
                source.as_str(),
                &gephyr_group,
                &source_group,
                rules,
                &mut counters,
            );
            endpoints.push(endpoint_verdict);
        }
    }

    let compliance_score = if counters.total_checks == 0 {
        1.0
    } else {
        (counters.pass_count as f64 + counters.drift_count as f64 * 0.5)
            / counters.total_checks as f64
    };

    let overall_verdict = if endpoints.iter().any(|e| {
        e.mismatches
            .iter()
            .any(|m| m.severity == MismatchSeverity::Fail)
    }) {
        Verdict::Fail
    } else if endpoints.iter().any(|e| !e.mismatches.is_empty()) {
        Verdict::Drift
    } else {
        Verdict::Pass
    };

    let gate_pass = match gate_policy {
        GatePolicy::AnyDifferenceFails => endpoints
            .iter()
            .all(|endpoint| endpoint.mismatches.is_empty()),
    };

    ParityDiffReport {
        schema_version: PARITY_SCHEMA_VERSION.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        gate_policy,
        gate_pass,
        gephyr_fingerprints_count: gephyr.len(),
        known_good_fingerprints_count: known_good.len(),
        endpoint_count: endpoints.len(),
        endpoints,
        overall_verdict,
        compliance_score,
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{BodyShape, RequestSource};
    use super::*;
    use serde_json::json;

    fn make_fp(
        url: &str,
        headers: Vec<(&str, &str)>,
        body: Option<serde_json::Value>,
        source: RequestSource,
    ) -> RequestFingerprint {
        RequestFingerprint::new(
            source,
            "POST".to_string(),
            url.to_string(),
            normalize_endpoint(url),
            headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body.as_ref().map(BodyShape::from_value),
            Some(1000),
            Some(450),
            Some(200),
            None,
        )
    }

    #[test]
    fn compliance_score_is_1_for_perfect_match() {
        let url = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";
        let headers = vec![
            ("authorization", "<redacted>"),
            ("content-type", "application/json"),
            ("user-agent", "antigravity/1.0 linux/x86_64"),
        ];
        let gephyr = vec![make_fp(url, headers.clone(), None, RequestSource::Gephyr)];
        let known = vec![make_fp(url, headers, None, RequestSource::KnownGood)];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        assert_eq!(report.overall_verdict, Verdict::Pass);
        assert!(report.gate_pass);
        assert_eq!(report.endpoint_count, 1);
        assert!((report.compliance_score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn diff_detects_missing_header_as_fail() {
        let url = "https://cloudcode-pa.googleapis.com/v1internal:test";
        let gephyr = vec![make_fp(
            url,
            vec![("content-type", "application/json")],
            None,
            RequestSource::Gephyr,
        )];
        let known = vec![make_fp(
            url,
            vec![
                ("content-type", "application/json"),
                ("x-goog-api-client", "gl-node/22.21.1"),
            ],
            None,
            RequestSource::AntigravityExe,
        )];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        assert_eq!(report.overall_verdict, Verdict::Fail);
        assert!(!report.gate_pass);

        let ep = &report.endpoints[0];
        let missing = ep
            .mismatches
            .iter()
            .find(|m| m.field == "header:x-goog-api-client");
        assert!(missing.is_some());
        assert_eq!(
            missing.expect("missing mismatch").severity,
            MismatchSeverity::Fail
        );
    }

    #[test]
    fn diff_allows_ignored_header_mismatch() {
        let url = "https://cloudcode-pa.googleapis.com/v1internal:test";
        let gephyr = vec![make_fp(
            url,
            vec![
                ("content-type", "application/json"),
                ("content-length", "42"),
            ],
            None,
            RequestSource::Gephyr,
        )];
        let known = vec![make_fp(
            url,
            vec![
                ("content-type", "application/json"),
                ("content-length", "999"),
            ],
            None,
            RequestSource::KnownGood,
        )];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        assert_eq!(report.overall_verdict, Verdict::Pass);
        assert!(report.gate_pass);
    }

    #[test]
    fn diff_reports_extra_endpoint_in_gephyr_as_gate_failure() {
        let gephyr = vec![make_fp(
            "https://cloudcode-pa.googleapis.com/v1internal:extra",
            vec![],
            None,
            RequestSource::Gephyr,
        )];
        let known: Vec<RequestFingerprint> = vec![];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        assert_eq!(report.endpoints.len(), 1);
        assert_eq!(report.endpoints[0].verdict, Verdict::Fail);
        assert!(!report.gate_pass);
    }

    #[test]
    fn diff_reports_missing_endpoint() {
        let gephyr: Vec<RequestFingerprint> = vec![];
        let known = vec![make_fp(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            vec![],
            None,
            RequestSource::KnownGood,
        )];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        assert_eq!(report.endpoints.len(), 1);
        assert_eq!(report.endpoints[0].verdict, Verdict::Fail);
        assert!(!report.gate_pass);
    }

    #[test]
    fn diff_body_shape_mismatch_is_fail() {
        let url = "https://cloudcode-pa.googleapis.com/v1internal:onboardUser";
        let gephyr = vec![make_fp(
            url,
            vec![],
            Some(json!({"project": "test"})),
            RequestSource::Gephyr,
        )];
        let known = vec![make_fp(
            url,
            vec![],
            Some(json!({"project": "test", "metadata": {"ideType": "X"}})),
            RequestSource::KnownGood,
        )];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        let ep = &report.endpoints[0];
        let body_mismatch = ep.mismatches.iter().find(|m| m.field == "body_shape");
        assert!(body_mismatch.is_some());
        assert_eq!(
            body_mismatch.expect("body mismatch").severity,
            MismatchSeverity::Fail
        );
    }

    #[test]
    fn diff_ignores_one_sided_missing_status_code_by_default() {
        let url = "https://cloudcode-pa.googleapis.com/v1internal:test";
        let gephyr = vec![make_fp(
            url,
            vec![("content-type", "application/json")],
            None,
            RequestSource::Gephyr,
        )];
        let mut known = vec![make_fp(
            url,
            vec![("content-type", "application/json")],
            None,
            RequestSource::KnownGood,
        )];
        known[0].status_code = None;

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        let ep = &report.endpoints[0];
        assert!(ep.mismatches.iter().all(|m| m.field != "status_code"));
        assert!(report.gate_pass);
    }

    #[test]
    fn diff_ignores_one_sided_missing_body_shape_by_default() {
        let url = "https://cloudcode-pa.googleapis.com/v1internal:test";
        let gephyr = vec![make_fp(
            url,
            vec![("content-type", "application/json")],
            Some(json!({"project":"x"})),
            RequestSource::Gephyr,
        )];
        let known = vec![make_fp(
            url,
            vec![("content-type", "application/json")],
            None,
            RequestSource::KnownGood,
        )];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        let ep = &report.endpoints[0];
        assert!(ep.mismatches.iter().all(|m| m.field != "body_shape"));
        assert!(report.gate_pass);
    }

    #[test]
    fn diff_ignores_one_sided_missing_latency_by_default() {
        let url = "https://cloudcode-pa.googleapis.com/v1internal:test";
        let gephyr = vec![make_fp(
            url,
            vec![("content-type", "application/json")],
            None,
            RequestSource::Gephyr,
        )];
        let mut known = vec![make_fp(
            url,
            vec![("content-type", "application/json")],
            None,
            RequestSource::KnownGood,
        )];
        known[0].latency_ms = None;

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        let ep = &report.endpoints[0];
        assert!(ep.mismatches.iter().all(|m| m.field != "latency_ms"));
        assert!(report.gate_pass);
    }

    #[test]
    fn diff_normalizes_daily_host_to_public() {
        let gephyr = vec![make_fp(
            "https://daily-cloudcode-pa.googleapis.com/v1internal:test?a=1&b=2",
            vec![("content-type", "application/json")],
            None,
            RequestSource::Gephyr,
        )];
        let known = vec![make_fp(
            "https://cloudcode-pa.googleapis.com/v1internal:test?b=2&a=1",
            vec![("content-type", "application/json")],
            None,
            RequestSource::KnownGood,
        )];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        assert_eq!(report.endpoint_count, 1);
        assert!(report.gate_pass);
    }

    #[test]
    fn diff_user_agent_value_mismatch_is_fail() {
        let url = "https://cloudcode-pa.googleapis.com/v1internal:test";
        let gephyr = vec![make_fp(
            url,
            vec![("user-agent", "antigravity/1.0 linux/x86_64")],
            None,
            RequestSource::Gephyr,
        )];
        let known = vec![make_fp(
            url,
            vec![("user-agent", "different-ua/2.0")],
            None,
            RequestSource::KnownGood,
        )];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );
        assert_eq!(report.overall_verdict, Verdict::Fail);
        let mismatch = report.endpoints[0]
            .mismatches
            .iter()
            .find(|m| m.field == "header:user-agent");
        assert!(mismatch.is_some());
    }

    #[test]
    fn grouped_by_source_produces_per_source_view() {
        let gephyr = vec![make_fp(
            "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
            vec![("content-type", "application/json")],
            None,
            RequestSource::Gephyr,
        )];

        let known = vec![
            make_fp(
                "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
                vec![("content-type", "application/json")],
                None,
                RequestSource::AntigravityExe,
            ),
            make_fp(
                "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
                vec![("content-type", "application/json")],
                None,
                RequestSource::LanguageServerWindowsX64,
            ),
        ];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::default(),
        );

        assert_eq!(report.endpoint_count, 2);
        assert!(report
            .endpoints
            .iter()
            .any(|e| e.source_bucket == "antigravity_exe"));
        assert!(report
            .endpoints
            .iter()
            .any(|e| e.source_bucket == "language_server_windows_x64"));
    }

    #[test]
    fn strict_gate_fails_on_any_difference_even_info_or_drift() {
        let url = "https://cloudcode-pa.googleapis.com/v1internal:test";
        let gephyr = vec![make_fp(
            url,
            vec![
                ("content-type", "application/json"),
                ("x-extra", "gephyr-only"),
            ],
            None,
            RequestSource::Gephyr,
        )];
        let known = vec![make_fp(
            url,
            vec![("content-type", "application/json")],
            None,
            RequestSource::KnownGood,
        )];

        let report = compare(
            &gephyr,
            &known,
            &ParityRuleSet::default(),
            GatePolicy::AnyDifferenceFails,
        );

        assert!(!report.gate_pass);
        assert_ne!(report.overall_verdict, Verdict::Pass);
    }
}
