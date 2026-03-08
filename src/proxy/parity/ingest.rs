use std::path::Path;

use super::types::{BodyShape, ParityRuleSet, RequestFingerprint, RequestSource};

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-goog-api-key"
            | "proxy-authorization"
    ) || name.contains("token")
        || name.contains("secret")
}

fn parse_source(raw: Option<&str>) -> RequestSource {
    match raw.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "gephyr" => RequestSource::Gephyr,
        "known_good" => RequestSource::KnownGood,
        "antigravity" | "antigravity_exe" => RequestSource::AntigravityExe,
        "language_server_windows_x64" | "language_server_windows_x64.exe" => {
            RequestSource::LanguageServerWindowsX64
        }
        "" => RequestSource::KnownGood,
        _ => RequestSource::Unknown,
    }
}

fn infer_source_from_headers(source: RequestSource, headers: &[(String, String)]) -> RequestSource {
    if !matches!(source, RequestSource::KnownGood | RequestSource::Unknown) {
        return source;
    }

    let user_agent = headers
        .iter()
        .find(|(k, _)| k == "user-agent")
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();

    if user_agent.contains("language_server_windows_x64") {
        return RequestSource::LanguageServerWindowsX64;
    }
    if user_agent.contains("antigravity/") || user_agent.contains("google-api-nodejs-client/") {
        return RequestSource::AntigravityExe;
    }

    source
}

fn infer_source_from_metadata(source: RequestSource, record: &serde_json::Value) -> RequestSource {
    if !matches!(source, RequestSource::KnownGood | RequestSource::Unknown) {
        return source;
    }

    let mut hints = Vec::new();
    for key in [
        "source",
        "mode",
        "source_tag",
        "phase",
        "tool",
        "process_name",
        "exe",
        "client",
    ] {
        if let Some(raw) = record.get(key).and_then(|v| v.as_str()) {
            hints.push(raw.to_ascii_lowercase());
        }
    }

    if hints
        .iter()
        .any(|v| v.contains("language_server_windows_x64"))
    {
        return RequestSource::LanguageServerWindowsX64;
    }
    if hints.iter().any(|v| v.contains("antigravity")) {
        return RequestSource::AntigravityExe;
    }

    source
}

fn format_header_value_for_mode(name: &str, value: &str, redact_sensitive_values: bool) -> String {
    let mut normalized = value.to_string();

    if redact_sensitive_values && is_sensitive_header(name) {
        return "<redacted>".to_string();
    }

    if normalize_volatile_id_candidate(name, &normalized) {
        normalized = "<volatile-id>".to_string();
    }

    normalized
}

fn normalize_antigravity_user_agent(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut tokens = trimmed.splitn(2, ' ');
    let first = tokens.next().unwrap_or(trimmed);
    let rest = tokens.next();

    if !first.to_ascii_lowercase().starts_with("antigravity/") {
        return trimmed.to_string();
    }

    match rest {
        Some(suffix) if !suffix.is_empty() => format!("antigravity/<version> {}", suffix),
        _ => "antigravity/<version>".to_string(),
    }
}

fn normalize_volatile_id_candidate(name: &str, value: &str) -> bool {
    let lower_name = name.to_ascii_lowercase();
    if !(lower_name.contains("id")
        || lower_name.contains("session")
        || lower_name.contains("trace")
        || lower_name.contains("request"))
    {
        return false;
    }

    let trimmed = value.trim();
    let len = trimmed.len();
    if !(len == 32 || len == 36 || len == 38 || len >= 20) {
        return false;
    }

    let mostly_hex_or_dash = trimmed
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '{' || c == '}');
    let mostly_alnum = trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '{' || c == '}');

    mostly_hex_or_dash || mostly_alnum
}

fn normalize_query_order(url: &url::Url) -> String {
    let mut url = url.clone();
    if let Some(query) = url.query() {
        let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        pairs.sort_by(|a, b| a.cmp(b));
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    url.to_string()
}

/// Normalize endpoint URL for parity comparison.
pub fn normalize_endpoint(url: &str) -> String {
    normalize_endpoint_with_options(url, true, true, true)
}

pub fn normalize_endpoint_with_options(
    url: &str,
    collapse_daily_cloudcode_host: bool,
    collapse_local_mock_google_hosts: bool,
    sort_query_params: bool,
) -> String {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return url.to_string(),
    };

    let path_lower = parsed.path().to_ascii_lowercase();
    let mut scheme = parsed.scheme().to_ascii_lowercase();
    let mut host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    let mut port = parsed.port();

    if collapse_local_mock_google_hosts
        && (host == "127.0.0.1" || host == "localhost" || host == "::1")
    {
        if path_lower.starts_with("/v1internal:") || path_lower.starts_with("/v1internal/") {
            scheme = "https".to_string();
            host = "cloudcode-pa.googleapis.com".to_string();
            port = None;
        } else if path_lower.starts_with("/oauth2/v2/userinfo") {
            scheme = "https".to_string();
            host = "www.googleapis.com".to_string();
            port = None;
        } else if path_lower.starts_with("/token") || path_lower.starts_with("/revoke") {
            scheme = "https".to_string();
            host = "oauth2.googleapis.com".to_string();
            port = None;
        }
    }

    if collapse_daily_cloudcode_host && host == "daily-cloudcode-pa.googleapis.com" {
        host = "cloudcode-pa.googleapis.com".to_string();
    }

    let port_part = port.map(|p| format!(":{}", p)).unwrap_or_default();
    let mut normalized = format!("{}://{}{}{}", scheme, host, port_part, parsed.path());

    if let Some(query) = parsed.query() {
        normalized.push('?');
        normalized.push_str(query);
    }

    if sort_query_params {
        if let Ok(parsed_norm) = url::Url::parse(&normalized) {
            return normalize_query_order(&parsed_norm);
        }
    }

    normalized
}

fn parse_headers(
    value: &serde_json::Value,
    redact_sensitive_values: bool,
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();

    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            let name = k.to_ascii_lowercase();
            let raw = v.as_str().unwrap_or("");
            headers.push((
                name.clone(),
                format_header_value_for_mode(&name, raw, redact_sensitive_values),
            ));
        }
    }

    if let Some(arr) = value.as_array() {
        for item in arr {
            if let Some(tuple_arr) = item.as_array() {
                if tuple_arr.len() == 2 {
                    let name = tuple_arr[0].as_str().unwrap_or("").to_ascii_lowercase();
                    let raw = tuple_arr[1].as_str().unwrap_or("");
                    headers.push((
                        name.clone(),
                        format_header_value_for_mode(&name, raw, redact_sensitive_values),
                    ));
                }
            }
        }
    }

    headers.sort_by(|a, b| a.0.cmp(&b.0));
    headers
}

fn parse_jsonl_record(
    line: &str,
    source_override: Option<RequestSource>,
) -> Result<RequestFingerprint, String> {
    let record: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("JSON parse error: {}", e))?;

    let source = source_override.unwrap_or_else(|| {
        let from_source = record
            .get("source")
            .and_then(|v| v.as_str())
            .or_else(|| record.get("mode").and_then(|v| v.as_str()));
        parse_source(from_source)
    });

    let method = record
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("POST")
        .to_ascii_uppercase();

    let url = record
        .get("url")
        .and_then(|v| v.as_str())
        .or_else(|| record.get("endpoint").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    let normalized_endpoint = record
        .get("normalized_endpoint")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .unwrap_or_else(|| normalize_endpoint(&url));

    let headers = parse_headers(
        record.get("headers").unwrap_or(&serde_json::Value::Null),
        true,
    );

    let body_shape = record
        .get("body_shape")
        .or_else(|| record.get("body"))
        .map(BodyShape::from_value);

    let timestamp_ms = record
        .get("timestamp_ms")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            record
                .get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
                .map(|dt| dt.timestamp_millis() as u64)
        });

    let latency_ms = record.get("latency_ms").and_then(|v| v.as_u64());
    let status_code = record
        .get("status_code")
        .and_then(|v| v.as_u64())
        .map(|v| v as u16);
    let capture_session_id = record
        .get("capture_session_id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    let source = infer_source_from_metadata(source, &record);
    let source = infer_source_from_headers(source, &headers);

    Ok(RequestFingerprint::new(
        source,
        method,
        url,
        normalized_endpoint,
        headers,
        body_shape,
        timestamp_ms,
        latency_ms,
        status_code,
        capture_session_id,
    ))
}

pub fn canonicalize_fingerprint(
    fingerprint: &RequestFingerprint,
    rules: &ParityRuleSet,
) -> RequestFingerprint {
    let c = &rules.canonicalization;
    let mut out = fingerprint.clone();

    out.normalized_endpoint = normalize_endpoint_with_options(
        &out.url,
        c.collapse_daily_cloudcode_host,
        c.collapse_local_mock_google_hosts,
        c.normalize_query_order,
    );

    if c.normalize_header_keys {
        for (name, _) in &mut out.headers {
            *name = name.to_ascii_lowercase();
        }
    }

    if c.redact_sensitive_values || c.normalize_volatile_ids {
        for (name, value) in &mut out.headers {
            *value = format_header_value_for_mode(name, value, c.redact_sensitive_values);
            if c.normalize_antigravity_user_agent_version && name == "user-agent" {
                *value = normalize_antigravity_user_agent(value);
            }
            if name == "host" {
                let host_lower = value.to_ascii_lowercase();
                if c.collapse_daily_cloudcode_host
                    && host_lower == "daily-cloudcode-pa.googleapis.com"
                {
                    *value = "cloudcode-pa.googleapis.com".to_string();
                }
                if c.collapse_local_mock_google_hosts
                    && (host_lower.starts_with("127.0.0.1")
                        || host_lower.starts_with("localhost")
                        || host_lower.starts_with("::1"))
                {
                    if let Ok(endpoint) = url::Url::parse(&out.normalized_endpoint) {
                        if let Some(endpoint_host) = endpoint.host_str() {
                            let normalized_host = if let Some(port) = endpoint.port() {
                                format!("{}:{}", endpoint_host, port)
                            } else {
                                endpoint_host.to_string()
                            };
                            if !normalized_host.is_empty() {
                                *value = normalized_host;
                            }
                        }
                    }
                }
            }
            if c.normalize_volatile_ids && normalize_volatile_id_candidate(name, value) {
                *value = "<volatile-id>".to_string();
            }
        }
    }

    if c.normalize_header_order {
        out.headers.sort_by(|a, b| a.0.cmp(&b.0));
    }

    if let (Some(bucket_ms), Some(latency)) = (c.timing_bucket_ms, out.latency_ms) {
        if bucket_ms > 0 {
            out.latency_ms = Some((latency / bucket_ms) * bucket_ms);
        }
    }

    if c.treat_null_body_shape_as_missing && matches!(out.body_shape, Some(BodyShape::Null)) {
        out.body_shape = None;
    }

    out
}

pub fn canonicalize_fingerprints(
    fingerprints: &[RequestFingerprint],
    rules: &ParityRuleSet,
) -> Vec<RequestFingerprint> {
    fingerprints
        .iter()
        .map(|fp| canonicalize_fingerprint(fp, rules))
        .collect()
}

pub fn load_jsonl(path: &Path) -> Result<Vec<RequestFingerprint>, String> {
    load_jsonl_as(path, None)
}

pub fn load_jsonl_as(
    path: &Path,
    source_override: Option<RequestSource>,
) -> Result<Vec<RequestFingerprint>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;

    let mut fingerprints = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match parse_jsonl_record(trimmed, source_override.clone()) {
            Ok(fp) => fingerprints.push(fp),
            Err(e) => {
                tracing::warn!(
                    "Skipping malformed JSONL line {} in {}: {}",
                    line_num + 1,
                    path.display(),
                    e
                );
            }
        }
    }

    Ok(fingerprints)
}

fn load_har(
    path: &Path,
    source_override: Option<RequestSource>,
) -> Result<Vec<RequestFingerprint>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read HAR {}: {}", path.display(), e))?;
    let value: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("HAR parse failed: {}", e))?;

    let entries = value
        .get("log")
        .and_then(|v| v.get("entries"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| "HAR file missing log.entries".to_string())?;

    let source = source_override.unwrap_or(RequestSource::KnownGood);

    let mut out = Vec::new();
    for entry in entries {
        let request = match entry.get("request") {
            Some(v) => v,
            None => continue,
        };

        let url = request
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            continue;
        }

        let method = request
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_ascii_uppercase();

        let mut headers = Vec::new();
        if let Some(hdrs) = request.get("headers").and_then(|v| v.as_array()) {
            for item in hdrs {
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if name.is_empty() {
                    continue;
                }
                let value = item.get("value").and_then(|v| v.as_str()).unwrap_or("");
                headers.push((
                    name.clone(),
                    format_header_value_for_mode(&name, value, true),
                ));
            }
            headers.sort_by(|a, b| a.0.cmp(&b.0));
        }

        let timestamp_ms = entry
            .get("startedDateTime")
            .and_then(|v| v.as_str())
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|dt| dt.timestamp_millis() as u64);

        out.push(RequestFingerprint::new(
            source.clone(),
            method,
            url.clone(),
            normalize_endpoint(&url),
            headers,
            None,
            timestamp_ms,
            None,
            None,
            None,
        ));
    }

    Ok(out)
}

fn load_saz(
    path: &Path,
    source_override: Option<RequestSource>,
) -> Result<Vec<RequestFingerprint>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("failed to open SAZ {}: {}", path.display(), e))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("failed to parse SAZ zip {}: {}", path.display(), e))?;

    let source = source_override.unwrap_or(RequestSource::KnownGood);
    let mut out = Vec::new();

    for idx in 0..archive.len() {
        let mut entry = archive
            .by_index(idx)
            .map_err(|e| format!("SAZ read error: {}", e))?;
        let name = entry.name().to_string();
        if !name.starts_with("raw/") || !name.ends_with("_c.txt") {
            continue;
        }

        use std::io::Read;
        let mut content = String::new();
        entry
            .read_to_string(&mut content)
            .map_err(|e| format!("SAZ entry read error: {}", e))?;

        let mut lines = content.lines();
        let first = lines.next().unwrap_or("").trim();
        if first.is_empty() {
            continue;
        }

        let parts: Vec<&str> = first.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let method = parts[0].to_ascii_uppercase();
        if method == "CONNECT" {
            continue;
        }

        let target = parts[1].to_string();
        let mut headers = Vec::new();
        let mut host = String::new();
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                let key = name.trim().to_ascii_lowercase();
                let val = value.trim();
                if key == "host" {
                    host = val.to_string();
                }
                headers.push((key.clone(), format_header_value_for_mode(&key, val, true)));
            }
        }
        headers.sort_by(|a, b| a.0.cmp(&b.0));

        let url = if target.starts_with("http://") || target.starts_with("https://") {
            target
        } else if !host.is_empty() {
            format!("https://{}{}", host, target)
        } else {
            continue;
        };

        out.push(RequestFingerprint::new(
            source.clone(),
            method,
            url.clone(),
            normalize_endpoint(&url),
            headers,
            None,
            None,
            None,
            None,
            None,
        ));
    }

    Ok(out)
}

pub fn load_trace(
    path: &Path,
    source_override: Option<RequestSource>,
) -> Result<Vec<RequestFingerprint>, String> {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "jsonl" | "ndjson" | "txt" => load_jsonl_as(path, source_override),
        "har" => load_har(path, source_override),
        "saz" => load_saz(path, source_override),
        other => Err(format!(
            "unsupported trace format .{} (expected jsonl/har/saz)",
            other
        )),
    }
}

pub fn filter_google_endpoints(fingerprints: Vec<RequestFingerprint>) -> Vec<RequestFingerprint> {
    fingerprints
        .into_iter()
        .filter(|fp| {
            if fp.url.contains("googleapis.com") || fp.url.contains("google.com") {
                return true;
            }

            let parsed = match url::Url::parse(&fp.url) {
                Ok(u) => u,
                Err(_) => return false,
            };
            let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
            if !(host == "127.0.0.1" || host == "localhost" || host == "::1") {
                return false;
            }

            let path = parsed.path().to_ascii_lowercase();
            path.starts_with("/v1internal:")
                || path.starts_with("/v1internal/")
                || path.starts_with("/oauth2/v2/userinfo")
                || path.starts_with("/token")
                || path.starts_with("/revoke")
                || path.starts_with("/log")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::parity::types::{GatePolicy, ParityDiffReport, Verdict};

    #[test]
    fn normalize_endpoint_collapses_daily_host() {
        let daily = "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";
        let normalized = normalize_endpoint(daily);
        assert_eq!(
            normalized,
            "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
        );
    }

    #[test]
    fn normalize_endpoint_sorts_query_params() {
        let source = "https://cloudcode-pa.googleapis.com/v1internal:generateContent?b=2&a=1";
        let normalized = normalize_endpoint(source);
        assert!(normalized.ends_with("?a=1&b=2"));
    }

    #[test]
    fn normalize_endpoint_maps_local_mock_cloudcode_host() {
        let mock = "http://127.0.0.1:51974/v1internal:loadCodeAssist";
        let normalized = normalize_endpoint(mock);
        assert_eq!(
            normalized,
            "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
        );
    }

    #[test]
    fn normalize_endpoint_maps_local_mock_userinfo_host() {
        let mock = "http://localhost:52000/oauth2/v2/userinfo";
        let normalized = normalize_endpoint(mock);
        assert_eq!(normalized, "https://www.googleapis.com/oauth2/v2/userinfo");
    }

    #[test]
    fn canonicalization_redacts_sensitive_headers() {
        let fp = RequestFingerprint::new(
            RequestSource::Gephyr,
            "POST".to_string(),
            "https://cloudcode-pa.googleapis.com/v1internal:x".to_string(),
            "".to_string(),
            vec![
                ("authorization".to_string(), "Bearer abc".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            None,
            Some(1),
            Some(234),
            Some(200),
            None,
        );
        let rules = ParityRuleSet::default();
        let out = canonicalize_fingerprint(&fp, &rules);
        let auth = out
            .headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.as_str());
        assert_eq!(auth, Some("<redacted>"));
        assert_eq!(out.latency_ms, Some(200));
    }

    #[test]
    fn canonicalization_normalizes_host_header_for_local_cloudcode_mocks() {
        let fp = RequestFingerprint::new(
            RequestSource::Gephyr,
            "POST".to_string(),
            "http://127.0.0.1:51974/v1internal:loadCodeAssist".to_string(),
            "".to_string(),
            vec![("host".to_string(), "127.0.0.1:51974".to_string())],
            None,
            Some(1),
            Some(234),
            Some(200),
            None,
        );
        let rules = ParityRuleSet::default();
        let out = canonicalize_fingerprint(&fp, &rules);
        let host = out
            .headers
            .iter()
            .find(|(k, _)| k == "host")
            .map(|(_, v)| v.as_str());
        assert_eq!(host, Some("cloudcode-pa.googleapis.com"));
    }

    #[test]
    fn canonicalization_normalizes_antigravity_user_agent_version() {
        let fp = RequestFingerprint::new(
            RequestSource::Gephyr,
            "POST".to_string(),
            "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist".to_string(),
            "".to_string(),
            vec![(
                "user-agent".to_string(),
                "antigravity/1.16.16 windows/amd64 google-api-nodejs-client/10.3.0".to_string(),
            )],
            None,
            Some(1),
            Some(234),
            Some(200),
            None,
        );
        let rules = ParityRuleSet::default();
        let out = canonicalize_fingerprint(&fp, &rules);
        let ua = out
            .headers
            .iter()
            .find(|(k, _)| k == "user-agent")
            .map(|(_, v)| v.as_str());
        assert_eq!(
            ua,
            Some("antigravity/<version> windows/amd64 google-api-nodejs-client/10.3.0")
        );
    }

    #[test]
    fn canonicalization_treats_null_body_shape_as_missing() {
        let fp = RequestFingerprint::new(
            RequestSource::KnownGood,
            "POST".to_string(),
            "https://cloudcode-pa.googleapis.com/v1internal:fetchUserInfo".to_string(),
            "".to_string(),
            vec![],
            Some(BodyShape::Null),
            Some(1),
            Some(100),
            Some(200),
            None,
        );
        let rules = ParityRuleSet::default();
        let out = canonicalize_fingerprint(&fp, &rules);
        assert!(out.body_shape.is_none());
    }

    #[test]
    fn load_jsonl_supports_legacy_and_v1_shapes() {
        let tmp = std::env::temp_dir().join("gephyr_parity_ingest_v1_test.jsonl");
        let lines = [
            r#"{"endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","method":"GET","mode":"known_good","headers":{"authorization":"Bearer X"}}"#,
            r#"{"schema_version":"v1","url":"https://cloudcode-pa.googleapis.com/v1internal:test2","normalized_endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test2","method":"POST","source":"gephyr","headers":{"content-type":"application/json"},"status_code":200}"#,
        ];
        std::fs::write(&tmp, lines.join("\n")).expect("write");
        let loaded = load_jsonl(&tmp).expect("load");
        let _ = std::fs::remove_file(&tmp);

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].schema_version, "v1");
        assert_eq!(loaded[1].status_code, Some(200));
    }

    #[test]
    fn load_jsonl_infers_official_source_from_phase_metadata() {
        let tmp = std::env::temp_dir().join("gephyr_parity_ingest_source_hint_test.jsonl");
        std::fs::write(
            &tmp,
            r#"{"endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","method":"POST","mode":"known_good","phase":"language_server_windows_x64/oauth","headers":{"content-type":"application/json"}}"#,
        )
        .expect("write");

        let loaded = load_jsonl(&tmp).expect("load");
        let _ = std::fs::remove_file(&tmp);

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].source, RequestSource::LanguageServerWindowsX64);
    }

    #[test]
    fn filter_google_endpoints_keeps_local_mock_google_paths() {
        let fps = vec![
            RequestFingerprint::new(
                RequestSource::Gephyr,
                "POST".to_string(),
                "http://127.0.0.1:52000/v1internal:loadCodeAssist".to_string(),
                "".to_string(),
                vec![],
                None,
                None,
                None,
                None,
                None,
            ),
            RequestFingerprint::new(
                RequestSource::Gephyr,
                "GET".to_string(),
                "http://127.0.0.1:52000/health".to_string(),
                "".to_string(),
                vec![],
                None,
                None,
                None,
                None,
                None,
            ),
        ];
        let filtered = filter_google_endpoints(fps);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].url.contains("v1internal:loadCodeAssist"));
    }

    #[test]
    fn parity_report_schema_roundtrip() {
        let report = ParityDiffReport {
            schema_version: "v1".to_string(),
            generated_at: "2026-03-01T00:00:00Z".to_string(),
            gate_policy: GatePolicy::AnyDifferenceFails,
            gate_pass: true,
            gephyr_fingerprints_count: 1,
            known_good_fingerprints_count: 1,
            endpoint_count: 1,
            endpoints: vec![],
            overall_verdict: Verdict::Pass,
            compliance_score: 1.0,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("schema_version"));
    }
}
