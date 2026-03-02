use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use gephyr_lib::parity;
use serde::Serialize;

#[derive(Default, Debug)]
struct ParsedArgs {
    values: HashMap<String, String>,
    flags: HashSet<String>,
    positionals: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SourceAuditSourceSummary {
    source: String,
    count: usize,
    share: f64,
    top_user_agents: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SourceAuditReport {
    input_path: String,
    total_records: usize,
    scoped_records: usize,
    unknown_records: usize,
    unknown_ratio: f64,
    required_sources: Vec<String>,
    missing_required_sources: Vec<String>,
    max_unknown_ratio: f64,
    sources: Vec<SourceAuditSourceSummary>,
    pass: bool,
}

fn parse_args(args: &[String]) -> ParsedArgs {
    let mut out = ParsedArgs::default();
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = &args[idx];
        if let Some(stripped) = arg.strip_prefix("--") {
            if let Some((k, v)) = stripped.split_once('=') {
                out.values.insert(k.to_string(), v.to_string());
                idx += 1;
                continue;
            }

            if idx + 1 < args.len() && !args[idx + 1].starts_with("--") {
                out.values
                    .insert(stripped.to_string(), args[idx + 1].clone());
                idx += 2;
                continue;
            }

            out.flags.insert(stripped.to_string());
            idx += 1;
            continue;
        }

        out.positionals.push(arg.clone());
        idx += 1;
    }

    out
}

fn parse_csv_arg(value: Option<&String>) -> Vec<String> {
    value
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn normalize_source_label(raw: &str) -> Option<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "gephyr" => Some("gephyr".to_string()),
        "known_good" | "known-good" => Some("known_good".to_string()),
        "antigravity" | "antigravity_exe" => Some("antigravity_exe".to_string()),
        "language_server_windows_x64"
        | "language_server_windows_x64.exe"
        | "language-server-windows-x64" => Some("language_server_windows_x64".to_string()),
        "unknown" => Some("unknown".to_string()),
        _ => None,
    }
}

fn parse_required_sources(parsed: &ParsedArgs) -> Result<Vec<String>, String> {
    let configured = parse_csv_arg(parsed.values.get("require-sources"));
    if configured.is_empty() {
        return Ok(vec![
            "antigravity_exe".to_string(),
            "language_server_windows_x64".to_string(),
        ]);
    }

    let mut out = Vec::new();
    for source in configured {
        let normalized = normalize_source_label(&source)
            .ok_or_else(|| format!("invalid source label in --require-sources: {}", source))?;
        if !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    Ok(out)
}

fn parse_f64_arg(parsed: &ParsedArgs, key: &str, default: f64) -> Result<f64, String> {
    let Some(raw) = parsed.values.get(key) else {
        return Ok(default);
    };
    let parsed_value = raw
        .trim()
        .parse::<f64>()
        .map_err(|e| format!("invalid --{} value '{}': {}", key, raw, e))?;
    if !(0.0..=1.0).contains(&parsed_value) {
        return Err(format!(
            "--{} must be within [0.0, 1.0], got {}",
            key, parsed_value
        ));
    }
    Ok(parsed_value)
}

fn parse_exe_file_version(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }

    let path_literal = path.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$item = Get-Item -LiteralPath '{}'; if ($item -and $item.VersionInfo -and $item.VersionInfo.FileVersion) {{ [Console]::Out.Write($item.VersionInfo.FileVersion) }}",
        path_literal
    );

    for shell in ["powershell", "pwsh"] {
        let output = Command::new(shell)
            .arg("-NoProfile")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(&script)
            .output();

        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() {
            return Some(stdout);
        }
    }

    None
}

fn resolve_version_from_args(
    parsed: &ParsedArgs,
    version_key: &str,
    path_key: &str,
    fallback: Option<String>,
) -> Option<String> {
    if let Some(raw) = parsed.values.get(version_key) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if let Some(path) = parsed.values.get(path_key) {
        let path = PathBuf::from(path);
        if let Some(version) = parse_exe_file_version(&path) {
            return Some(version);
        }
        return Some("unknown".to_string());
    }

    fallback
}

fn top_user_agents_for_source(
    records: &[&parity::types::RequestFingerprint],
    limit: usize,
) -> Vec<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for fp in records {
        let ua = fp
            .headers
            .iter()
            .find(|(name, _)| name == "user-agent")
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| "<missing-user-agent>".to_string());
        *counts.entry(ua).or_insert(0) += 1;
    }

    let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked
        .into_iter()
        .take(limit)
        .map(|(ua, count)| format!("{} ({})", ua, count))
        .collect()
}

fn build_source_audit_report(
    records: &[parity::types::RequestFingerprint],
    input_path: &str,
    required_sources: &[String],
    max_unknown_ratio: f64,
) -> SourceAuditReport {
    let mut by_source: BTreeMap<String, Vec<&parity::types::RequestFingerprint>> = BTreeMap::new();
    for fp in records {
        by_source
            .entry(stable_source_key(&fp.source).to_string())
            .or_default()
            .push(fp);
    }

    let scoped_records = records.len();
    let unknown_records = by_source.get("unknown").map(|v| v.len()).unwrap_or(0);
    let unknown_ratio = if scoped_records == 0 {
        0.0
    } else {
        unknown_records as f64 / scoped_records as f64
    };

    let mut sources = Vec::new();
    for (source, source_records) in &by_source {
        let share = if scoped_records == 0 {
            0.0
        } else {
            source_records.len() as f64 / scoped_records as f64
        };
        sources.push(SourceAuditSourceSummary {
            source: source.clone(),
            count: source_records.len(),
            share,
            top_user_agents: top_user_agents_for_source(source_records, 5),
        });
    }
    sources.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.source.cmp(&b.source)));

    let mut missing_required_sources = Vec::new();
    for required in required_sources {
        if !by_source.contains_key(required) {
            missing_required_sources.push(required.clone());
        }
    }

    let pass = missing_required_sources.is_empty() && unknown_ratio <= max_unknown_ratio;

    SourceAuditReport {
        input_path: input_path.to_string(),
        total_records: scoped_records,
        scoped_records,
        unknown_records,
        unknown_ratio,
        required_sources: required_sources.to_vec(),
        missing_required_sources,
        max_unknown_ratio,
        sources,
        pass,
    }
}

#[derive(Debug, Clone)]
struct ManifestMetadata {
    capture_mode: String,
    platform: String,
    capture_date: String,
    input_path: String,
    ruleset_version: String,
    gephyr_version: Option<String>,
    antigravity_version: Option<String>,
    language_server_version: Option<String>,
    capture_sources: Vec<String>,
}

impl ManifestMetadata {
    fn from_args(parsed: &ParsedArgs, input_path: String, capture_sources: Vec<String>) -> Self {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        Self {
            capture_mode: parsed
                .values
                .get("capture-mode")
                .cloned()
                .unwrap_or_else(|| "guided_semi_auto".to_string()),
            platform: parsed
                .values
                .get("platform")
                .cloned()
                .unwrap_or_else(|| "windows".to_string()),
            capture_date: parsed.values.get("capture-date").cloned().unwrap_or(today),
            input_path,
            ruleset_version: parsed
                .values
                .get("ruleset-version")
                .cloned()
                .unwrap_or_else(|| "standard_v1".to_string()),
            gephyr_version: resolve_version_from_args(
                parsed,
                "gephyr-version",
                "gephyr-exe-path",
                Some(env!("CARGO_PKG_VERSION").to_string()),
            ),
            antigravity_version: resolve_version_from_args(
                parsed,
                "antigravity-version",
                "antigravity-exe-path",
                None,
            ),
            language_server_version: resolve_version_from_args(
                parsed,
                "language-server-version",
                "language-server-exe-path",
                None,
            ),
            capture_sources,
        }
    }
}

fn stable_source_key(source: &parity::types::RequestSource) -> &'static str {
    match source {
        parity::types::RequestSource::Gephyr => "gephyr",
        parity::types::RequestSource::KnownGood => "known_good",
        parity::types::RequestSource::AntigravityExe => "antigravity_exe",
        parity::types::RequestSource::LanguageServerWindowsX64 => "language_server_windows_x64",
        parity::types::RequestSource::Unknown => "unknown",
    }
}

fn collect_source_labels(fingerprints: &[parity::types::RequestFingerprint]) -> Vec<String> {
    let mut labels: BTreeSet<String> = BTreeSet::new();
    for fp in fingerprints {
        labels.insert(stable_source_key(&fp.source).to_string());
    }
    labels.into_iter().collect()
}

fn relative_display_path(path: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = path.strip_prefix(&cwd) {
            return rel.to_string_lossy().to_string();
        }
    }
    path.to_string_lossy().to_string()
}

fn manifest_path_for_jsonl(path: &Path) -> PathBuf {
    let mut manifest = path.to_path_buf();
    manifest.set_extension("manifest.json");
    manifest
}

fn print_help() {
    println!(
        "gephyr-parity\n\nCommands:\n  capture-gephyr <start|stop|status|export> [--api-base URL] [--api-key KEY]\n  capture-official --guided [--script PATH] [--skip-guided-run] [--known-good-path PATH] [--bundle-out-dir DIR] [--rules PATH] [--require-sources CSV] [--max-unknown-ratio 0.15]\n  source-audit --input PATH [--out PATH] [--require-sources CSV] [--max-unknown-ratio 0.15]\n  diff --gephyr PATH --known-good PATH [--rules PATH] [--out PATH] [--known-source SOURCE]\n  gate --gephyr PATH --known-good PATH [--rules PATH] [--out PATH] [--known-source SOURCE]\n  baseline-redact --input PATH --out PATH [--manifest PATH] [--rules PATH] [--source SOURCE] [--platform windows]\n  refresh-baseline --gephyr PATH --official PATH [--baseline-dir DIR] [--rules PATH] [--gate]\n\nManifest metadata flags: --gephyr-version, --gephyr-exe-path, --antigravity-version, --antigravity-exe-path, --language-server-version, --language-server-exe-path, --capture-date"
    );
}

fn resolve_default_api_key() -> Option<String> {
    let user_home = std::env::var("USERPROFILE")
        .ok()
        .or_else(|| std::env::var("HOME").ok())?;
    let cfg_path = PathBuf::from(user_home).join(".gephyr").join("config.json");
    if !cfg_path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(cfg_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.get("proxy")
        .and_then(|v| v.get("api_key"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

async fn admin_call(
    method: reqwest::Method,
    url: &str,
    api_key: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    let mut req = client
        .request(method, url)
        .header("Authorization", format!("Bearer {}", api_key));

    if let Some(payload) = body {
        req = req.json(&payload);
    }

    let response = req
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    if !status.is_success() {
        return Err(format!("request failed [{}]: {}", status, text));
    }

    serde_json::from_str::<serde_json::Value>(&text)
        .map_err(|e| format!("invalid json response: {} | body={}", e, text))
}

async fn run_capture_gephyr(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("capture-gephyr requires subcommand: start|stop|status|export".to_string());
    }

    let action = args[0].as_str();
    let parsed = parse_args(&args[1..]);

    let api_base = parsed
        .values
        .get("api-base")
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:8045".to_string());
    let api_key = parsed
        .values
        .get("api-key")
        .cloned()
        .or_else(resolve_default_api_key)
        .ok_or_else(|| {
            "missing api key (pass --api-key or configure ~/.gephyr/config.json)".to_string()
        })?;

    let (method, path, body) = match action {
        "start" => (
            reqwest::Method::POST,
            "/api/proxy/parity/capture/start",
            Some(serde_json::json!({
                "ring_limit": parsed.values.get("ring-limit").and_then(|v| v.parse::<usize>().ok()),
                "raw_output_dir": parsed.values.get("raw-output-dir"),
                "redacted_output_dir": parsed.values.get("redacted-output-dir")
            })),
        ),
        "stop" => (
            reqwest::Method::POST,
            "/api/proxy/parity/capture/stop",
            None,
        ),
        "status" => (
            reqwest::Method::GET,
            "/api/proxy/parity/capture/status",
            None,
        ),
        "export" => (
            reqwest::Method::POST,
            "/api/proxy/parity/capture/export",
            Some(serde_json::json!({
                "raw_path": parsed.values.get("raw-path"),
                "redacted_path": parsed.values.get("redacted-path"),
                "rules_path": parsed.values.get("rules")
            })),
        ),
        other => {
            return Err(format!(
                "unsupported capture-gephyr subcommand: {} (expected start|stop|status|export)",
                other
            ))
        }
    };

    let url = format!("{}{}", api_base.trim_end_matches('/'), path);
    let response = admin_call(method, &url, &api_key, body).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_else(|_| response.to_string())
    );

    Ok(())
}

fn run_capture_official(args: &[String]) -> Result<(), String> {
    let parsed = parse_args(args);
    if !parsed.flags.contains("guided") {
        return Err("capture-official requires --guided".to_string());
    }

    let script = parsed
        .values
        .get("script")
        .cloned()
        .unwrap_or_else(|| "scripts/live-google-parity-verify-interactive.ps1".to_string());

    if !parsed.flags.contains("skip-guided-run") {
        if !PathBuf::from(&script).exists() {
            return Err(format!("guided capture script not found: {}", script));
        }

        let mut command = std::process::Command::new("powershell");
        command
            .arg("-NoProfile")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(script)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());

        let status = command
            .status()
            .map_err(|e| format!("failed to launch guided capture: {}", e))?;

        if !status.success() {
            return Err(format!(
                "guided official capture failed with status {}",
                status
            ));
        }
    }

    let known_good_path = parsed
        .values
        .get("known-good-path")
        .cloned()
        .unwrap_or_else(|| "output/known_good.jsonl".to_string());
    let rules = load_rules(parsed.values.get("rules").map(|s| s.as_str()))?;
    let out_dir = PathBuf::from(
        parsed
            .values
            .get("bundle-out-dir")
            .cloned()
            .unwrap_or_else(|| "output/parity/official".to_string()),
    );

    let loaded = parity::ingest::load_trace(PathBuf::from(&known_good_path).as_path(), None)?;
    let official_records = if parsed.flags.contains("all-endpoints") {
        loaded
    } else {
        parity::ingest::filter_google_endpoints(loaded)
    };
    if official_records.is_empty() {
        return Err(format!(
            "official capture produced no records after filtering: {}",
            known_good_path
        ));
    }

    let metadata = ManifestMetadata::from_args(
        &parsed,
        known_good_path.clone(),
        collect_source_labels(&official_records),
    );
    write_tagged_bundle_set(&official_records, &rules, &out_dir, &metadata)?;

    let required_sources = parse_required_sources(&parsed)?;
    let max_unknown_ratio = parse_f64_arg(&parsed, "max-unknown-ratio", 0.15)?;
    let audit_report = build_source_audit_report(
        &official_records,
        &known_good_path,
        &required_sources,
        max_unknown_ratio,
    );
    let audit_report_path = PathBuf::from(
        parsed
            .values
            .get("audit-report-path")
            .cloned()
            .unwrap_or_else(|| {
                out_dir
                    .join("source_audit.json")
                    .to_string_lossy()
                    .to_string()
            }),
    );
    write_source_audit_report(&audit_report_path, &audit_report)?;

    let source_counts = split_by_source(&official_records)
        .into_iter()
        .map(|(key, v)| format!("{}={}", key, v.len()))
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "Wrote official tagged bundle set under {} (records={}, sources: {})",
        out_dir.display(),
        official_records.len(),
        source_counts
    );
    println!(
        "Source audit: pass={} unknown_ratio={:.3} report={}",
        audit_report.pass,
        audit_report.unknown_ratio,
        audit_report_path.display()
    );

    if !audit_report.pass && !parsed.flags.contains("no-audit-gate") {
        return Err(
            "capture-official source audit failed (use --no-audit-gate to bypass)".to_string(),
        );
    }

    Ok(())
}

fn parse_source_hint(raw: Option<&str>) -> Option<parity::types::RequestSource> {
    let raw = raw?.trim().to_ascii_lowercase();
    match raw.as_str() {
        "gephyr" => Some(parity::types::RequestSource::Gephyr),
        "known_good" => Some(parity::types::RequestSource::KnownGood),
        "antigravity" | "antigravity_exe" => Some(parity::types::RequestSource::AntigravityExe),
        "language_server_windows_x64" | "language_server_windows_x64.exe" => {
            Some(parity::types::RequestSource::LanguageServerWindowsX64)
        }
        "unknown" => Some(parity::types::RequestSource::Unknown),
        _ => None,
    }
}

fn load_rules(path: Option<&str>) -> Result<parity::types::ParityRuleSet, String> {
    if let Some(path) = path {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read rules file {}: {}", path, e))?;
        serde_json::from_str::<parity::types::ParityRuleSet>(&content)
            .map_err(|e| format!("invalid rules json in {}: {}", path, e))
    } else {
        Ok(parity::types::ParityRuleSet::default())
    }
}

fn split_by_source(
    fingerprints: &[parity::types::RequestFingerprint],
) -> BTreeMap<String, Vec<parity::types::RequestFingerprint>> {
    let mut grouped: BTreeMap<String, Vec<parity::types::RequestFingerprint>> = BTreeMap::new();
    for fp in fingerprints {
        grouped
            .entry(stable_source_key(&fp.source).to_string())
            .or_default()
            .push(fp.clone());
    }
    grouped
}

fn write_jsonl(
    path: &Path,
    fingerprints: &[parity::types::RequestFingerprint],
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }

    let mut file = std::fs::File::create(path)
        .map_err(|e| format!("failed to create {}: {}", path.display(), e))?;
    use std::io::Write;
    for fp in fingerprints {
        let line = serde_json::to_string(fp).map_err(|e| format!("serialize failed: {}", e))?;
        writeln!(file, "{}", line).map_err(|e| format!("write failed: {}", e))?;
    }
    Ok(())
}

fn write_manifest(
    manifest_path: &Path,
    redacted_baseline_path: &Path,
    record_count: usize,
    checksum_sha256: &str,
    metadata: &ManifestMetadata,
) -> Result<(), String> {
    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }

    let manifest = serde_json::json!({
        "schema_version": parity::types::PARITY_SCHEMA_VERSION,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "capture_mode": metadata.capture_mode,
        "platform": metadata.platform,
        "capture_date": metadata.capture_date,
        "input_path": metadata.input_path,
        "redacted_baseline_path": relative_display_path(redacted_baseline_path),
        "record_count": record_count,
        "checksum_sha256": checksum_sha256,
        "ruleset_version": metadata.ruleset_version,
        "executable_versions": {
            "gephyr": metadata.gephyr_version,
            "antigravity_exe": metadata.antigravity_version,
            "language_server_windows_x64": metadata.language_server_version,
        },
        "capture_sources": metadata.capture_sources,
    });

    std::fs::write(
        manifest_path,
        serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("failed to serialize manifest: {}", e))?,
    )
    .map_err(|e| format!("failed to write {}: {}", manifest_path.display(), e))
}

fn write_tagged_bundle_set(
    fingerprints: &[parity::types::RequestFingerprint],
    rules: &parity::types::ParityRuleSet,
    out_dir: &Path,
    metadata: &ManifestMetadata,
) -> Result<(), String> {
    let raw_dir = out_dir.join("raw");
    let redacted_dir = out_dir.join("redacted");
    std::fs::create_dir_all(&raw_dir)
        .map_err(|e| format!("failed to create {}: {}", raw_dir.display(), e))?;
    std::fs::create_dir_all(&redacted_dir)
        .map_err(|e| format!("failed to create {}: {}", redacted_dir.display(), e))?;

    let combined_raw = raw_dir.join("official.tagged.combined.jsonl");
    write_jsonl(&combined_raw, fingerprints)?;
    let combined_redacted_records = parity::ingest::canonicalize_fingerprints(fingerprints, rules);
    let combined_redacted = redacted_dir.join("official.tagged.combined.jsonl");
    write_jsonl(&combined_redacted, &combined_redacted_records)?;
    let combined_checksum = file_sha256(&combined_redacted)?;
    write_manifest(
        &manifest_path_for_jsonl(&combined_redacted),
        &combined_redacted,
        combined_redacted_records.len(),
        &combined_checksum,
        metadata,
    )?;

    let by_source = split_by_source(fingerprints);
    for (source_key, source_records) in by_source {
        let raw_path = raw_dir.join(format!("official.tagged.{}.jsonl", source_key));
        write_jsonl(&raw_path, &source_records)?;

        let redacted_records = parity::ingest::canonicalize_fingerprints(&source_records, rules);
        let redacted_path = redacted_dir.join(format!("official.tagged.{}.jsonl", source_key));
        write_jsonl(&redacted_path, &redacted_records)?;

        let checksum = file_sha256(&redacted_path)?;
        let mut source_metadata = metadata.clone();
        source_metadata.capture_sources = vec![source_key.clone()];
        write_manifest(
            &manifest_path_for_jsonl(&redacted_path),
            &redacted_path,
            redacted_records.len(),
            &checksum,
            &source_metadata,
        )?;
    }

    Ok(())
}

fn write_source_audit_report(path: &Path, report: &SourceAuditReport) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }
    std::fs::write(
        path,
        serde_json::to_string_pretty(report)
            .map_err(|e| format!("failed to serialize source audit report: {}", e))?,
    )
    .map_err(|e| format!("failed to write {}: {}", path.display(), e))
}

fn run_source_audit(args: &[String]) -> Result<(), String> {
    let parsed = parse_args(args);
    let input_path = parsed
        .values
        .get("input")
        .ok_or_else(|| "missing --input path".to_string())?;
    let out_path = PathBuf::from(
        parsed
            .values
            .get("out")
            .cloned()
            .unwrap_or_else(|| "output/parity/source_audit.json".to_string()),
    );

    let loaded = parity::ingest::load_trace(PathBuf::from(input_path).as_path(), None)?;
    let scoped = if parsed.flags.contains("all-endpoints") {
        loaded
    } else {
        parity::ingest::filter_google_endpoints(loaded)
    };
    if scoped.is_empty() {
        return Err(format!(
            "source-audit found no records after filtering: {}",
            input_path
        ));
    }

    let required_sources = parse_required_sources(&parsed)?;
    let max_unknown_ratio = parse_f64_arg(&parsed, "max-unknown-ratio", 0.15)?;
    let report =
        build_source_audit_report(&scoped, input_path, &required_sources, max_unknown_ratio);
    write_source_audit_report(&out_path, &report)?;

    println!(
        "Source audit: pass={} scoped_records={} unknown_ratio={:.3} report={}",
        report.pass,
        report.scoped_records,
        report.unknown_ratio,
        out_path.display()
    );
    if !report.missing_required_sources.is_empty() {
        println!(
            "Missing required sources: {}",
            report.missing_required_sources.join(", ")
        );
    }
    if !report.pass {
        return Err("source-audit gate failed".to_string());
    }

    Ok(())
}

fn run_diff_like(args: &[String], gate_mode: bool) -> Result<(), String> {
    let parsed = parse_args(args);

    let gephyr_path = parsed
        .values
        .get("gephyr")
        .ok_or_else(|| "missing --gephyr path".to_string())?;
    let known_good_path = parsed
        .values
        .get("known-good")
        .ok_or_else(|| "missing --known-good path".to_string())?;

    let gephyr = parity::ingest::filter_google_endpoints(parity::ingest::load_trace(
        PathBuf::from(gephyr_path).as_path(),
        Some(parity::types::RequestSource::Gephyr),
    )?);
    let known = parity::ingest::filter_google_endpoints(parity::ingest::load_trace(
        PathBuf::from(known_good_path).as_path(),
        parse_source_hint(parsed.values.get("known-source").map(|s| s.as_str()))
            .or(Some(parity::types::RequestSource::KnownGood)),
    )?);

    let rules = load_rules(parsed.values.get("rules").map(|s| s.as_str()))?;

    let report = parity::diff::compare(
        &gephyr,
        &known,
        &rules,
        parity::types::GatePolicy::AnyDifferenceFails,
    );

    println!(
        "Parity diff: verdict={:?}, gate_pass={}, endpoints={}, compliance={:.3}",
        report.overall_verdict, report.gate_pass, report.endpoint_count, report.compliance_score
    );

    if let Some(out_path) = parsed.values.get("out") {
        let path = PathBuf::from(out_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
        }
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&report)
                .map_err(|e| format!("failed to serialize report: {}", e))?,
        )
        .map_err(|e| format!("failed to write {}: {}", path.display(), e))?;
        println!("Wrote report: {}", path.display());
    }

    if gate_mode && !report.gate_pass {
        return Err("gate failed: parity differences detected".to_string());
    }

    Ok(())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    use sha2::Digest;
    let bytes =
        std::fs::read(path).map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    let digest = sha2::Sha256::digest(bytes);
    Ok(format!("{:x}", digest))
}

fn run_baseline_redact(args: &[String]) -> Result<(), String> {
    let parsed = parse_args(args);
    let input = parsed
        .values
        .get("input")
        .ok_or_else(|| "missing --input path".to_string())?;
    let out = parsed
        .values
        .get("out")
        .ok_or_else(|| "missing --out path".to_string())?;

    let source = parse_source_hint(parsed.values.get("source").map(|s| s.as_str()))
        .or(Some(parity::types::RequestSource::KnownGood));
    let rules = load_rules(parsed.values.get("rules").map(|s| s.as_str()))?;

    let loaded = parity::ingest::load_trace(PathBuf::from(input).as_path(), source.clone())?;
    let google_only = parity::ingest::filter_google_endpoints(loaded);
    let redacted = parity::ingest::canonicalize_fingerprints(&google_only, &rules);

    let out_path = PathBuf::from(out);
    write_jsonl(&out_path, &redacted)?;

    let manifest_path = parsed
        .values
        .get("manifest")
        .map(PathBuf::from)
        .unwrap_or_else(|| out_path.with_extension("manifest.json"));

    let checksum = file_sha256(&out_path)?;
    let mut metadata =
        ManifestMetadata::from_args(&parsed, input.to_string(), collect_source_labels(&redacted));
    if let Some(source) = source {
        metadata.capture_sources = vec![stable_source_key(&source).to_string()];
    }
    write_manifest(
        &manifest_path,
        &out_path,
        redacted.len(),
        &checksum,
        &metadata,
    )?;

    println!("Wrote redacted baseline: {}", out_path.display());
    println!("Wrote manifest: {}", manifest_path.display());

    Ok(())
}

fn run_refresh_baseline(args: &[String]) -> Result<(), String> {
    let parsed = parse_args(args);
    let gephyr_input = parsed
        .values
        .get("gephyr")
        .ok_or_else(|| "missing --gephyr path".to_string())?;
    let official_input = parsed
        .values
        .get("official")
        .ok_or_else(|| "missing --official path".to_string())?;
    let baseline_dir = PathBuf::from(
        parsed
            .values
            .get("baseline-dir")
            .cloned()
            .unwrap_or_else(|| "parity/baselines/redacted/windows/default".to_string()),
    );

    let rules = load_rules(parsed.values.get("rules").map(|s| s.as_str()))?;

    let gephyr_loaded = parity::ingest::load_trace(
        PathBuf::from(gephyr_input).as_path(),
        Some(parity::types::RequestSource::Gephyr),
    )?;
    let gephyr_google = parity::ingest::filter_google_endpoints(gephyr_loaded);
    if gephyr_google.is_empty() {
        return Err(format!(
            "gephyr capture has no google records: {}",
            gephyr_input
        ));
    }
    let gephyr_redacted = parity::ingest::canonicalize_fingerprints(&gephyr_google, &rules);

    let official_loaded =
        parity::ingest::load_trace(PathBuf::from(official_input).as_path(), None)?;
    let official_google = parity::ingest::filter_google_endpoints(official_loaded);
    if official_google.is_empty() {
        return Err(format!(
            "official capture has no google records: {}",
            official_input
        ));
    }
    let official_redacted = parity::ingest::canonicalize_fingerprints(&official_google, &rules);

    std::fs::create_dir_all(&baseline_dir)
        .map_err(|e| format!("failed to create {}: {}", baseline_dir.display(), e))?;

    let gephyr_out = baseline_dir.join("gephyr.reference.jsonl");
    write_jsonl(&gephyr_out, &gephyr_redacted)?;
    let gephyr_checksum = file_sha256(&gephyr_out)?;
    let mut gephyr_meta = ManifestMetadata::from_args(
        &parsed,
        gephyr_input.to_string(),
        vec!["gephyr".to_string()],
    );
    gephyr_meta.capture_sources = vec!["gephyr".to_string()];
    write_manifest(
        &manifest_path_for_jsonl(&gephyr_out),
        &gephyr_out,
        gephyr_redacted.len(),
        &gephyr_checksum,
        &gephyr_meta,
    )?;

    let known_default_out = baseline_dir.join("known_good.default.jsonl");
    write_jsonl(&known_default_out, &official_redacted)?;
    let known_default_checksum = file_sha256(&known_default_out)?;
    let default_sources = collect_source_labels(&official_redacted);
    let known_meta = ManifestMetadata::from_args(
        &parsed,
        official_input.to_string(),
        if default_sources.is_empty() {
            vec!["known_good".to_string()]
        } else {
            default_sources
        },
    );
    write_manifest(
        &manifest_path_for_jsonl(&known_default_out),
        &known_default_out,
        official_redacted.len(),
        &known_default_checksum,
        &known_meta,
    )?;

    let official_by_source = split_by_source(&official_redacted);
    for (source, records) in &official_by_source {
        if source == "gephyr" {
            continue;
        }
        let out = baseline_dir.join(format!("known_good.{}.jsonl", source));
        write_jsonl(&out, records)?;
        let checksum = file_sha256(&out)?;
        let mut source_meta =
            ManifestMetadata::from_args(&parsed, official_input.to_string(), vec![source.clone()]);
        source_meta.capture_sources = vec![source.clone()];
        write_manifest(
            &manifest_path_for_jsonl(&out),
            &out,
            records.len(),
            &checksum,
            &source_meta,
        )?;
    }

    let gate_enabled = parsed.flags.contains("gate");
    if gate_enabled {
        let reports_dir = baseline_dir.join("reports");
        std::fs::create_dir_all(&reports_dir)
            .map_err(|e| format!("failed to create {}: {}", reports_dir.display(), e))?;

        let default_report = parity::diff::compare(
            &gephyr_redacted,
            &official_redacted,
            &rules,
            parity::types::GatePolicy::AnyDifferenceFails,
        );
        let default_report_path = reports_dir.join("gate.default.json");
        std::fs::write(
            &default_report_path,
            serde_json::to_string_pretty(&default_report)
                .map_err(|e| format!("failed to serialize default gate report: {}", e))?,
        )
        .map_err(|e| format!("failed to write {}: {}", default_report_path.display(), e))?;

        let mut all_passed = default_report.gate_pass;
        for (source, records) in &official_by_source {
            if source == "gephyr" {
                continue;
            }
            let report = parity::diff::compare(
                &gephyr_redacted,
                records,
                &rules,
                parity::types::GatePolicy::AnyDifferenceFails,
            );
            let report_path = reports_dir.join(format!("gate.{}.json", source));
            std::fs::write(
                &report_path,
                serde_json::to_string_pretty(&report)
                    .map_err(|e| format!("failed to serialize {} gate report: {}", source, e))?,
            )
            .map_err(|e| format!("failed to write {}: {}", report_path.display(), e))?;
            all_passed = all_passed && report.gate_pass;
        }

        if !all_passed {
            return Err(format!(
                "refresh-baseline gate failed; see reports under {}",
                reports_dir.display()
            ));
        }
    }

    println!(
        "Refreshed baseline under {} (gephyr={}, official={}, per-source={})",
        baseline_dir.display(),
        gephyr_redacted.len(),
        official_redacted.len(),
        official_by_source.len()
    );
    if gate_enabled {
        println!("Gate checks passed.");
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        std::process::exit(1);
    }

    let command = args[0].as_str();
    let result = match command {
        "capture-gephyr" => run_capture_gephyr(&args[1..]).await,
        "capture-official" => run_capture_official(&args[1..]),
        "source-audit" => run_source_audit(&args[1..]),
        "diff" => run_diff_like(&args[1..], false),
        "gate" => run_diff_like(&args[1..], true),
        "baseline-redact" => run_baseline_redact(&args[1..]),
        "refresh-baseline" => run_refresh_baseline(&args[1..]),
        _ => {
            print_help();
            Err(format!("unknown command: {}", command))
        }
    };

    if let Err(error) = result {
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gephyr_lib::parity::types::{RequestFingerprint, RequestSource};

    fn write_fixture(path: &Path, lines: &[&str]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture parent");
        }
        std::fs::write(path, lines.join("\n")).expect("write fixture");
    }

    #[test]
    fn gate_passes_on_matching_fixtures() {
        let tmp = std::env::temp_dir().join(format!(
            "gephyr-parity-cli-test-pass-{}",
            uuid::Uuid::new_v4()
        ));
        let gephyr = tmp.join("gephyr.jsonl");
        let known = tmp.join("known.jsonl");

        write_fixture(
            &gephyr,
            &[
                r#"{"schema_version":"v1","source":"gephyr","method":"POST","url":"https://cloudcode-pa.googleapis.com/v1internal:test","normalized_endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":[["content-type","application/json"],["user-agent","antigravity google-api-nodejs-client/10.3.0"]],"status_code":200,"latency_ms":200}"#,
            ],
        );
        write_fixture(
            &known,
            &[
                r#"{"schema_version":"v1","source":"antigravity_exe","method":"POST","url":"https://cloudcode-pa.googleapis.com/v1internal:test","normalized_endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":[["content-type","application/json"],["user-agent","antigravity google-api-nodejs-client/10.3.0"]],"status_code":200,"latency_ms":200}"#,
            ],
        );

        let result = run_diff_like(
            &[
                "--gephyr".to_string(),
                gephyr.to_string_lossy().to_string(),
                "--known-good".to_string(),
                known.to_string_lossy().to_string(),
            ],
            true,
        );

        let _ = std::fs::remove_dir_all(&tmp);
        assert!(result.is_ok());
    }

    #[test]
    fn gate_fails_on_mismatch() {
        let tmp = std::env::temp_dir().join(format!(
            "gephyr-parity-cli-test-fail-{}",
            uuid::Uuid::new_v4()
        ));
        let gephyr = tmp.join("gephyr.jsonl");
        let known = tmp.join("known.jsonl");

        write_fixture(
            &gephyr,
            &[
                r#"{"schema_version":"v1","source":"gephyr","method":"POST","url":"https://cloudcode-pa.googleapis.com/v1internal:test","normalized_endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":[["content-type","application/json"],["user-agent","antigravity google-api-nodejs-client/10.3.0"]],"status_code":200,"latency_ms":200}"#,
            ],
        );
        write_fixture(
            &known,
            &[
                r#"{"schema_version":"v1","source":"antigravity_exe","method":"POST","url":"https://cloudcode-pa.googleapis.com/v1internal:test","normalized_endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":[["content-type","application/json"],["user-agent","different-agent/0.0"]],"status_code":200,"latency_ms":200}"#,
            ],
        );

        let result = run_diff_like(
            &[
                "--gephyr".to_string(),
                gephyr.to_string_lossy().to_string(),
                "--known-good".to_string(),
                known.to_string_lossy().to_string(),
            ],
            true,
        );

        let _ = std::fs::remove_dir_all(&tmp);
        assert!(result.is_err());
    }

    #[test]
    fn write_tagged_bundle_set_emits_per_source_outputs() {
        let tmp = std::env::temp_dir().join(format!(
            "gephyr-parity-bundle-test-{}",
            uuid::Uuid::new_v4()
        ));
        let out_dir = tmp.join("official_bundle");

        let fps = vec![
            RequestFingerprint::new(
                RequestSource::AntigravityExe,
                "POST".to_string(),
                "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist".to_string(),
                "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist".to_string(),
                vec![("user-agent".to_string(), "antigravity".to_string())],
                None,
                Some(1),
                Some(200),
                Some(200),
                Some("s1".to_string()),
            ),
            RequestFingerprint::new(
                RequestSource::LanguageServerWindowsX64,
                "POST".to_string(),
                "https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels".to_string(),
                "https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels".to_string(),
                vec![(
                    "user-agent".to_string(),
                    "language_server_windows_x64".to_string(),
                )],
                None,
                Some(2),
                Some(300),
                Some(200),
                Some("s1".to_string()),
            ),
        ];

        let metadata = ManifestMetadata {
            capture_mode: "guided_semi_auto".to_string(),
            platform: "windows".to_string(),
            capture_date: "2026-03-02".to_string(),
            input_path: "output/known_good.jsonl".to_string(),
            ruleset_version: "standard_v1".to_string(),
            gephyr_version: None,
            antigravity_version: Some("1.0.0".to_string()),
            language_server_version: Some("1.0.1".to_string()),
            capture_sources: vec![
                "antigravity_exe".to_string(),
                "language_server_windows_x64".to_string(),
            ],
        };

        write_tagged_bundle_set(
            &fps,
            &parity::types::ParityRuleSet::default(),
            &out_dir,
            &metadata,
        )
        .expect("write tagged bundle set");

        assert!(out_dir.join("raw/official.tagged.combined.jsonl").exists());
        assert!(out_dir
            .join("redacted/official.tagged.combined.jsonl")
            .exists());
        assert!(out_dir
            .join("redacted/official.tagged.antigravity_exe.jsonl")
            .exists());
        assert!(out_dir
            .join("redacted/official.tagged.language_server_windows_x64.jsonl")
            .exists());
        assert!(out_dir
            .join("redacted/official.tagged.antigravity_exe.manifest.json")
            .exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn refresh_baseline_writes_default_and_source_files() {
        let tmp = std::env::temp_dir().join(format!(
            "gephyr-parity-refresh-test-{}",
            uuid::Uuid::new_v4()
        ));
        let gephyr = tmp.join("gephyr.jsonl");
        let official = tmp.join("official.jsonl");
        let baseline_dir = tmp.join("baseline");

        write_fixture(
            &gephyr,
            &[
                r#"{"schema_version":"v1","source":"gephyr","method":"POST","url":"https://cloudcode-pa.googleapis.com/v1internal:test","normalized_endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":[["content-type","application/json"],["user-agent","antigravity google-api-nodejs-client/10.3.0"]],"status_code":200,"latency_ms":200}"#,
            ],
        );
        write_fixture(
            &official,
            &[
                r#"{"method":"POST","endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":{"user-agent":"antigravity/1.0","content-type":"application/json"}}"#,
                r#"{"method":"POST","endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":{"user-agent":"language_server_windows_x64/1.0","content-type":"application/json"}}"#,
            ],
        );

        let result = run_refresh_baseline(&[
            "--gephyr".to_string(),
            gephyr.to_string_lossy().to_string(),
            "--official".to_string(),
            official.to_string_lossy().to_string(),
            "--baseline-dir".to_string(),
            baseline_dir.to_string_lossy().to_string(),
        ]);
        assert!(result.is_ok());

        assert!(baseline_dir.join("gephyr.reference.jsonl").exists());
        assert!(baseline_dir.join("known_good.default.jsonl").exists());
        assert!(baseline_dir
            .join("known_good.antigravity_exe.jsonl")
            .exists());
        assert!(baseline_dir
            .join("known_good.language_server_windows_x64.jsonl")
            .exists());
        assert!(baseline_dir
            .join("known_good.language_server_windows_x64.manifest.json")
            .exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn source_audit_fails_when_required_sources_missing() {
        let tmp = std::env::temp_dir().join(format!(
            "gephyr-parity-source-audit-fail-{}",
            uuid::Uuid::new_v4()
        ));
        let input = tmp.join("official.jsonl");
        write_fixture(
            &input,
            &[
                r#"{"method":"POST","endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":{"user-agent":"antigravity/1.0","content-type":"application/json"}}"#,
            ],
        );

        let result = run_source_audit(&[
            "--input".to_string(),
            input.to_string_lossy().to_string(),
            "--out".to_string(),
            tmp.join("audit.json").to_string_lossy().to_string(),
        ]);

        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn source_audit_passes_when_requirements_are_met() {
        let tmp = std::env::temp_dir().join(format!(
            "gephyr-parity-source-audit-pass-{}",
            uuid::Uuid::new_v4()
        ));
        let input = tmp.join("official.jsonl");
        write_fixture(
            &input,
            &[
                r#"{"method":"POST","endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":{"user-agent":"antigravity/1.0","content-type":"application/json"}}"#,
                r#"{"method":"POST","endpoint":"https://cloudcode-pa.googleapis.com/v1internal:test","headers":{"user-agent":"language_server_windows_x64/1.0","content-type":"application/json"}}"#,
            ],
        );

        let result = run_source_audit(&[
            "--input".to_string(),
            input.to_string_lossy().to_string(),
            "--out".to_string(),
            tmp.join("audit.json").to_string_lossy().to_string(),
            "--max-unknown-ratio".to_string(),
            "0.0".to_string(),
        ]);

        assert!(result.is_ok());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn manifest_metadata_prefers_explicit_version_flags() {
        let parsed = parse_args(&[
            "--gephyr-version".to_string(),
            "1.16.16".to_string(),
            "--antigravity-version".to_string(),
            "2.0.0".to_string(),
            "--language-server-version".to_string(),
            "3.1.4".to_string(),
        ]);

        let metadata = ManifestMetadata::from_args(
            &parsed,
            "input.jsonl".to_string(),
            vec!["known_good".to_string()],
        );
        assert_eq!(metadata.gephyr_version.as_deref(), Some("1.16.16"));
        assert_eq!(metadata.antigravity_version.as_deref(), Some("2.0.0"));
        assert_eq!(metadata.language_server_version.as_deref(), Some("3.1.4"));
    }
}
