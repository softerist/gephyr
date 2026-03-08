use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use reqwest::header::HeaderMap;

use super::ingest::canonicalize_fingerprints;
use super::types::{
    BodyShape, ParityCaptureStatus, ParityDiffReport, ParityExportResult, ParityRuleSet,
    RequestFingerprint, RequestSource,
};

const DEFAULT_RING_LIMIT: usize = 20_000;
const DEFAULT_RAW_OUTPUT_DIR: &str = "output/parity/raw";
const DEFAULT_REDACTED_OUTPUT_DIR: &str = "output/parity/redacted";

#[derive(Debug, Clone)]
pub struct CaptureStartConfig {
    pub ring_limit: Option<usize>,
    pub raw_output_dir: Option<PathBuf>,
    pub redacted_output_dir: Option<PathBuf>,
}

impl Default for CaptureStartConfig {
    fn default() -> Self {
        Self {
            ring_limit: Some(DEFAULT_RING_LIMIT),
            raw_output_dir: Some(PathBuf::from(DEFAULT_RAW_OUTPUT_DIR)),
            redacted_output_dir: Some(PathBuf::from(DEFAULT_REDACTED_OUTPUT_DIR)),
        }
    }
}

#[derive(Debug)]
struct ParityManager {
    enabled: bool,
    session_id: Option<String>,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    ring_limit: usize,
    raw_output_dir: PathBuf,
    redacted_output_dir: PathBuf,
    capture_buffer: VecDeque<RequestFingerprint>,
    latest_diff: Option<ParityDiffReport>,
}

impl Default for ParityManager {
    fn default() -> Self {
        Self {
            enabled: false,
            session_id: None,
            started_at: None,
            ring_limit: DEFAULT_RING_LIMIT,
            raw_output_dir: PathBuf::from(DEFAULT_RAW_OUTPUT_DIR),
            redacted_output_dir: PathBuf::from(DEFAULT_REDACTED_OUTPUT_DIR),
            capture_buffer: VecDeque::new(),
            latest_diff: None,
        }
    }
}

fn manager() -> &'static Mutex<ParityManager> {
    static MANAGER: OnceLock<Mutex<ParityManager>> = OnceLock::new();
    MANAGER.get_or_init(|| Mutex::new(ParityManager::default()))
}

fn now_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn generate_session_id() -> String {
    format!(
        "parity-{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        uuid::Uuid::new_v4().simple()
    )
}

pub fn start_capture(config: CaptureStartConfig) -> ParityCaptureStatus {
    let mut lock = manager().lock().expect("parity manager lock poisoned");
    lock.enabled = true;
    lock.session_id = Some(generate_session_id());
    lock.started_at = Some(chrono::Utc::now());
    lock.ring_limit = config
        .ring_limit
        .unwrap_or(DEFAULT_RING_LIMIT)
        .clamp(1, 1_000_000);

    if let Some(path) = config.raw_output_dir {
        lock.raw_output_dir = path;
    }
    if let Some(path) = config.redacted_output_dir {
        lock.redacted_output_dir = path;
    }

    lock.capture_buffer.clear();

    status_from_manager(&lock)
}

pub fn stop_capture() -> ParityCaptureStatus {
    let mut lock = manager().lock().expect("parity manager lock poisoned");
    let should_flush = lock.enabled && !lock.capture_buffer.is_empty();
    let flush_data = if should_flush {
        Some((
            lock.capture_buffer.iter().cloned().collect::<Vec<_>>(),
            lock.session_id
                .clone()
                .unwrap_or_else(|| "parity-no-session".to_string()),
            lock.raw_output_dir.clone(),
            lock.redacted_output_dir.clone(),
        ))
    } else {
        None
    };
    lock.enabled = false;
    let status = status_from_manager(&lock);
    drop(lock);

    if let Some((fingerprints, session_id, raw_dir, redacted_dir)) = flush_data {
        let raw_output = default_export_path(&raw_dir, &session_id, "raw");
        let redacted_output = default_export_path(&redacted_dir, &session_id, "redacted");
        if let Err(e) = write_jsonl_file(&raw_output, &fingerprints) {
            tracing::warn!(
                "parity stop_capture raw flush failed ({}): {}",
                raw_output.display(),
                e
            );
        }
        let redacted = canonicalize_fingerprints(&fingerprints, &ParityRuleSet::default());
        if let Err(e) = write_jsonl_file(&redacted_output, &redacted) {
            tracing::warn!(
                "parity stop_capture redacted flush failed ({}): {}",
                redacted_output.display(),
                e
            );
        }
    }

    status
}

pub fn clear_capture() {
    let mut lock = manager().lock().expect("parity manager lock poisoned");
    lock.capture_buffer.clear();
}

pub fn capture_status() -> ParityCaptureStatus {
    let lock = manager().lock().expect("parity manager lock poisoned");
    status_from_manager(&lock)
}

fn status_from_manager(manager: &ParityManager) -> ParityCaptureStatus {
    ParityCaptureStatus {
        enabled: manager.enabled,
        session_id: manager.session_id.clone(),
        started_at: manager.started_at.map(|dt| dt.to_rfc3339()),
        captured_count: manager.capture_buffer.len(),
        ring_limit: manager.ring_limit,
    }
}

fn normalized_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
}

pub fn header_map_to_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in headers {
        out.push((
            name.as_str().to_ascii_lowercase(),
            value.to_str().unwrap_or("<non-utf8>").to_string(),
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Record outbound request fingerprint if capture is enabled.
pub fn record_outbound_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body_json: Option<&serde_json::Value>,
    latency_ms: Option<u64>,
    status_code: Option<u16>,
    source: RequestSource,
) {
    let mut lock = manager().lock().expect("parity manager lock poisoned");
    if !lock.enabled {
        return;
    }

    let mut fp = RequestFingerprint::new(
        source,
        method.to_ascii_uppercase(),
        url.to_string(),
        super::ingest::normalize_endpoint(url),
        normalized_headers(headers),
        body_json.map(BodyShape::from_value),
        Some(now_timestamp_ms()),
        latency_ms,
        status_code,
        lock.session_id.clone(),
    );

    if fp.normalized_endpoint.is_empty() {
        fp.normalized_endpoint = super::ingest::normalize_endpoint(&fp.url);
    }

    if lock.capture_buffer.len() >= lock.ring_limit {
        let _ = lock.capture_buffer.pop_front();
    }
    lock.capture_buffer.push_back(fp);
}

pub fn record_reqwest_outbound(
    method: &str,
    url: &str,
    headers: &HeaderMap,
    body_json: Option<&serde_json::Value>,
    started_at: Instant,
    status_code: Option<u16>,
    source: RequestSource,
) {
    let latency = started_at.elapsed().as_millis() as u64;
    let header_pairs = header_map_to_pairs(headers);
    record_outbound_request(
        method,
        url,
        &header_pairs,
        body_json,
        Some(latency),
        status_code,
        source,
    );
}

pub fn captured_snapshot() -> Vec<RequestFingerprint> {
    let lock = manager().lock().expect("parity manager lock poisoned");
    lock.capture_buffer.iter().cloned().collect()
}

pub fn drain_captured() -> Vec<RequestFingerprint> {
    let mut lock = manager().lock().expect("parity manager lock poisoned");
    lock.capture_buffer.drain(..).collect()
}

pub fn set_latest_diff(report: ParityDiffReport) {
    let mut lock = manager().lock().expect("parity manager lock poisoned");
    lock.latest_diff = Some(report);
}

pub fn clear_latest_diff() {
    let mut lock = manager().lock().expect("parity manager lock poisoned");
    lock.latest_diff = None;
}

pub fn latest_diff() -> Option<ParityDiffReport> {
    let lock = manager().lock().expect("parity manager lock poisoned");
    lock.latest_diff.clone()
}

fn default_export_path(base_dir: &Path, session_id: &str, suffix: &str) -> PathBuf {
    base_dir.join(format!("{}.{}.jsonl", session_id, suffix))
}

fn ensure_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }
    Ok(())
}

fn write_jsonl_file(path: &Path, fingerprints: &[RequestFingerprint]) -> Result<(), String> {
    ensure_parent(path)?;
    let mut file = std::fs::File::create(path)
        .map_err(|e| format!("failed to create {}: {}", path.display(), e))?;

    for fp in fingerprints {
        let line = serde_json::to_string(fp).map_err(|e| format!("serialize error: {}", e))?;
        writeln!(file, "{}", line).map_err(|e| format!("write error: {}", e))?;
    }

    Ok(())
}

pub fn export_dual_artifacts(
    raw_path: Option<&Path>,
    redacted_path: Option<&Path>,
    rules: Option<&ParityRuleSet>,
) -> Result<ParityExportResult, String> {
    let lock = manager().lock().expect("parity manager lock poisoned");
    let fingerprints: Vec<RequestFingerprint> = lock.capture_buffer.iter().cloned().collect();
    let session_id = lock
        .session_id
        .clone()
        .unwrap_or_else(|| "parity-no-session".to_string());

    let raw_output = raw_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| default_export_path(&lock.raw_output_dir, &session_id, "raw"));
    let redacted_output = redacted_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| default_export_path(&lock.redacted_output_dir, &session_id, "redacted"));
    drop(lock);

    write_jsonl_file(&raw_output, &fingerprints)?;

    let rules = rules.cloned().unwrap_or_default();
    let canonicalized = canonicalize_fingerprints(&fingerprints, &rules);
    write_jsonl_file(&redacted_output, &canonicalized)?;

    Ok(ParityExportResult {
        raw_path: raw_output.display().to_string(),
        redacted_path: redacted_output.display().to_string(),
        count: fingerprints.len(),
        session_id: Some(session_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::parity::types::RequestSource;
    use serde_json::json;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn capture_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("capture test lock")
    }

    #[test]
    fn capture_is_opt_in_and_respects_ring_limit() {
        let _guard = capture_test_lock();
        clear_capture();
        stop_capture();
        record_outbound_request(
            "GET",
            "https://example.com",
            &[],
            None,
            Some(1),
            Some(200),
            RequestSource::Gephyr,
        );
        assert!(captured_snapshot().is_empty());

        let mut cfg = CaptureStartConfig::default();
        cfg.ring_limit = Some(2);
        let status = start_capture(cfg);
        assert!(status.enabled);

        for idx in 0..3 {
            record_outbound_request(
                "POST",
                &format!("https://cloudcode-pa.googleapis.com/v1internal:test{}", idx),
                &[("content-type".to_string(), "application/json".to_string())],
                Some(&json!({"i": idx})),
                Some(idx),
                Some(200),
                RequestSource::Gephyr,
            );
        }

        let snapshot = captured_snapshot();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot[0].url.contains("test1"));
        assert!(snapshot[1].url.contains("test2"));
    }

    #[test]
    fn export_writes_raw_and_redacted_files() {
        let _guard = capture_test_lock();
        let _ = start_capture(CaptureStartConfig::default());
        clear_capture();
        record_outbound_request(
            "POST",
            "https://cloudcode-pa.googleapis.com/v1internal:test",
            &[("authorization".to_string(), "Bearer test".to_string())],
            Some(&json!({"x": 1})),
            Some(12),
            Some(200),
            RequestSource::Gephyr,
        );

        let tmp_dir = std::env::temp_dir().join("gephyr_parity_capture_export");
        let raw = tmp_dir.join("capture.raw.jsonl");
        let redacted = tmp_dir.join("capture.redacted.jsonl");

        let result = export_dual_artifacts(Some(&raw), Some(&redacted), None).expect("export");
        assert_eq!(result.count, 1);
        assert!(raw.exists());
        assert!(redacted.exists());

        let redacted_content = std::fs::read_to_string(&redacted).expect("read redacted");
        assert!(redacted_content.contains("<redacted>"));

        let _ = std::fs::remove_file(raw);
        let _ = std::fs::remove_file(redacted);
        let _ = std::fs::remove_dir_all(tmp_dir);

        // Clean up global state to avoid leaking into other tests.
        stop_capture();
        clear_capture();
    }
}
