#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

KNOWN_GOOD_PATH="output/known_good.discovery.jsonl"
OUT_GEPHYR_PATH="output/gephyr_google_outbound_headers.latest.jsonl"
STARTUP_TIMEOUT_SECONDS=90
ALLOWLIST_PATH="scripts/allowlists/antigravity_google_endpoints_default_chat.txt"
REQUIRE_OAUTH_RELINK=false
ALLOW_MIMIC_TOKEN_REFRESH=false
INCLUDE_CHAT_PROBE=false
INCLUDE_AUTH_EVENT_PROBES=false
INCLUDE_EXTENDED_FLOW=false
REFRESH_INCLUSIVE=false
ALLOW_MISSING_ALLOWLIST_ENDPOINTS=false
SKIP_ALLOWLIST_VALIDATION=false
SKIP_REPO_GATE=false
SKIP_BASELINE_GATE=false
SKIP_MISMATCH_CONTRACT=false
PRUNE_OUTPUT=false
NO_AUTO_CAPTURE_KNOWN_GOOD=false
SKIP_LS_SNI_PREFLIGHT=false
KNOWN_GOOD_CAPTURE_PORT=8891
KNOWN_GOOD_ANTIGRAVITY_EXE=""
KNOWN_GOOD_CAPTURE_REQUIRE_STREAM=false
BASELINE_GEPHYR_PATH="parity/baselines/redacted/windows/default/gephyr.reference.jsonl"
BASELINE_KNOWN_GOOD_PATH="parity/baselines/redacted/windows/default/known_good.default.jsonl"
OUT_STATUS_JSON="output/parity/master_validation.status.json"
JSON_OUTPUT=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/parity-master-validate.sh [options]

Options:
  --known-good-path <path>               Default: output/known_good.discovery.jsonl
  --out-gephyr-path <path>               Default: output/gephyr_google_outbound_headers.latest.jsonl
  --startup-timeout-seconds <n>          Default: 90
  --allowlist-path <path>                Default: scripts/allowlists/antigravity_google_endpoints_default_chat.txt
  --require-oauth-relink
  --allow-mimic-token-refresh
  --include-chat-probe
  --include-auth-event-probes
  --include-extended-flow
  --refresh-inclusive                  Include refresh noise lane (permits oauth2/token extra traffic)
  --allow-missing-allowlist-endpoints
  --skip-allowlist-validation
  --skip-repo-gate
  --skip-baseline-gate
  --skip-mismatch-contract
  --prune-output                         Remove disposable capture/debug artifacts and keep latest useful outputs
  --no-auto-capture-known-good           Disable auto official capture bootstrap when known-good is missing
  --skip-ls-sni-preflight                Skip Wireshark/tshark LS SNI preflight before official auto-capture
  --known-good-capture-port <n>          Default: 8891
  --known-good-antigravity-exe <path>    Optional Antigravity.exe path for auto official bootstrap
  --known-good-capture-require-stream    Require generation/stream endpoint during auto official bootstrap
  --baseline-gephyr-path <path>          Default: parity/baselines/redacted/windows/default/gephyr.reference.jsonl
  --baseline-known-good-path <path>      Default: parity/baselines/redacted/windows/default/known_good.default.jsonl
  --status-json <path>                   Default: output/parity/master_validation.status.json
  --json                                 Print machine-readable status JSON
  -h, --help                             Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --known-good-path) KNOWN_GOOD_PATH="$2"; shift 2 ;;
    --out-gephyr-path) OUT_GEPHYR_PATH="$2"; shift 2 ;;
    --startup-timeout-seconds) STARTUP_TIMEOUT_SECONDS="$2"; shift 2 ;;
    --allowlist-path) ALLOWLIST_PATH="$2"; shift 2 ;;
    --require-oauth-relink) REQUIRE_OAUTH_RELINK=true; shift ;;
    --allow-mimic-token-refresh) ALLOW_MIMIC_TOKEN_REFRESH=true; shift ;;
    --include-chat-probe) INCLUDE_CHAT_PROBE=true; shift ;;
    --include-auth-event-probes) INCLUDE_AUTH_EVENT_PROBES=true; shift ;;
    --include-extended-flow) INCLUDE_EXTENDED_FLOW=true; shift ;;
    --refresh-inclusive) REFRESH_INCLUSIVE=true; shift ;;
    --allow-missing-allowlist-endpoints) ALLOW_MISSING_ALLOWLIST_ENDPOINTS=true; shift ;;
    --skip-allowlist-validation) SKIP_ALLOWLIST_VALIDATION=true; shift ;;
    --skip-repo-gate) SKIP_REPO_GATE=true; shift ;;
    --skip-baseline-gate) SKIP_BASELINE_GATE=true; shift ;;
    --skip-mismatch-contract) SKIP_MISMATCH_CONTRACT=true; shift ;;
    --prune-output) PRUNE_OUTPUT=true; shift ;;
    --no-auto-capture-known-good) NO_AUTO_CAPTURE_KNOWN_GOOD=true; shift ;;
    --skip-ls-sni-preflight) SKIP_LS_SNI_PREFLIGHT=true; shift ;;
    --known-good-capture-port) KNOWN_GOOD_CAPTURE_PORT="$2"; shift 2 ;;
    --known-good-antigravity-exe) KNOWN_GOOD_ANTIGRAVITY_EXE="$2"; shift 2 ;;
    --known-good-capture-require-stream) KNOWN_GOOD_CAPTURE_REQUIRE_STREAM=true; shift ;;
    --baseline-gephyr-path) BASELINE_GEPHYR_PATH="$2"; shift 2 ;;
    --baseline-known-good-path) BASELINE_KNOWN_GOOD_PATH="$2"; shift 2 ;;
    --status-json) OUT_STATUS_JSON="$2"; shift 2 ;;
    --json) JSON_OUTPUT=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

mkdir -p "$REPO_ROOT/output/parity"
mkdir -p "$(dirname "$REPO_ROOT/$OUT_STATUS_JSON")"

# Prefer the PowerShell master validator when available.
PS_EXE=""
if command -v pwsh >/dev/null 2>&1; then
  PS_EXE="pwsh"
elif command -v pwsh.exe >/dev/null 2>&1; then
  PS_EXE="pwsh.exe"
elif command -v powershell >/dev/null 2>&1; then
  PS_EXE="powershell"
elif command -v powershell.exe >/dev/null 2>&1; then
  PS_EXE="powershell.exe"
fi

if [[ -n "$PS_EXE" ]]; then
  ps_script="$SCRIPT_DIR/parity-master-validate.ps1"
  ps_bin_path="$(command -v "$PS_EXE" || true)"
  needs_windows_path=false
  if [[ "$PS_EXE" == *.exe || "$ps_bin_path" == *.exe ]]; then
    needs_windows_path=true
  fi
  if [[ "$needs_windows_path" == "true" ]]; then
    if command -v cygpath >/dev/null 2>&1; then
      ps_script="$(cygpath -w "$ps_script")"
    elif command -v wslpath >/dev/null 2>&1; then
      ps_script="$(wslpath -w "$ps_script")"
    fi
  fi

  ps_args=(
    -NoProfile
    -ExecutionPolicy Bypass
    -File "$ps_script"
    -KnownGoodPath "$KNOWN_GOOD_PATH"
    -OutGephyrPath "$OUT_GEPHYR_PATH"
    -StartupTimeoutSeconds "$STARTUP_TIMEOUT_SECONDS"
    -AllowlistPath "$ALLOWLIST_PATH"
    -BaselineGephyrPath "$BASELINE_GEPHYR_PATH"
    -BaselineKnownGoodPath "$BASELINE_KNOWN_GOOD_PATH"
    -OutStatusJson "$OUT_STATUS_JSON"
  )
  [[ "$REQUIRE_OAUTH_RELINK" == "true" ]] && ps_args+=(-RequireOAuthRelink)
  [[ "$ALLOW_MIMIC_TOKEN_REFRESH" == "true" ]] && ps_args+=(-AllowMimicTokenRefresh)
  [[ "$INCLUDE_CHAT_PROBE" == "true" ]] && ps_args+=(-IncludeChatProbe)
  [[ "$INCLUDE_AUTH_EVENT_PROBES" == "true" ]] && ps_args+=(-IncludeAuthEventProbes)
  [[ "$INCLUDE_EXTENDED_FLOW" == "true" ]] && ps_args+=(-IncludeExtendedFlow)
  [[ "$REFRESH_INCLUSIVE" == "true" ]] && ps_args+=(-RefreshInclusive)
  [[ "$ALLOW_MISSING_ALLOWLIST_ENDPOINTS" == "true" ]] && ps_args+=(-AllowMissingAllowlistEndpoints)
  [[ "$SKIP_ALLOWLIST_VALIDATION" == "true" ]] && ps_args+=(-SkipAllowlistValidation)
  [[ "$SKIP_REPO_GATE" == "true" ]] && ps_args+=(-SkipRepoGate)
  [[ "$SKIP_BASELINE_GATE" == "true" ]] && ps_args+=(-SkipBaselineGate)
  [[ "$SKIP_MISMATCH_CONTRACT" == "true" ]] && ps_args+=(-SkipMismatchContract)
  [[ "$PRUNE_OUTPUT" == "true" ]] && ps_args+=(-PruneOutput)
  [[ "$NO_AUTO_CAPTURE_KNOWN_GOOD" == "true" ]] && ps_args+=(-NoAutoCaptureKnownGood)
  [[ "$SKIP_LS_SNI_PREFLIGHT" == "true" ]] && ps_args+=(-SkipLsSniPreflight)
  [[ "$KNOWN_GOOD_CAPTURE_REQUIRE_STREAM" == "true" ]] && ps_args+=(-KnownGoodCaptureRequireStream)
  ps_args+=(-KnownGoodCapturePort "$KNOWN_GOOD_CAPTURE_PORT")
  if [[ -n "$KNOWN_GOOD_ANTIGRAVITY_EXE" ]]; then
    ps_args+=(-KnownGoodAntigravityExe "$KNOWN_GOOD_ANTIGRAVITY_EXE")
  fi
  [[ "$JSON_OUTPUT" == "true" ]] && ps_args+=(-Json)

  "$PS_EXE" "${ps_args[@]}"
  exit $?
fi

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required for fallback mode." >&2; exit 1; }
cd "$REPO_ROOT"

live_args=(
  --known-good-path "$KNOWN_GOOD_PATH"
  --out-gephyr-path "$OUT_GEPHYR_PATH"
  --startup-timeout-seconds "$STARTUP_TIMEOUT_SECONDS"
  --allowlist-path "$ALLOWLIST_PATH"
)
[[ "$REQUIRE_OAUTH_RELINK" == "true" ]] && live_args+=(--require-oauth-relink)
[[ "$ALLOW_MIMIC_TOKEN_REFRESH" == "true" ]] && live_args+=(--allow-mimic-token-refresh)
[[ "$REFRESH_INCLUSIVE" == "true" ]] && live_args+=(--refresh-inclusive)
[[ "$ALLOW_MISSING_ALLOWLIST_ENDPOINTS" == "true" ]] && live_args+=(--allow-missing-allowlist-endpoints)
[[ "$SKIP_ALLOWLIST_VALIDATION" == "true" ]] && live_args+=(--skip-allowlist-validation)

set +e
bash "$SCRIPT_DIR/live-google-parity-verify-antigravity.sh" "${live_args[@]}"
live_exit=$?
set -e

manifest_exit=0
raw_exit=0
if [[ "$SKIP_REPO_GATE" != "true" ]]; then
  set +e
  bash "$SCRIPT_DIR/validate-parity-baseline-manifests.sh"
  manifest_exit=$?
  bash "$SCRIPT_DIR/check-no-raw-parity-artifacts.sh"
  raw_exit=$?
  set -e
fi

baseline_exit=0
baseline_gate_out="output/parity/master_validation.baseline_gate.report.json"
if [[ "$SKIP_BASELINE_GATE" != "true" ]]; then
  set +e
  cargo run --quiet --bin gephyr-parity -- gate \
    --gephyr "$BASELINE_GEPHYR_PATH" \
    --known-good "$BASELINE_KNOWN_GOOD_PATH" \
    --out "$baseline_gate_out"
  baseline_exit=$?
  set -e
fi

mismatch_exit=0
mismatch_gate_out="output/parity/master_validation.mismatch_gate.report.json"
mismatch_fixture_path="output/parity/master_validation.known_good.mismatch.jsonl"
if [[ "$SKIP_MISMATCH_CONTRACT" != "true" ]]; then
  set +e
  python3 - <<'PY' \
    "$BASELINE_KNOWN_GOOD_PATH" \
    "$mismatch_fixture_path"
import json
import os
import sys

src = sys.argv[1]
dst = sys.argv[2]
if not os.path.exists(src):
    print(f"ERROR: known-good baseline not found: {src}", file=sys.stderr)
    raise SystemExit(1)

records = []
with open(src, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))

if not records:
    print(f"ERROR: known-good baseline is empty: {src}", file=sys.stderr)
    raise SystemExit(1)

mutated = False
for rec in records:
    headers = rec.get("headers", [])
    if not isinstance(headers, list):
        continue
    new_headers = []
    for pair in headers:
        if isinstance(pair, list) and len(pair) >= 2:
            key = str(pair[0])
            if (not mutated) and key.lower() == "user-agent":
                new_headers.append([pair[0], "mismatch-agent/0.0"])
                mutated = True
            else:
                new_headers.append([pair[0], pair[1]])
        else:
            new_headers.append(pair)
    rec["headers"] = new_headers

if not mutated:
    print("ERROR: could not mutate user-agent in known-good baseline", file=sys.stderr)
    raise SystemExit(1)

os.makedirs(os.path.dirname(dst), exist_ok=True)
with open(dst, "w", encoding="utf-8") as f:
    for rec in records:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
PY
  mismatch_prepare_exit=$?
  if [[ "$mismatch_prepare_exit" -ne 0 ]]; then
    mismatch_exit=200
  else
    cargo run --quiet --bin gephyr-parity -- gate \
      --gephyr "$BASELINE_GEPHYR_PATH" \
      --known-good "$mismatch_fixture_path" \
      --out "$mismatch_gate_out" >/dev/null 2>&1
    mismatch_exit=$?
  fi
  set -e
fi

# Mismatch fixture is always disposable.
rm -f "$mismatch_fixture_path" 2>/dev/null || true

pruned_artifacts=0
if [[ "$PRUNE_OUTPUT" == "true" ]]; then
  while IFS= read -r -d '' stale; do
    rm -f "$stale" 2>/dev/null || true
    pruned_artifacts=$((pruned_artifacts + 1))
  done < <(find "$REPO_ROOT/output" -type f \( \
      -name '*.missing-stream-*.jsonl' -o \
      -name '*.bak-*' -o \
      -name 'mitmdump_stderr*.log' -o \
      -name 'mitmdump_stdout*.log' -o \
      -name 'system_proxy.before_restore.*.json' -o \
      -name '*.pktmon.etl' -o \
      -name '*.pktmon.pcapng' -o \
      -name '*.connections.csv' -o \
      -name 'ls_*.csv' -o \
      -name 'ls_*.txt' -o \
      -name 'ls_*.json' -o \
      -name 'known_good_capture_hosts.json' -o \
      -name 'known_good.all.live.jsonl' -o \
      -name 'known_good.discovery.scoped.jsonl' -o \
      -name 'known_good.live.jsonl' -o \
      -name 'known_good.source_probe.jsonl' -o \
      -path '*/output/parity/ci/*.json' -o \
      -path '*/output/parity/ci/*.jsonl' -o \
      -name 'source-audit-smoke.json' \
    \) -print0 2>/dev/null)

  # Remove replay captures/history noise while keeping current master outputs.
  for dir in \
    "$REPO_ROOT/output/parity/raw" \
    "$REPO_ROOT/output/parity/redacted" \
    "$REPO_ROOT/output/parity/official" \
    "$REPO_ROOT/output/parity/official-smoke" \
    "$REPO_ROOT/output/parity/official-smoke-strict" \
    "$REPO_ROOT/output/parity/official-test" \
    "$REPO_ROOT/output/parity/refresh-smoke" \
    "$REPO_ROOT/output/parity/refresh-metadata-smoke"; do
    if [[ -d "$dir" ]]; then
      while IFS= read -r -d '' f; do
        rm -f "$f" 2>/dev/null || true
        pruned_artifacts=$((pruned_artifacts + 1))
      done < <(find "$dir" -type f -print0 2>/dev/null)
    fi
  done
fi

python3 - <<'PY' \
  "$REPO_ROOT/output/google_trace_diff_report.json" \
  "$REPO_ROOT/output/antigravity_allowed_endpoint_validation.json" \
  "$OUT_STATUS_JSON" \
  "$live_exit" \
  "$manifest_exit" \
  "$raw_exit" \
  "$baseline_exit" \
  "$mismatch_exit" \
  "$SKIP_REPO_GATE" \
  "$SKIP_BASELINE_GATE" \
  "$SKIP_MISMATCH_CONTRACT" \
  "$REFRESH_INCLUSIVE" \
  "$PRUNE_OUTPUT" \
  "$pruned_artifacts" \
  "$JSON_OUTPUT" \
  "$baseline_gate_out" \
  "$mismatch_gate_out" \
  "$mismatch_fixture_path" \
  "$KNOWN_GOOD_PATH" \
  "$OUT_GEPHYR_PATH" \
  "$ALLOWLIST_PATH" \
  "$BASELINE_GEPHYR_PATH" \
  "$BASELINE_KNOWN_GOOD_PATH"
import json
import os
import sys
from datetime import datetime, timezone

(
    diff_path,
    allowlist_path,
    out_status_json,
    live_exit,
    manifest_exit,
    raw_exit,
    baseline_exit,
    mismatch_exit,
    skip_repo_gate,
    skip_baseline_gate,
    skip_mismatch_contract,
    refresh_inclusive,
    prune_output,
    pruned_artifacts,
    json_output,
    baseline_gate_out,
    mismatch_gate_out,
    mismatch_fixture_path,
    known_good_path,
    out_gephyr_path,
    allowlist_input_path,
    baseline_gephyr_path,
    baseline_known_good_path,
) = sys.argv[1:]

live_ok = int(live_exit) == 0
skip_repo_gate = skip_repo_gate.lower() == "true"
skip_baseline_gate = skip_baseline_gate.lower() == "true"
skip_mismatch_contract = skip_mismatch_contract.lower() == "true"
refresh_inclusive = refresh_inclusive.lower() == "true"
prune_output = prune_output.lower() == "true"
pruned_artifacts = int(pruned_artifacts)
json_output = json_output.lower() == "true"

def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [value]

diff = load_json(diff_path)
allow = load_json(allowlist_path)

endpoint_rows = as_list(diff.get("endpoints") if isinstance(diff, dict) else None)
if refresh_inclusive:
    classification_issues = [
        e for e in endpoint_rows
        if str(e.get("classification")) not in ("matched_or_extra_only", "extra_endpoint_in_gephyr")
    ]
    count_issues = [
        e for e in endpoint_rows
        if int(e.get("known_request_count", 0)) > int(e.get("gephyr_request_count", 0))
    ]
else:
    classification_issues = [e for e in endpoint_rows if str(e.get("classification")) != "matched_or_extra_only"]
    count_issues = [e for e in endpoint_rows if int(e.get("known_request_count", 0)) != int(e.get("gephyr_request_count", 0))]
missing_header_issues = [e for e in endpoint_rows if len(as_list(e.get("missing_in_gephyr"))) > 0]
extra_header_issues = [e for e in endpoint_rows if len(as_list(e.get("extra_in_gephyr"))) > 0]

records_match = False
if isinstance(diff, dict):
    try:
        records_match = int(diff.get("gephyr_records", 0)) == int(diff.get("known_good_records", 0))
    except Exception:
        records_match = False

effective_records_match = True if refresh_inclusive else records_match
diff_pass = (
    isinstance(diff, dict)
    and not classification_issues
    and not count_issues
    and not missing_header_issues
    and not extra_header_issues
    and effective_records_match
)

allow_unknown_list = as_list(allow.get("unknown_google_endpoints")) if isinstance(allow, dict) else []
if refresh_inclusive:
    allow_unknown_list = [e for e in allow_unknown_list if e != "https://oauth2.googleapis.com/token"]
allow_unknown = len(allow_unknown_list)
allow_missing = len(as_list(allow.get("missing_allowed_endpoints"))) if isinstance(allow, dict) else 0
if isinstance(allow, dict):
    if refresh_inclusive:
        require_all = bool(allow.get("require_all_allowed_observed"))
        allow_pass = (allow_unknown == 0) and ((not require_all) or allow_missing == 0)
    else:
        allow_pass = bool(allow.get("pass"))
else:
    allow_pass = False

manifest_ok = int(manifest_exit) == 0
raw_ok = int(raw_exit) == 0
repo_gate_pass = skip_repo_gate or (manifest_ok and raw_ok)

baseline_ok = int(baseline_exit) == 0
baseline_gate_pass = skip_baseline_gate or baseline_ok

mismatch_report = load_json(mismatch_gate_out)
mismatch_report_gate_fail = (
    isinstance(mismatch_report, dict)
    and ("gate_pass" in mismatch_report)
    and (not bool(mismatch_report.get("gate_pass")))
)
mismatch_contract_pass = skip_mismatch_contract or ((int(mismatch_exit) != 0) and mismatch_report_gate_fail)

overall = live_ok and diff_pass and allow_pass and repo_gate_pass and baseline_gate_pass and mismatch_contract_pass

status = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "one_to_one_pass": overall,
    "one_to_one_status": "PASS" if overall else "FAIL",
    "lane": "refresh-inclusive" if refresh_inclusive else "strict-default",
    "inputs": {
        "known_good_path": known_good_path,
        "out_gephyr_path": out_gephyr_path,
        "allowlist_path": allowlist_input_path,
        "baseline_gephyr_path": baseline_gephyr_path,
        "baseline_known_good_path": baseline_known_good_path,
    },
    "steps": {
        "live_verify": {
            "pass": live_ok,
            "exit_code": int(live_exit),
        },
        "diff": {
            "pass": diff_pass,
            "report_path": os.path.relpath(diff_path),
            "gephyr_records": int(diff.get("gephyr_records", 0)) if isinstance(diff, dict) else 0,
            "known_good_records": int(diff.get("known_good_records", 0)) if isinstance(diff, dict) else 0,
            "records_match_required": (not refresh_inclusive),
            "classification_issues": len(classification_issues),
            "request_count_issues": len(count_issues),
            "missing_header_issues": len(missing_header_issues),
            "extra_header_issues": len(extra_header_issues),
        },
        "allowlist": {
            "pass": allow_pass,
            "report_path": os.path.relpath(allowlist_path),
            "unknown_google_endpoints": allow_unknown,
            "missing_allowed_endpoints": allow_missing,
        },
        "repo_gate": {
            "skipped": skip_repo_gate,
            "pass": repo_gate_pass,
            "manifest_pass": manifest_ok,
            "no_raw_artifacts_pass": raw_ok,
        },
        "baseline_gate": {
            "skipped": skip_baseline_gate,
            "pass": baseline_gate_pass,
            "exit_code": int(baseline_exit),
            "report_path": baseline_gate_out,
        },
        "mismatch_contract": {
            "skipped": skip_mismatch_contract,
            "pass": mismatch_contract_pass,
            "gate_exit_code": int(mismatch_exit),
            "report_has_gate_pass_false": mismatch_report_gate_fail,
            "fixture_path": mismatch_fixture_path,
            "report_path": mismatch_gate_out,
        },
        "cleanup": {
            "enabled": prune_output,
            "pruned_artifacts": pruned_artifacts,
        },
    },
}

os.makedirs(os.path.dirname(out_status_json), exist_ok=True)
with open(out_status_json, "w", encoding="utf-8") as f:
    json.dump(status, f, indent=2)

if json_output:
    print(json.dumps(status, indent=2))
else:
    print("")
    print("Parity Master Validation")
    print(f"  lane: {status['lane']}")
    print(f"  1:1 status: {status['one_to_one_status']}")
    print(f"  live verify: {status['steps']['live_verify']['pass']}")
    print(f"  diff strict: {status['steps']['diff']['pass']}")
    print(f"  allowlist: {status['steps']['allowlist']['pass']}")
    print(f"  repo gate: {status['steps']['repo_gate']['pass']} (skipped={status['steps']['repo_gate']['skipped']})")
    print(f"  baseline gate: {status['steps']['baseline_gate']['pass']} (skipped={status['steps']['baseline_gate']['skipped']})")
    print(f"  mismatch contract: {status['steps']['mismatch_contract']['pass']} (skipped={status['steps']['mismatch_contract']['skipped']})")
    if prune_output:
        print(f"  cleanup: pruned {status['steps']['cleanup']['pruned_artifacts']} artifact(s)")
    print(f"  status json: {out_status_json}")

sys.exit(0 if overall else 1)
PY
