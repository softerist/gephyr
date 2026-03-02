#!/usr/bin/env bash
# Prunes parity output artifacts, keeping only the latest/essential ones.
# Linux/Bash equivalent of prune-parity-output.ps1.
set -euo pipefail

KNOWN_GOOD_PATH="${1:-output/known_good.discovery.jsonl}"
KNOWN_GOOD_SCOPED_PATH="${2:-output/known_good.antigravity_scope.latest.jsonl}"
OUT_GEPHYR_PATH="${3:-output/gephyr_google_outbound_headers.latest.jsonl}"
DIFF_JSON_PATH="${4:-output/google_trace_diff_report.json}"
DIFF_TXT_PATH="${5:-output/google_trace_diff_report.txt}"
ALLOWLIST_JSON_PATH="${6:-output/antigravity_allowed_endpoint_validation.json}"
ALLOWLIST_TXT_PATH="${7:-output/antigravity_allowed_endpoint_validation.txt}"
STATUS_JSON_PATH="${8:-output/parity/master_validation.status.json}"
BASELINE_GATE_OUT="${9:-output/parity/master_validation.baseline_gate.report.json}"
MISMATCH_GATE_OUT="${10:-output/parity/master_validation.mismatch_gate.report.json}"

# Helper to get absolute path if exists
abspath() {
  if [[ -e "$1" ]]; then
    readlink -f "$1"
  fi
}

# Create a "keep" list using absolute paths
KEEP_FILE=$(mktemp)
trap 'rm -f "$KEEP_FILE"' EXIT

for p in "$KNOWN_GOOD_PATH" "$KNOWN_GOOD_SCOPED_PATH" "$OUT_GEPHYR_PATH" \
         "$DIFF_JSON_PATH" "$DIFF_TXT_PATH" "$ALLOWLIST_JSON_PATH" \
         "$ALLOWLIST_TXT_PATH" "$STATUS_JSON_PATH" "$BASELINE_GATE_OUT" \
         "$MISMATCH_GATE_OUT"; do
  abs=$(abspath "$p")
  if [[ -n "$abs" ]]; then
    echo "$abs" >> "$KEEP_FILE"
  fi
done

DELETED_COUNT=0

# Patterns to prune
PATTERNS=(
  "output/*.missing-stream-*.jsonl"
  "output/*.bak-*"
  "output/mitmdump_stderr*.log"
  "output/mitmdump_stdout*.log"
  "output/system_proxy.before_restore.*.json"
  "output/*.pktmon.etl"
  "output/*.pktmon.pcapng"
  "output/*.connections.csv"
  "output/ls_*.csv"
  "output/ls_*.txt"
  "output/ls_*.json"
  "output/known_good_capture_hosts.json"
  "output/known_good.all.live.jsonl"
  "output/known_good.discovery.scoped.jsonl"
  "output/known_good.live.jsonl"
  "output/known_good.source_probe.jsonl"
  "output/parity/raw/*.jsonl"
  "output/parity/redacted/*.jsonl"
  "output/parity/ci/*.json"
  "output/parity/ci/*.jsonl"
  "output/parity/source-audit-smoke.json"
  "output/parity/master_validation.known_good.mismatch.jsonl"
)

# Also prune specific directories recursively, preserving only kept files
PRUNE_DIRS=(
  "output/parity/raw"
  "output/parity/redacted"
  "output/parity/official"
  "output/parity/official-smoke"
  "output/parity/official-smoke-strict"
  "output/parity/official-test"
  "output/parity/refresh-smoke"
  "output/parity/refresh-metadata-smoke"
)

prune_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then return; fi
  local abs_f
  abs_f=$(readlink -f "$f")
  if grep -qFx "$abs_f" "$KEEP_FILE"; then
    return
  fi
  if rm -f "$f"; then
    ((DELETED_COUNT++))
  fi
}

# 1. Prune by patterns
for pat in "${PATTERNS[@]}"; do
  # Use find for recursive patterns or simple glob for others
  if [[ "$pat" == *"**"* ]]; then
    dir=$(echo "$pat" | cut -d'*' -f1)
    # Note: the glob patterns in PS1 didn't use ** actually, except in comments
    # but the Get-ChildItem -Recurse did.
    find "${dir:-.}" -type f -name "${pat#*/}" -print0 2>/dev/null | while IFS= read -r -d '' file; do
      prune_file "$file"
    done
  else
    # Simple shell globbing for safety (handles spaces etc if quoted)
    # We want to emulate the PS1 behavior which was recursive for some.
    shopt -s globstar nullglob 2>/dev/null || true
    for file in $pat; do
      prune_file "$file"
    done
  fi
done

# 2. Prune by directories
for d in "${PRUNE_DIRS[@]}"; do
  if [[ -d "$d" ]]; then
    find "$d" -type f -print0 | while IFS= read -r -d '' file; do
      prune_file "$file"
    done
  fi
done

echo "Pruned artifacts: $DELETED_COUNT"
