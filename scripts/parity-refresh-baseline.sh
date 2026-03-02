#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") --gephyr <path> --official <path> [options]

Required:
  --gephyr <path>                 Path to Gephyr capture (JSONL/HAR/SAZ)
  --official <path>               Path to official binary capture

Options:
  --baseline-dir <dir>            Output baseline directory (default: parity/baselines/redacted/windows/default)
  --rules <path>                  Path to custom ParityRuleSet JSON
  --antigravity-exe-path <path>   Path to antigravity.exe binary
  --language-server-exe-path <p>  Path to language_server_windows_x64.exe
  --gate                          Enable gate mode (fail on parity regression)
  -h, --help                      Show this help
EOF
  exit 1
}

GEPHYR_PATH=""
OFFICIAL_PATH=""
BASELINE_DIR="parity/baselines/redacted/windows/default"
RULES_PATH=""
ANTIGRAVITY_EXE_PATH=""
LANGUAGE_SERVER_EXE_PATH=""
GATE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gephyr)              GEPHYR_PATH="$2";              shift 2 ;;
    --official)            OFFICIAL_PATH="$2";             shift 2 ;;
    --baseline-dir)        BASELINE_DIR="$2";              shift 2 ;;
    --rules)               RULES_PATH="$2";                shift 2 ;;
    --antigravity-exe-path)     ANTIGRAVITY_EXE_PATH="$2"; shift 2 ;;
    --language-server-exe-path) LANGUAGE_SERVER_EXE_PATH="$2"; shift 2 ;;
    --gate)                GATE=true;                      shift   ;;
    -h|--help)             usage ;;
    *)                     echo "Unknown option: $1" >&2; usage ;;
  esac
done

if [[ -z "$GEPHYR_PATH" || -z "$OFFICIAL_PATH" ]]; then
  echo "ERROR: --gephyr and --official are required" >&2
  usage
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# --- source audit ---
echo "Running source audit on official capture..."
cargo run --quiet --bin gephyr-parity -- \
  source-audit \
  --input "$OFFICIAL_PATH" \
  --out output/parity/official/source_audit.json

# --- refresh baseline ---
REFRESH_ARGS=(
  run --quiet --bin gephyr-parity --
  refresh-baseline
  --gephyr "$GEPHYR_PATH"
  --official "$OFFICIAL_PATH"
  --baseline-dir "$BASELINE_DIR"
)

if [[ "$GATE" == true ]]; then
  REFRESH_ARGS+=(--gate)
fi
if [[ -n "$RULES_PATH" ]]; then
  REFRESH_ARGS+=(--rules "$RULES_PATH")
fi
if [[ -n "$ANTIGRAVITY_EXE_PATH" ]]; then
  REFRESH_ARGS+=(--antigravity-exe-path "$ANTIGRAVITY_EXE_PATH")
fi
if [[ -n "$LANGUAGE_SERVER_EXE_PATH" ]]; then
  REFRESH_ARGS+=(--language-server-exe-path "$LANGUAGE_SERVER_EXE_PATH")
fi

echo "Refreshing baseline artifacts/manifests..."
cargo "${REFRESH_ARGS[@]}"

echo "Done. Baseline refreshed at: $BASELINE_DIR"
echo "Source audit report: output/parity/official/source_audit.json"
