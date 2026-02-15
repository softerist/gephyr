#!/usr/bin/env bash
# Wrapper: runs live Google parity verification with Antigravity-specific defaults.
# Delegates to live-google-parity-verify.sh, then runs allowlist validation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONFIG_PATH="$HOME/.gephyr/config.json"
KNOWN_GOOD_PATH="output/known_good.jsonl"
OUT_GEPHYR_PATH="output/gephyr_google_outbound_headers.jsonl"
STARTUP_TIMEOUT_SECONDS=60
REQUIRE_OAUTH_RELINK=false
ALLOWLIST_PATH="scripts/allowlists/antigravity_google_endpoints_default_chat.txt"
SKIP_ALLOWLIST_VALIDATION=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/live-google-parity-verify-antigravity.sh [options]

Options:
  --config-path <path>             Default: ~/.gephyr/config.json
  --known-good-path <path>         Default: output/known_good.jsonl
  --out-gephyr-path <path>         Default: output/gephyr_google_outbound_headers.jsonl
  --startup-timeout-seconds <n>    Default: 60
  --require-oauth-relink           Force OAuth relink
  --allowlist-path <path>          Default: scripts/allowlists/antigravity_google_endpoints_default_chat.txt
  --skip-allowlist-validation      Skip endpoint allowlist validation
  -h, --help                       Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config-path) CONFIG_PATH="$2"; shift 2 ;;
    --known-good-path) KNOWN_GOOD_PATH="$2"; shift 2 ;;
    --out-gephyr-path) OUT_GEPHYR_PATH="$2"; shift 2 ;;
    --startup-timeout-seconds) STARTUP_TIMEOUT_SECONDS="$2"; shift 2 ;;
    --require-oauth-relink) REQUIRE_OAUTH_RELINK=true; shift ;;
    --allowlist-path) ALLOWLIST_PATH="$2"; shift 2 ;;
    --skip-allowlist-validation) SKIP_ALLOWLIST_VALIDATION=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

args=(
  --config-path "$CONFIG_PATH"
  --known-good-path "$KNOWN_GOOD_PATH"
  --out-gephyr-path "$OUT_GEPHYR_PATH"
  --startup-timeout-seconds "$STARTUP_TIMEOUT_SECONDS"
)
[[ "$REQUIRE_OAUTH_RELINK" == "true" ]] && args+=(--require-oauth-relink)

bash "$SCRIPT_DIR/live-google-parity-verify.sh" "${args[@]}"

if [[ "$SKIP_ALLOWLIST_VALIDATION" != "true" ]]; then
  [[ -f "$OUT_GEPHYR_PATH" ]] || { echo "ERROR: Expected Gephyr outbound trace not found: $OUT_GEPHYR_PATH" >&2; exit 1; }
  echo "Running Antigravity Google endpoint allowlist validation ..."
  bash "$SCRIPT_DIR/validate-antigravity-allowed-google-endpoints.sh" \
    --trace "$OUT_GEPHYR_PATH" \
    --allowlist "$ALLOWLIST_PATH"
fi
