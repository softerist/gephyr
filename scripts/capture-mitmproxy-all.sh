#!/usr/bin/env bash
# Wrapper: captures ALL traffic (not just Google) through mitmproxy.
# Delegates to capture-known-good-mitmproxy.sh with --capture-all --capture-noise.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PORT=8879
OUT_PATH="output/mitm_all_traffic.jsonl"
TRUST_CERT=false
SELF_TEST_PROXY=false
MANAGE_ENV_PROXY=false
MANAGE_ANTIGRAVITY_IDE_PROXY=false
LAUNCH_ANTIGRAVITY_PROXIED=false
STOP_EXISTING_ANTIGRAVITY=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/capture-mitmproxy-all.sh [options]

Options:
  --port <n>                       Proxy port. Default: 8879
  --out-path <path>                Output JSONL. Default: output/mitm_all_traffic.jsonl
  --trust-cert                     Install mitmproxy CA
  --self-test-proxy                Send proxy self-test
  --manage-env-proxy               Set env proxy vars
  --manage-antigravity-ide-proxy   Set IDE proxy
  --launch-antigravity-proxied     Launch Antigravity proxied
  --stop-existing-antigravity      Kill existing Antigravity
  -h, --help                       Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --out-path) OUT_PATH="$2"; shift 2 ;;
    --trust-cert) TRUST_CERT=true; shift ;;
    --self-test-proxy) SELF_TEST_PROXY=true; shift ;;
    --manage-env-proxy) MANAGE_ENV_PROXY=true; shift ;;
    --manage-antigravity-ide-proxy) MANAGE_ANTIGRAVITY_IDE_PROXY=true; shift ;;
    --launch-antigravity-proxied) LAUNCH_ANTIGRAVITY_PROXIED=true; shift ;;
    --stop-existing-antigravity) STOP_EXISTING_ANTIGRAVITY=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

args=(
  --port "$PORT"
  --known-good-path "$OUT_PATH"
  --skip-diff
  --capture-all
  --capture-noise
)

[[ "$TRUST_CERT" == "true" ]] && args+=(--trust-cert)
[[ "$SELF_TEST_PROXY" == "true" ]] && args+=(--self-test-proxy)
[[ "$MANAGE_ENV_PROXY" == "true" ]] && args+=(--manage-env-proxy)
[[ "$MANAGE_ANTIGRAVITY_IDE_PROXY" == "true" ]] && args+=(--manage-antigravity-ide-proxy)
[[ "$LAUNCH_ANTIGRAVITY_PROXIED" == "true" ]] && args+=(--launch-antigravity-proxied)
[[ "$STOP_EXISTING_ANTIGRAVITY" == "true" ]] && args+=(--stop-existing-antigravity)

exec bash "$SCRIPT_DIR/capture-known-good-mitmproxy.sh" "${args[@]}"
