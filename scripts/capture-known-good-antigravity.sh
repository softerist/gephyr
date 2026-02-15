#!/usr/bin/env bash
# Wrapper: captures known-good Google API traffic from Antigravity IDE.
# Delegates to capture-known-good-mitmproxy.sh with Antigravity-specific defaults.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PORT=8879
KNOWN_GOOD_PATH="output/known_good_antigravity.jsonl"
CAPTURE_ALL=false
CAPTURE_NOISE=false
TRUST_CERT=false
SELF_TEST_PROXY=false
REQUIRE_STREAM=false
STOP_EXISTING_ANTIGRAVITY=false
MANAGE_ENV_PROXY=false
TARGET_HOSTS=()
TARGET_SUFFIXES=()

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/capture-known-good-antigravity.sh [options]

Options:
  --port <n>                  Proxy port. Default: 8879
  --known-good-path <path>    Output JSONL. Default: output/known_good_antigravity.jsonl
  --target-hosts <host>       Repeatable. Additional target hosts
  --target-suffixes <suffix>  Repeatable. Additional target suffixes
  --capture-all               Capture all hosts
  --capture-noise             Include noise endpoints
  --trust-cert                Install mitmproxy CA
  --self-test-proxy           Send proxy self-test
  --require-stream            Require streamGenerateContent
  --stop-existing-antigravity Kill existing Antigravity
  --manage-env-proxy          Set env proxy vars during capture
  -h, --help                  Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --known-good-path) KNOWN_GOOD_PATH="$2"; shift 2 ;;
    --target-hosts) TARGET_HOSTS+=("$2"); shift 2 ;;
    --target-suffixes) TARGET_SUFFIXES+=("$2"); shift 2 ;;
    --capture-all) CAPTURE_ALL=true; shift ;;
    --capture-noise) CAPTURE_NOISE=true; shift ;;
    --trust-cert) TRUST_CERT=true; shift ;;
    --self-test-proxy) SELF_TEST_PROXY=true; shift ;;
    --require-stream) REQUIRE_STREAM=true; shift ;;
    --stop-existing-antigravity) STOP_EXISTING_ANTIGRAVITY=true; shift ;;
    --manage-env-proxy) MANAGE_ENV_PROXY=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

args=(
  --port "$PORT"
  --known-good-path "$KNOWN_GOOD_PATH"
  --skip-diff
  --manage-antigravity-ide-proxy
  --launch-antigravity-proxied
)

for h in "${TARGET_HOSTS[@]+"${TARGET_HOSTS[@]}"}"; do
  args+=(--target-hosts "$h")
done
for s in "${TARGET_SUFFIXES[@]+"${TARGET_SUFFIXES[@]}"}"; do
  args+=(--target-suffixes "$s")
done

[[ "$CAPTURE_ALL" == "true" ]] && args+=(--capture-all)
[[ "$CAPTURE_NOISE" == "true" ]] && args+=(--capture-noise)
[[ "$TRUST_CERT" == "true" ]] && args+=(--trust-cert)
[[ "$SELF_TEST_PROXY" == "true" ]] && args+=(--self-test-proxy)
[[ "$REQUIRE_STREAM" == "true" ]] && args+=(--require-stream)
[[ "$STOP_EXISTING_ANTIGRAVITY" == "true" ]] && args+=(--stop-existing-antigravity)
[[ "$MANAGE_ENV_PROXY" == "true" ]] && args+=(--manage-env-proxy)

exec bash "$SCRIPT_DIR/capture-known-good-mitmproxy.sh" "${args[@]}"
