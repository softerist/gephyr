#!/usr/bin/env bash
# Smoke-test the dedicated proxy-pool runtime endpoint.
# Linux/macOS equivalent of test-proxy-pool-runtime.ps1.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONSOLE_SCRIPT="$REPO_ROOT/console.sh"
ENV_FILE="$REPO_ROOT/.env.local"

PORT="${PORT:-8045}"; CONTAINER_NAME="${CONTAINER_NAME:-gephyr}"
IMAGE="${IMAGE:-gephyr:latest}"; DATA_DIR="${DATA_DIR:-$HOME/.gephyr}"
TARGET_ENABLED=""; TARGET_AUTO_FAILOVER=""; TARGET_HEALTH_CHECK_INTERVAL=""
SKIP_START="false"; KEEP_CHANGE="false"

C_CYAN="\033[36m"; C_YELLOW="\033[33m"; C_GREEN="\033[32m"; C_GRAY="\033[90m"; C_RED="\033[31m"; C_RESET="\033[0m"
write_section() { printf "\n${C_CYAN}%s\n%s\n%s${C_RESET}\n" "$(printf '=%.0s' {1..76})" "$1" "$(printf '=%.0s' {1..76})"; }
write_step()    { printf "\n${C_YELLOW}[%d] %s${C_RESET}\n" "$1" "$2"; }
die() { printf "${C_RED}ERROR: %s${C_RESET}\n" "$1" >&2; exit 1; }

assert_dependencies() {
  local missing=()
  command -v curl >/dev/null 2>&1 || missing+=("curl")
  command -v jq   >/dev/null 2>&1 || missing+=("jq")
  command -v docker >/dev/null 2>&1 || missing+=("docker")
  if [[ ${#missing[@]} -gt 0 ]]; then
    printf "${C_RED}Missing required tool(s): %s${C_RESET}\n" "${missing[*]}" >&2
    echo "" >&2
    echo "Install with:" >&2
    echo "  Ubuntu/Debian : sudo apt-get install -y ${missing[*]}" >&2
    echo "  Fedora/RHEL   : sudo dnf install -y ${missing[*]}" >&2
    echo "  macOS (Brew)  : brew install ${missing[*]}" >&2
    echo "  Alpine        : apk add ${missing[*]}" >&2
    echo "" >&2
    echo "  Docker        : https://docs.docker.com/engine/install/" >&2
    exit 1
  fi
}

show_usage() {
  cat <<'EOF'
Usage: ./scripts/test-proxy-pool-runtime.sh [options]

Examples:
  ./scripts/test-proxy-pool-runtime.sh
  ./scripts/test-proxy-pool-runtime.sh --target-enabled true --target-auto-failover false --target-health-check-interval 120
  ./scripts/test-proxy-pool-runtime.sh --skip-start --keep-change

Options:
  --port <int>                            Default: 8045
  --container <string>                    Default: gephyr
  --image <string>                        Default: gephyr:latest
  --data-dir <string>                     Default: $HOME/.gephyr
  --target-enabled <true|false>           Optional explicit target
  --target-auto-failover <true|false>     Optional explicit target
  --target-health-check-interval <int>    Optional explicit target (seconds)
  --skip-start                            Uses currently running server
  --keep-change                           Do not restore original values
  -h, --help                              Print this usage
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;; --container) CONTAINER_NAME="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;; --data-dir) DATA_DIR="$2"; shift 2 ;;
    --target-enabled) TARGET_ENABLED="$2"; shift 2 ;;
    --target-auto-failover) TARGET_AUTO_FAILOVER="$2"; shift 2 ;;
    --target-health-check-interval) TARGET_HEALTH_CHECK_INTERVAL="$2"; shift 2 ;;
    --skip-start) SKIP_START="true"; shift ;; --keep-change) KEEP_CHANGE="true"; shift ;;
    -h|--help) show_usage; exit 0 ;; *) die "Unknown argument: $1" ;;
  esac
done

BASE_URL="http://127.0.0.1:${PORT}"

load_env_local() {
  [[ -f "$ENV_FILE" ]] || return 0
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "${line:0:1}" == "#" || "$line" != *"="* ]] && continue
    local key="${line%%=*}" value="${line#*=}"
    key="$(echo "$key" | xargs)"; value="$(echo "$value" | sed -E "s/^['\"]|['\"]$//g")"
    [[ -n "$key" && -n "$value" && -z "${!key:-}" ]] && export "$key=$value"
  done < "$ENV_FILE"
}

ensure_api_key() { [[ -n "${API_KEY:-}" ]] || die "Missing API_KEY. Set env var or add it to .env.local."; }

wait_service_ready() {
  local attempts="${1:-50}" delay="${2:-0.5}"; ensure_api_key
  for _ in $(seq 1 "$attempts"); do
    local code; code="$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${API_KEY}" "${BASE_URL}/health" 2>/dev/null || true)"
    [[ "$code" == "200" ]] && return 0; sleep "$delay"
  done; return 1
}

start_server() { bash "$CONSOLE_SCRIPT" start --admin-api --port "$PORT" --container "$CONTAINER_NAME" --image "$IMAGE" --data-dir "$DATA_DIR"; }
api_get() { ensure_api_key; curl -sS -H "Authorization: Bearer ${API_KEY}" --max-time 30 "${BASE_URL}$1"; }
api_post_json() { ensure_api_key; curl -sS -H "Authorization: Bearer ${API_KEY}" -H "Content-Type: application/json" -X POST --max-time 30 -d "$2" "${BASE_URL}$1"; }

# Flip boolean: "true" → "false", anything else → "true"
flip_bool() { [[ "$1" == "true" ]] && echo "false" || echo "true"; }
max_int() { [[ "$1" -gt "$2" ]] && echo "$1" || echo "$2"; }

# ── Main ───────────────────────────────────────────────────────────────────
write_section "Gephyr Proxy-Pool Runtime Endpoint Smoke Test"
printf "${C_GRAY}This script validates GET/POST /api/proxy/pool/runtime behavior.${C_RESET}\n"
[[ -f "$CONSOLE_SCRIPT" ]] || die "console.sh not found at $CONSOLE_SCRIPT"

load_env_local
assert_dependencies
ensure_api_key

if [[ -n "$TARGET_HEALTH_CHECK_INTERVAL" && "$TARGET_HEALTH_CHECK_INTERVAL" -lt 1 ]]; then
  die "target-health-check-interval must be >= 1."
fi

before_json=""; restore_needed="false"

cleanup() {
  if [[ "$restore_needed" == "true" && -n "$before_json" ]]; then
    local b_enabled b_failover b_interval
    b_enabled="$(printf '%s' "$before_json" | jq -r '.enabled')"
    b_failover="$(printf '%s' "$before_json" | jq -r '.auto_failover')"
    b_interval="$(printf '%s' "$before_json" | jq -r '.health_check_interval')"
    local payload
    payload="$(jq -n --argjson e "$b_enabled" --argjson af "$b_failover" --argjson hci "$b_interval" \
      '{enabled:$e, auto_failover:$af, health_check_interval:$hci}')"
    api_post_json "/api/proxy/pool/runtime" "$payload" >/dev/null 2>&1 && \
      printf "${C_GRAY}Restored original runtime knobs: enabled=%s, auto_failover=%s, health_check_interval=%s${C_RESET}\n" \
        "$b_enabled" "$b_failover" "$b_interval" || \
      printf "${C_YELLOW}Warning: failed to restore original runtime knobs automatically.${C_RESET}\n"
  elif [[ "$KEEP_CHANGE" == "true" ]]; then
    printf "${C_GRAY}KeepChange set: runtime knob changes were kept.${C_RESET}\n"
  fi
}
trap cleanup EXIT

if [[ "$SKIP_START" != "true" ]]; then
  write_step 1 "Start server with admin API enabled"; start_server
  wait_service_ready || die "Service did not become ready on $BASE_URL"
  printf "${C_GREEN}Service is ready.${C_RESET}\n"
else
  write_step 1 "Using running server (SkipStart)"
  wait_service_ready 5 0.3 || die "Server is not reachable on $BASE_URL."
  printf "${C_GREEN}Service is reachable.${C_RESET}\n"
fi

write_step 2 "Verify route capability"
caps="$(api_get "/api/version/routes")"
printf '%s' "$caps" | jq -e '.routes["GET /api/proxy/pool/runtime"]' >/dev/null 2>&1 || die "Running image does not expose GET /api/proxy/pool/runtime."
printf '%s' "$caps" | jq -e '.routes["POST /api/proxy/pool/runtime"]' >/dev/null 2>&1 || die "Running image does not expose POST /api/proxy/pool/runtime."
printf "${C_GREEN}Running version: %s${C_RESET}\n" "$(printf '%s' "$caps" | jq -r '.version // "unknown"')"

write_step 3 "Read current runtime snapshot"
before_json="$(api_get "/api/proxy/pool/runtime")"
cur_enabled="$(printf '%s' "$before_json" | jq -r '.enabled')"
cur_failover="$(printf '%s' "$before_json" | jq -r '.auto_failover')"
cur_interval="$(printf '%s' "$before_json" | jq -r '.health_check_interval')"
printf "${C_GRAY}Before: enabled=%s, auto_failover=%s, health_check_interval=%s, strategy=%s${C_RESET}\n" \
  "$cur_enabled" "$cur_failover" "$cur_interval" "$(printf '%s' "$before_json" | jq -r '.strategy // "n/a"')"

# Derive next values
next_enabled="$([[ -n "$TARGET_ENABLED" ]] && echo "$TARGET_ENABLED" || flip_bool "$cur_enabled")"
next_failover="$([[ -n "$TARGET_AUTO_FAILOVER" ]] && echo "$TARGET_AUTO_FAILOVER" || flip_bool "$cur_failover")"
next_interval="$([[ -n "$TARGET_HEALTH_CHECK_INTERVAL" ]] && echo "$TARGET_HEALTH_CHECK_INTERVAL" || max_int 30 $((cur_interval + 30)))"

# If derived payload matches current, bump interval further
if [[ "$next_enabled" == "$cur_enabled" && "$next_failover" == "$cur_failover" && "$next_interval" == "$cur_interval" ]]; then
  next_interval="$(max_int 30 $((cur_interval + 60)))"
  printf "${C_YELLOW}Derived payload matched current state; bumping health_check_interval to %s.${C_RESET}\n" "$next_interval"
fi

write_step 4 "Update runtime knobs via dedicated endpoint"
payload="$(jq -n --argjson e "$next_enabled" --argjson af "$next_failover" --argjson hci "$next_interval" \
  '{enabled:$e, auto_failover:$af, health_check_interval:$hci}')"
post="$(api_post_json "/api/proxy/pool/runtime" "$payload")"
post_ok="$(printf '%s' "$post" | jq -r '.ok // false')"
post_saved="$(printf '%s' "$post" | jq -r '.saved // false')"
[[ "$post_ok" == "true" && "$post_saved" == "true" ]] || die "Runtime update endpoint did not return success payload."
printf "${C_GREEN}Updated: enabled=%s, auto_failover=%s, health_check_interval=%s${C_RESET}\n" \
  "$(printf '%s' "$post" | jq -r '.proxy_pool.enabled')" \
  "$(printf '%s' "$post" | jq -r '.proxy_pool.auto_failover')" \
  "$(printf '%s' "$post" | jq -r '.proxy_pool.health_check_interval')"

write_step 5 "Verify persisted runtime snapshot"
after="$(api_get "/api/proxy/pool/runtime")"
af_enabled="$(printf '%s' "$after" | jq -r '.enabled')"
af_failover="$(printf '%s' "$after" | jq -r '.auto_failover')"
af_interval="$(printf '%s' "$after" | jq -r '.health_check_interval')"

[[ "$af_enabled" == "$next_enabled" ]] || die "Expected enabled=$next_enabled, got $af_enabled."
[[ "$af_failover" == "$next_failover" ]] || die "Expected auto_failover=$next_failover, got $af_failover."
[[ "$af_interval" == "$next_interval" ]] || die "Expected health_check_interval=$next_interval, got $af_interval."

restore_needed="true"
[[ "$KEEP_CHANGE" == "true" ]] && restore_needed="false"

write_step 6 "Result summary"
printf "Before: enabled=%s, auto_failover=%s, health_check_interval=%s\n" "$cur_enabled" "$cur_failover" "$cur_interval"
printf "After:  enabled=%s, auto_failover=%s, health_check_interval=%s\n" "$af_enabled" "$af_failover" "$af_interval"
echo ""
printf "${C_GREEN}PASS: Dedicated pool-runtime endpoint is working.${C_RESET}\n"
