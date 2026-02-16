#!/usr/bin/env bash
# Smoke-test the dedicated proxy-pool strategy endpoint.
# Linux/macOS equivalent of test-proxy-pool-strategy.ps1.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONSOLE_SCRIPT="$REPO_ROOT/console.sh"
ENV_FILE="$REPO_ROOT/.env.local"

PORT="${PORT:-8045}"; CONTAINER_NAME="${CONTAINER_NAME:-gephyr}"
IMAGE="${IMAGE:-gephyr:latest}"; DATA_DIR="${DATA_DIR:-$HOME/.gephyr}"
TARGET_STRATEGY="round_robin"; SKIP_START="false"; KEEP_CHANGE="false"
ALLOWED_STRATEGIES=("round_robin" "random" "priority" "least_connections" "weighted_round_robin")

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
Usage: ./scripts/test-proxy-pool-strategy.sh [options]

Examples:
  ./scripts/test-proxy-pool-strategy.sh
  ./scripts/test-proxy-pool-strategy.sh --target-strategy weighted_round_robin
  ./scripts/test-proxy-pool-strategy.sh --skip-start --keep-change

Options:
  --port <int>                     Default: 8045
  --container <string>             Default: gephyr
  --image <string>                 Default: gephyr:latest
  --data-dir <string>              Default: $HOME/.gephyr
  --target-strategy <string>       Default: round_robin
  --skip-start                     Uses currently running server
  --keep-change                    Do not restore original strategy
  -h, --help                       Print this usage
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;; --container) CONTAINER_NAME="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;; --data-dir) DATA_DIR="$2"; shift 2 ;;
    --target-strategy) TARGET_STRATEGY="$2"; shift 2 ;;
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

is_allowed_strategy() {
  local s="$1"
  for a in "${ALLOWED_STRATEGIES[@]}"; do [[ "$a" == "$s" ]] && return 0; done
  return 1
}

select_alternate_strategy() {
  local current="$1"
  for c in "${ALLOWED_STRATEGIES[@]}"; do [[ "$c" != "$current" ]] && { echo "$c"; return 0; }; done
  echo "$current"
}

# ── Main ───────────────────────────────────────────────────────────────────
write_section "Gephyr Proxy-Pool Strategy Endpoint Smoke Test"
printf "${C_GRAY}This script validates GET/POST /api/proxy/pool/strategy behavior.${C_RESET}\n"
[[ -f "$CONSOLE_SCRIPT" ]] || die "console.sh not found at $CONSOLE_SCRIPT"

load_env_local
assert_dependencies
ensure_api_key

normalized_target="$(echo "$TARGET_STRATEGY" | tr '[:upper:]' '[:lower:]' | xargs)"
is_allowed_strategy "$normalized_target" || die "Invalid TargetStrategy '$TARGET_STRATEGY'. Allowed: ${ALLOWED_STRATEGIES[*]}"

original_strategy=""; updated_strategy=""

cleanup() {
  if [[ "$KEEP_CHANGE" != "true" && -n "$original_strategy" && -n "$updated_strategy" && "$original_strategy" != "$updated_strategy" ]]; then
    api_post_json "/api/proxy/pool/strategy" "$(jq -n --arg s "$original_strategy" '{strategy:$s}')" >/dev/null 2>&1 && \
      printf "${C_GRAY}Restored original strategy: %s${C_RESET}\n" "$original_strategy" || \
      printf "${C_YELLOW}Warning: failed to restore original strategy automatically.${C_RESET}\n"
  elif [[ "$KEEP_CHANGE" == "true" ]]; then
    printf "${C_GRAY}KeepChange set: strategy left as updated value.${C_RESET}\n"
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
printf '%s' "$caps" | jq -e '.routes["GET /api/proxy/pool/strategy"]' >/dev/null 2>&1 || die "Running image does not expose GET /api/proxy/pool/strategy."
printf '%s' "$caps" | jq -e '.routes["POST /api/proxy/pool/strategy"]' >/dev/null 2>&1 || die "Running image does not expose POST /api/proxy/pool/strategy."
printf "${C_GREEN}Running version: %s${C_RESET}\n" "$(printf '%s' "$caps" | jq -r '.version // "unknown"')"

write_step 3 "Read current strategy snapshot"
before="$(api_get "/api/proxy/pool/strategy")"
original_strategy="$(printf '%s' "$before" | jq -r '.strategy // empty')"
[[ -n "$original_strategy" ]] || die "Current strategy is missing from response."
printf "${C_GRAY}Current strategy: %s${C_RESET}\n" "$original_strategy"
printf "${C_GRAY}Pool enabled: %s, auto_failover: %s, health_check_interval: %s${C_RESET}\n" \
  "$(printf '%s' "$before" | jq -r '.enabled')" \
  "$(printf '%s' "$before" | jq -r '.auto_failover')" \
  "$(printf '%s' "$before" | jq -r '.health_check_interval')"

if [[ "$normalized_target" == "$original_strategy" ]]; then
  normalized_target="$(select_alternate_strategy "$original_strategy")"
  printf "${C_YELLOW}Target matched current; using alternate strategy: %s${C_RESET}\n" "$normalized_target"
fi

write_step 4 "Update strategy via dedicated endpoint"
post="$(api_post_json "/api/proxy/pool/strategy" "$(jq -n --arg s "$normalized_target" '{strategy:$s}')")"
post_ok="$(printf '%s' "$post" | jq -r '.ok // false')"
post_saved="$(printf '%s' "$post" | jq -r '.saved // false')"
[[ "$post_ok" == "true" && "$post_saved" == "true" ]] || die "Strategy update endpoint did not return success payload."
updated_strategy="$(printf '%s' "$post" | jq -r '.proxy_pool.strategy // empty')"
printf "${C_GREEN}Updated strategy: %s${C_RESET}\n" "$updated_strategy"

write_step 5 "Verify persisted runtime snapshot"
after="$(api_get "/api/proxy/pool/strategy")"
after_strategy="$(printf '%s' "$after" | jq -r '.strategy // empty')"
[[ "$after_strategy" == "$normalized_target" ]] || die "Expected strategy '$normalized_target', got '$after_strategy'."
printf "${C_GREEN}Verified strategy after update: %s${C_RESET}\n" "$after_strategy"

write_step 6 "Result summary"
printf "Original strategy: %s\n" "$original_strategy"
printf "Target strategy:   %s\n" "$normalized_target"
printf "Final strategy:    %s\n" "$after_strategy"
echo ""
printf "${C_GREEN}PASS: Dedicated pool-strategy endpoint is working.${C_RESET}\n"
