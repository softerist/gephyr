#!/usr/bin/env bash
# Smoke-test compliance counters in Gephyr.
# Linux/macOS equivalent of test-compliance-counters.ps1.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONSOLE_SCRIPT="$REPO_ROOT/console.sh"
ENV_FILE="$REPO_ROOT/.env.local"

PORT="${PORT:-8045}"; CONTAINER_NAME="${CONTAINER_NAME:-gephyr}"
IMAGE="${IMAGE:-gephyr:latest}"; DATA_DIR="${GEPHYR_DATA_DIR:-$HOME/.gephyr}"
REQUEST_COUNT=5; STRESS_MODE="false"; POLL_INFLIGHT_ATTEMPTS=25; POLL_INFLIGHT_DELAY_MS=150
MODEL="gpt-5.3-codex"; FALLBACK_MODELS="gemini-3-flash,gemini-3.0-flash,claude-sonnet-4-5"
AUTO_LOGIN="false"; SKIP_START="false"

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
Usage: ./scripts/test-compliance-counters.sh [options]

Options:
  --port <int>                     Default: 8045
  --request-count <int>            Default: 5
  --stress-mode                    Concurrent burst + in-flight polling
  --poll-inflight-attempts <int>   Default: 25
  --poll-inflight-delay-ms <int>   Default: 150
  --model <string>                 Default: gpt-5.3-codex
  --fallback-models <csv>          Default: gemini-3-flash,gemini-3.0-flash,claude-sonnet-4-5
  --auto-login                     Starts OAuth flow if no account linked
  --skip-start                     Uses currently running server
  -h, --help                       Print this usage
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;; --container) CONTAINER_NAME="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;; --data-dir) DATA_DIR="$2"; shift 2 ;;
    --request-count) REQUEST_COUNT="$2"; shift 2 ;; --stress-mode) STRESS_MODE="true"; shift ;;
    --poll-inflight-attempts) POLL_INFLIGHT_ATTEMPTS="$2"; shift 2 ;;
    --poll-inflight-delay-ms) POLL_INFLIGHT_DELAY_MS="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;; --fallback-models) FALLBACK_MODELS="$2"; shift 2 ;;
    --auto-login) AUTO_LOGIN="true"; shift ;; --skip-start) SKIP_START="true"; shift ;;
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

ensure_api_key() { [[ -n "${GEPHYR_API_KEY:-}" ]] || die "Missing GEPHYR_API_KEY."; }

wait_service_ready() {
  local attempts="${1:-50}" delay="${2:-0.5}"; ensure_api_key
  for _ in $(seq 1 "$attempts"); do
    local code; code="$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${GEPHYR_API_KEY}" "${BASE_URL}/healthz" 2>/dev/null || true)"
    [[ "$code" == "200" ]] && return 0; sleep "$delay"
  done; return 1
}
start_server() { bash "$CONSOLE_SCRIPT" start --admin-api --port "$PORT" --container "$CONTAINER_NAME" --image "$IMAGE" --data-dir "$DATA_DIR"; }
api_get() { ensure_api_key; curl -sS -H "Authorization: Bearer ${GEPHYR_API_KEY}" --max-time 30 "${BASE_URL}$1"; }
api_post_json() { ensure_api_key; curl -sS -H "Authorization: Bearer ${GEPHYR_API_KEY}" -H "Content-Type: application/json" -X POST --max-time 60 -d "$2" "${BASE_URL}$1"; }

ensure_account_linked() {
  local resp count; resp="$(api_get "/api/accounts")"
  count="$(printf '%s' "$resp" | jq '.accounts | length' 2>/dev/null || echo 0)"
  [[ "$count" -gt 0 ]] && { echo "$count"; return 0; }
  [[ "$AUTO_LOGIN" == "true" ]] || die "No linked accounts found. Re-run with --auto-login or login first."
  printf "${C_YELLOW}No linked accounts. Starting OAuth login flow...${C_RESET}\n"
  bash "$CONSOLE_SCRIPT" login --port "$PORT" --container "$CONTAINER_NAME" --image "$IMAGE" --data-dir "$DATA_DIR"
  for _ in $(seq 1 30); do sleep 2; resp="$(api_get "/api/accounts")"
    count="$(printf '%s' "$resp" | jq '.accounts | length' 2>/dev/null || echo 0)"
    [[ "$count" -gt 0 ]] && { echo "$count"; return 0; }
  done; die "No accounts linked after OAuth flow."
}

# Returns: status|account_email|mapped_model|error
invoke_test_request() {
  local model="$1" prompt="$2" allow_error="${3:-false}"
  local body hf bf http_code email="" mapped="" err=""
  body="$(jq -n --arg m "$model" --arg c "$prompt" '{model:$m,messages:[{role:"user",content:$c}]}')"
  hf="$(mktemp)"; bf="$(mktemp)"
  http_code="$(curl -s -o "$bf" -D "$hf" -w "%{http_code}" -H "Authorization: Bearer ${GEPHYR_API_KEY}" -H "Content-Type: application/json" -X POST --max-time 120 -d "$body" "${BASE_URL}/v1/chat/completions" 2>/dev/null || echo "000")"
  if [[ "$http_code" == "200" ]]; then
    email="$(grep -i '^x-account-email:' "$hf" | head -1 | sed -E 's/^[^:]+:[[:space:]]*//' | tr -d '\r' || true)"
    mapped="$(grep -i '^x-mapped-model:' "$hf" | head -1 | sed -E 's/^[^:]+:[[:space:]]*//' | tr -d '\r' || true)"
  else
    err="$(cat "$bf" 2>/dev/null || echo "HTTP $http_code")"
    [[ "$allow_error" == "true" ]] || { rm -f "$hf" "$bf"; die "Request failed: $err"; }
  fi
  rm -f "$hf" "$bf"; echo "${http_code}|${email}|${mapped}|${err}"
}

select_working_model() {
  local dp="$1"; IFS=',' read -ra fa <<< "$FALLBACK_MODELS"
  local -a cands=("$MODEL")
  for m in "${fa[@]}"; do m="$(echo "$m"|xargs)"; [[ -z "$m" ]] && continue
    local dup=false; for c in "${cands[@]}"; do [[ "$c" == "$m" ]] && dup=true; done
    [[ "$dup" == "false" ]] && cands+=("$m")
  done
  local fails=""
  for c in "${cands[@]}"; do printf "${C_GRAY}Trying model: %s${C_RESET}\n" "$c"
    local r s; r="$(invoke_test_request "$c" "$dp" "true")"; s="$(echo "$r"|cut -d'|' -f1)"
    [[ "$s" == "200" ]] && { echo "$c"; return 0; }; fails="${fails}${c}:${s}, "
  done; die "No working model found. Attempts: ${fails%, }"
}

# ── Main ───────────────────────────────────────────────────────────────────
write_section "Gephyr Compliance Counters Smoke Test"
printf "${C_GRAY}Sends a request burst and verifies compliance counters move.${C_RESET}\n"
[[ -f "$CONSOLE_SCRIPT" ]] || die "console.sh not found at $CONSOLE_SCRIPT"
load_env_local
assert_dependencies
ensure_api_key
[[ "$REQUEST_COUNT" -ge 1 ]] || die "request-count must be >= 1"
[[ "$POLL_INFLIGHT_ATTEMPTS" -ge 1 ]] || die "poll-inflight-attempts must be >= 1"
[[ "$POLL_INFLIGHT_DELAY_MS" -ge 10 ]] || die "poll-inflight-delay-ms must be >= 10"

if [[ "$SKIP_START" != "true" ]]; then
  write_step 1 "Start server with admin API enabled"; start_server
  wait_service_ready || die "Service did not become ready on $BASE_URL"
  printf "${C_GREEN}Service is ready.${C_RESET}\n"
else write_step 1 "Using running server (SkipStart)"; fi

write_step 2 "Verify route capability"
cap="$(api_get "/api/version/routes")"
printf '%s' "$cap" | jq -e '.routes["POST /api/proxy/compliance"]' >/dev/null 2>&1 || die "Running image does not expose POST /api/proxy/compliance."
printf "${C_GREEN}Running version: %s${C_RESET}\n" "$(printf '%s' "$cap" | jq -r '.version // "unknown"')"

write_step 3 "Ensure at least one account is linked"
acct_count="$(ensure_account_linked)"; printf "${C_GREEN}Linked accounts: %s${C_RESET}\n" "$acct_count"

write_step 4 "Enable compliance via dedicated endpoint"
update_resp="$(api_post_json "/api/proxy/compliance" '{"enabled":true,"max_global_requests_per_minute":120,"max_account_requests_per_minute":20,"max_account_concurrency":2,"risk_cooldown_seconds":300,"max_retry_attempts":2}')"
[[ "$(printf '%s' "$update_resp" | jq -r '.ok // "true"')" != "false" ]] || die "Compliance update endpoint reported failure."
verify="$(api_get "/api/proxy/compliance")"
[[ "$(printf '%s' "$verify" | jq -r '.config.enabled // false')" == "true" ]] || die "Compliance not enabled after update."
printf "${C_GREEN}Compliance config updated.${C_RESET}\n"

write_step 5 "Capture counters before traffic"
before_global="$(printf '%s' "$verify" | jq -r '.global_requests_in_last_minute // 0')"
before_acct="$(printf '%s' "$verify" | jq -c '.account_requests_in_last_minute // {}')"
printf "${C_GRAY}Captured snapshot: global=%s, accounts=%s${C_RESET}\n" "$before_global" "$(printf '%s' "$before_acct" | jq 'length')"

write_step 6 "Pick a working model and send request burst"
run_id="$(date -u +%Y%m%d-%H%M%S)"
selected_model="$(select_working_model "Compliance smoke discovery run=$run_id")"
probe_requests=1; printf "${C_GREEN}Selected model: %s${C_RESET}\n" "$selected_model"

sent=0; ok=0; declare -A account_hits; peak_inflight=0

if [[ "$STRESS_MODE" == "true" ]]; then
  printf "${C_YELLOW}Stress mode: launching %d concurrent requests...${C_RESET}\n" "$REQUEST_COUNT"
  sdir="$(mktemp -d)"; pids=()
  for i in $(seq 1 "$REQUEST_COUNT"); do
    prompt="Compliance stress request $i run=$run_id. Reply in one sentence."
    ( body="$(jq -n --arg m "$selected_model" --arg c "$prompt" '{model:$m,messages:[{role:"user",content:$c}]}')"
      hf="$(mktemp)"; bf="$(mktemp)"
      hc="$(curl -s -o "$bf" -D "$hf" -w "%{http_code}" -H "Authorization: Bearer ${GEPHYR_API_KEY}" -H "Content-Type: application/json" -X POST --max-time 120 -d "$body" "${BASE_URL}/v1/chat/completions" 2>/dev/null || echo "000")"
      em=""; [[ "$hc" == "200" ]] && em="$(grep -i '^x-account-email:' "$hf"|head -1|sed -E 's/^[^:]+:[[:space:]]*//'|tr -d '\r'||true)"
      echo "${i}|${hc}|${em}" > "$sdir/r_${i}.txt"; rm -f "$hf" "$bf"
    ) & pids+=($!)
  done
  poll_s="$(echo "scale=3; $POLL_INFLIGHT_DELAY_MS / 1000" | bc)"
  for _ in $(seq 1 "$POLL_INFLIGHT_ATTEMPTS"); do
    alive=0; for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null && alive=1 && break; done; [[ "$alive" -eq 0 ]] && break
    snap="$(api_get "/api/proxy/compliance" 2>/dev/null || true)"
    [[ -n "$snap" ]] && { ift="$(printf '%s' "$snap"|jq '[.account_in_flight//{}|to_entries[]|.value]|add//0' 2>/dev/null||echo 0)"; [[ "$ift" -gt "$peak_inflight" ]] && peak_inflight="$ift"; }
    sleep "$poll_s"
  done
  for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
  for i in $(seq 1 "$REQUEST_COUNT"); do
    [[ -f "$sdir/r_${i}.txt" ]] || continue; rl="$(cat "$sdir/r_${i}.txt")"
    idx="$(echo "$rl"|cut -d'|' -f1)"; st="$(echo "$rl"|cut -d'|' -f2)"; em="$(echo "$rl"|cut -d'|' -f3)"
    sent=$((sent+1))
    if [[ "$st" == "200" ]]; then ok=$((ok+1)); [[ -n "$em" ]] && account_hits["$em"]=$(( ${account_hits["$em"]:-0} + 1 ))
      printf "${C_GREEN}  #%s: 200 (%s)${C_RESET}\n" "$idx" "$em"
    else printf "${C_YELLOW}  #%s: %s${C_RESET}\n" "$idx" "$st"; fi
  done; rm -rf "$sdir"
else
  for i in $(seq 1 "$REQUEST_COUNT"); do
    prompt="Compliance smoke request $i run=$run_id. Reply in one sentence."
    r="$(invoke_test_request "$selected_model" "$prompt" "true")"; st="$(echo "$r"|cut -d'|' -f1)"; em="$(echo "$r"|cut -d'|' -f2)"
    sent=$((sent+1))
    if [[ "$st" == "200" ]]; then ok=$((ok+1)); [[ -n "$em" ]] && account_hits["$em"]=$(( ${account_hits["$em"]:-0} + 1 ))
      printf "${C_GREEN}  #%d: 200 (%s)${C_RESET}\n" "$i" "$em"
    else printf "${C_YELLOW}  #%d: %s${C_RESET}\n" "$i" "$st"; fi
  done
fi

[[ "$ok" -gt 0 ]] || die "All smoke requests failed. Cannot validate counter movement."

write_step 7 "Capture counters after traffic"
after="$(api_get "/api/proxy/compliance")"
after_global="$(printf '%s' "$after"|jq -r '.global_requests_in_last_minute//0')"
after_acct="$(printf '%s' "$after"|jq -c '.account_requests_in_last_minute//{}')"
after_inflight="$(printf '%s' "$after"|jq -c '.account_in_flight//{}')"
after_cooldown="$(printf '%s' "$after"|jq -c '.account_cooldown_seconds_remaining//{}')"
global_delta=$((after_global - before_global))

write_step 8 "Result summary"
printf "Probe requests:     %d\nBurst requests:     %d\nExpected tracked:   %d\n" "$probe_requests" "$sent" "$((probe_requests+sent))"
printf "Requests sent:      %d\nRequests succeeded: %d\nModel used:         %s\n" "$sent" "$ok" "$selected_model"
printf "Global before:      %d\nGlobal after:       %d\nGlobal delta:       %d\n" "$before_global" "$after_global" "$global_delta"

if [[ ${#account_hits[@]} -gt 0 ]]; then echo ""; echo "Observed account hits (from response headers):"
  for k in "${!account_hits[@]}"; do printf "  %s: %d\n" "$k" "${account_hits[$k]}"; done; fi

echo ""; echo "Account counter deltas:"
all_keys="$(printf '%s\n%s' "$(printf '%s' "$before_acct"|jq -r 'keys[]' 2>/dev/null)" "$(printf '%s' "$after_acct"|jq -r 'keys[]' 2>/dev/null)"|sort -u|grep -v '^$'||true)"
if [[ -z "$all_keys" ]]; then echo "  (no account counters recorded)"
else while IFS= read -r k; do b="$(printf '%s' "$before_acct"|jq -r --arg k "$k" '.[$k]//0')"; a="$(printf '%s' "$after_acct"|jq -r --arg k "$k" '.[$k]//0')"
  printf "  %s: %d -> %d (delta %d)\n" "$k" "$b" "$a" "$((a-b))"; done <<< "$all_keys"; fi

echo ""
printf "In-flight map now:  %s\nCooldown map now:   %s\n" "$after_inflight" "$after_cooldown"
[[ "$STRESS_MODE" == "true" ]] && printf "Peak in-flight observed during load: %d\n" "$peak_inflight"
[[ "$global_delta" -ge 1 ]] || die "FAIL: global compliance counter did not increase."
echo ""; printf "${C_GREEN}PASS: Compliance counters moved after request burst.${C_RESET}\n"
