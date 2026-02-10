#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Validate sticky session binding persistence across container restart.
#
# Linux/macOS equivalent of test-session-binding-persistence.ps1.
#
# Usage:
#   ./scripts/test-session-binding-persistence.sh [options]
#
# Examples:
#   ./scripts/test-session-binding-persistence.sh
#   ./scripts/test-session-binding-persistence.sh --auto-login --no-pause
#   ./scripts/test-session-binding-persistence.sh --model gemini-3-flash --no-pause
#
# Options:
#   --port <int>                 Default: 8045
#   --container <string>         Default: gephyr
#   --image <string>             Default: gephyr:latest
#   --data-dir <string>          Default: $HOME/.gephyr
#   --model <string>             Default: gpt-5.3-codex
#   --fallback-models <csv>      Default: gemini-3-flash,gemini-3.0-flash,claude-sonnet-4-5
#   --prompt <string>            Base prompt for deterministic session id
#   --auto-login                 Starts OAuth flow if no account linked
#   --no-pause                   Skips interactive pause before restart
#   -h, --help                   Print this usage
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONSOLE_SCRIPT="$REPO_ROOT/console.sh"
ENV_FILE="$REPO_ROOT/.env.local"

PORT="${PORT:-8045}"
CONTAINER_NAME="${CONTAINER_NAME:-gephyr}"
IMAGE="${IMAGE:-gephyr:latest}"
DATA_DIR="${GEPHYR_DATA_DIR:-$HOME/.gephyr}"
MODEL="gpt-5.3-codex"
FALLBACK_MODELS="gemini-3-flash,gemini-3.0-flash,claude-sonnet-4-5"
PROMPT="Persistent session binding validation prompt for restart testing."
AUTO_LOGIN="false"
NO_PAUSE="false"

# ── Colors ─────────────────────────────────────────────────────────────────
C_CYAN="\033[36m"
C_YELLOW="\033[33m"
C_GREEN="\033[32m"
C_GRAY="\033[90m"
C_RED="\033[31m"
C_RESET="\033[0m"

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

# ── Argument parsing ───────────────────────────────────────────────────────
show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/test-session-binding-persistence.sh [options]

Common examples:
  ./scripts/test-session-binding-persistence.sh
  ./scripts/test-session-binding-persistence.sh --auto-login --no-pause
  ./scripts/test-session-binding-persistence.sh --model gemini-3-flash --no-pause

Options:
  --port <int>                 Default: 8045
  --container <string>         Default: gephyr
  --image <string>             Default: gephyr:latest
  --data-dir <string>          Default: $HOME/.gephyr
  --model <string>             Default: gpt-5.3-codex
  --fallback-models <csv>      Default: gemini-3-flash,gemini-3.0-flash,claude-sonnet-4-5
  --prompt <string>            Base prompt for deterministic session id
  --auto-login                 Starts OAuth flow if no account linked
  --no-pause                   Skips interactive pause before restart
  -h, --help                   Print this usage
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)             PORT="$2"; shift 2 ;;
    --container)        CONTAINER_NAME="$2"; shift 2 ;;
    --image)            IMAGE="$2"; shift 2 ;;
    --data-dir)         DATA_DIR="$2"; shift 2 ;;
    --model)            MODEL="$2"; shift 2 ;;
    --fallback-models)  FALLBACK_MODELS="$2"; shift 2 ;;
    --prompt)           PROMPT="$2"; shift 2 ;;
    --auto-login)       AUTO_LOGIN="true"; shift ;;
    --no-pause)         NO_PAUSE="true"; shift ;;
    -h|--help)          show_usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

BASE_URL="http://127.0.0.1:${PORT}"

# ── Shared helpers ─────────────────────────────────────────────────────────
load_env_local() {
  [[ -f "$ENV_FILE" ]] || return 0
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "${line:0:1}" == "#" || "$line" != *"="* ]] && continue
    local key="${line%%=*}" value="${line#*=}"
    key="$(echo "$key" | xargs)"
    value="$(echo "$value" | sed -E "s/^['\"]|['\"]$//g")"
    if [[ -n "$key" && -n "$value" && -z "${!key:-}" ]]; then
      export "$key=$value"
    fi
  done < "$ENV_FILE"
}

ensure_api_key() {
  if [[ -z "${GEPHYR_API_KEY:-}" ]]; then
    die "Missing GEPHYR_API_KEY. Set env var or add it to .env.local."
  fi
}

assert_docker_ready() {
  command -v docker >/dev/null 2>&1 || die "Docker CLI not found in PATH."
  docker info >/dev/null 2>&1 || die "Docker daemon is not reachable. Start Docker first."
}

wait_service_ready() {
  local attempts="${1:-50}" delay="${2:-0.5}"
  ensure_api_key
  for _ in $(seq 1 "$attempts"); do
    local code
    code="$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer ${GEPHYR_API_KEY}" \
      "${BASE_URL}/healthz" 2>/dev/null || true)"
    [[ "$code" == "200" ]] && return 0
    sleep "$delay"
  done
  return 1
}

start_server() {
  bash "$CONSOLE_SCRIPT" start --admin-api --port "$PORT" --container "$CONTAINER_NAME" --image "$IMAGE" --data-dir "$DATA_DIR"
}

stop_server() {
  bash "$CONSOLE_SCRIPT" stop --port "$PORT" --container "$CONTAINER_NAME" --image "$IMAGE" --data-dir "$DATA_DIR"
}

start_login_flow() {
  bash "$CONSOLE_SCRIPT" login --port "$PORT" --container "$CONTAINER_NAME" --image "$IMAGE" --data-dir "$DATA_DIR"
}

api_get() {
  ensure_api_key
  curl -sS -H "Authorization: Bearer ${GEPHYR_API_KEY}" \
    --max-time 30 "${BASE_URL}$1"
}

api_post_json() {
  ensure_api_key
  curl -sS -H "Authorization: Bearer ${GEPHYR_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST --max-time 60 -d "$2" "${BASE_URL}$1"
}

has_json_key() {
  # Usage: has_json_key "$json" ".path.to.key"
  local val
  val="$(printf '%s' "$1" | jq -r "$2 // empty" 2>/dev/null)"
  [[ -n "$val" ]]
}

pause_if_needed() {
  if [[ "$NO_PAUSE" != "true" ]]; then
    read -rp "${1:-Press Enter to continue} "
  fi
}

get_session_id_from_prompt() {
  local text="$1"
  text="$(echo "$text" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
  if [[ ${#text} -le 10 ]]; then
    die "Prompt must be > 10 chars to match session extraction logic."
  fi
  if [[ "$text" == *"<system-reminder>"* ]]; then
    die "Prompt cannot contain '<system-reminder>' for deterministic session-id generation."
  fi
  local hex
  hex="$(printf '%s' "$text" | sha256sum | awk '{print $1}')"
  echo "sid-${hex:0:16}"
}

# Returns: status|account_email|response_id|mapped_model|error_message
invoke_test_request() {
  local message="$1" request_model="$2" allow_error="${3:-false}"
  local body
  body="$(jq -n --arg model "$request_model" --arg content "$message" \
    '{model: $model, messages: [{role: "user", content: $content}]}')"

  local tmpfile
  tmpfile="$(mktemp)"
  local http_code
  http_code="$(curl -s -o "$tmpfile" -w "%{http_code}" \
    -H "Authorization: Bearer ${GEPHYR_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST --max-time 120 \
    -D - \
    -d "$body" "${BASE_URL}/v1/chat/completions" 2>/dev/null || echo "000")"

  # Separate headers and body from the -D - output
  # Re-do: use two files
  rm -f "$tmpfile"
  local header_file body_file
  header_file="$(mktemp)"
  body_file="$(mktemp)"

  http_code="$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
    -H "Authorization: Bearer ${GEPHYR_API_KEY}" \
    -H "Content-Type: application/json" \
    -X POST --max-time 120 \
    -d "$body" "${BASE_URL}/v1/chat/completions" 2>/dev/null || echo "000")"

  local account_email="" response_id="" mapped_model="" error_message=""

  if [[ "$http_code" == "200" ]]; then
    account_email="$(grep -i '^x-account-email:' "$header_file" | head -1 | sed -E 's/^[^:]+:[[:space:]]*//' | tr -d '\r' || true)"
    mapped_model="$(grep -i '^x-mapped-model:' "$header_file" | head -1 | sed -E 's/^[^:]+:[[:space:]]*//' | tr -d '\r' || true)"
    response_id="$(jq -r '.id // empty' "$body_file" 2>/dev/null || true)"
  else
    error_message="$(cat "$body_file" 2>/dev/null || true)"
    if [[ -z "$error_message" ]]; then
      error_message="HTTP $http_code"
    fi
    if [[ "$allow_error" != "true" ]]; then
      rm -f "$header_file" "$body_file"
      die "Request failed: $error_message"
    fi
  fi

  rm -f "$header_file" "$body_file"
  # Return pipe-delimited string
  echo "${http_code}|${account_email}|${response_id}|${mapped_model}|${request_model}|${error_message}"
}

# Tries primary model then fallbacks; prints result line on success
invoke_test_request_with_fallback() {
  local message="$1"
  IFS=',' read -ra fallback_arr <<< "$FALLBACK_MODELS"

  # Build unique candidate list
  local -a candidates=("$MODEL")
  for m in "${fallback_arr[@]}"; do
    m="$(echo "$m" | xargs)"
    [[ -z "$m" ]] && continue
    local dup=false
    for c in "${candidates[@]}"; do [[ "$c" == "$m" ]] && dup=true; done
    [[ "$dup" == "false" ]] && candidates+=("$m")
  done

  local attempts_summary=""
  for candidate in "${candidates[@]}"; do
    printf "${C_GRAY}Trying model: %s${C_RESET}\n" "$candidate"
    local result
    result="$(invoke_test_request "$message" "$candidate" "true")"
    local status
    status="$(echo "$result" | cut -d'|' -f1)"
    if [[ "$status" == "200" ]]; then
      echo "$result"
      return 0
    fi
    attempts_summary="${attempts_summary}${candidate}:${status}, "
  done

  die "No test model succeeded. Attempts: ${attempts_summary%, }"
}

get_binding_map_value() {
  local session_id="$1"
  local binding_file="$DATA_DIR/session_bindings.json"
  if [[ ! -f "$binding_file" ]]; then
    die "Binding file not found: $binding_file"
  fi
  local raw
  raw="$(cat "$binding_file")"
  if [[ -z "$raw" || "$raw" == "{}" ]]; then
    return 1
  fi
  local val
  val="$(printf '%s' "$raw" | jq -r --arg sid "$session_id" '.[$sid] // empty' 2>/dev/null)"
  if [[ -z "$val" ]]; then
    return 1
  fi
  echo "$val"
}

# ── Main ───────────────────────────────────────────────────────────────────
write_section "Gephyr Persistent Session Binding Restart Test"
printf "${C_GRAY}This script validates sticky session continuity across container restart.${C_RESET}\n"
printf "${C_GRAY}Validation signals used:${C_RESET}\n"
printf "${C_GRAY}  - same deterministic session_id before/after restart${C_RESET}\n"
printf "${C_GRAY}  - same X-Account-Email before/after restart${C_RESET}\n"
printf "${C_GRAY}  - session key present in session_bindings.json${C_RESET}\n"

[[ -f "$CONSOLE_SCRIPT" ]] || die "console.sh not found at $CONSOLE_SCRIPT"

load_env_local
assert_dependencies
assert_docker_ready
ensure_api_key

original_preferred_account=""
should_restore_preferred="false"

cleanup() {
  if [[ "$should_restore_preferred" == "true" && -n "$original_preferred_account" ]]; then
    local payload
    payload="$(jq -n --arg aid "$original_preferred_account" '{accountId: $aid}')"
    api_post_json "/api/proxy/preferred-account" "$payload" >/dev/null 2>&1 || \
      printf "${C_YELLOW}Warning: failed to restore preferred account automatically.${C_RESET}\n"
    printf "${C_GRAY}Restored original preferred account: %s${C_RESET}\n" "$original_preferred_account"
  fi
}
trap cleanup EXIT

write_step 1 "Start server with admin API enabled"
start_server
if ! wait_service_ready; then
  die "Service did not become ready on $BASE_URL"
fi
printf "${C_GREEN}Service is ready.${C_RESET}\n"

write_step 2 "Check config prerequisites (persist_session_bindings + scheduling mode)"
cap="$(api_get "/api/version/routes")"
has_sticky_patch="false"
if printf '%s' "$cap" | jq -e '.routes["POST /api/proxy/sticky"]' >/dev/null 2>&1; then
  has_sticky_patch="true"
fi

cfg="$(api_get "/api/config")"
config_changed="false"

if ! printf '%s' "$cfg" | jq -e '.proxy' >/dev/null 2>&1; then
  die "Runtime /api/config response is missing 'proxy'. Cannot validate prerequisites."
fi

has_persist_snake="false"
has_persist_camel="false"
if printf '%s' "$cfg" | jq -e '.proxy.persist_session_bindings != null' >/dev/null 2>&1; then
  has_persist_snake="true"
fi
if printf '%s' "$cfg" | jq -e '.proxy.persistSessionBindings != null' >/dev/null 2>&1; then
  has_persist_camel="true"
fi

if [[ "$has_persist_snake" == "false" && "$has_persist_camel" == "false" ]]; then
  die "Current runtime does not expose proxy.persist_session_bindings in /api/config.
This usually means the running image is older than the persistence implementation.

Rebuild and run the latest local image, then rerun this script:
  docker build -t gephyr:latest -f docker/Dockerfile ."
fi

persist_enabled="false"
if [[ "$has_persist_snake" == "true" ]]; then
  persist_enabled="$(printf '%s' "$cfg" | jq -r '.proxy.persist_session_bindings')"
else
  persist_enabled="$(printf '%s' "$cfg" | jq -r '.proxy.persistSessionBindings')"
fi

if [[ "$persist_enabled" != "true" ]]; then
  printf "${C_YELLOW}persist_session_bindings=false -> enabling it for this test.${C_RESET}\n"
  if [[ "$has_persist_snake" == "true" ]]; then
    cfg="$(printf '%s' "$cfg" | jq '.proxy.persist_session_bindings = true')"
  else
    cfg="$(printf '%s' "$cfg" | jq '.proxy.persistSessionBindings = true')"
  fi
  config_changed="true"
fi

if ! printf '%s' "$cfg" | jq -e '.proxy.scheduling.mode' >/dev/null 2>&1; then
  die "Runtime /api/config is missing proxy.scheduling.mode. Cannot validate sticky mode prerequisite."
fi

current_mode="$(printf '%s' "$cfg" | jq -r '.proxy.scheduling.mode')"
if [[ "$current_mode" == "performance_first" || "$current_mode" == "PerformanceFirst" ]]; then
  printf "${C_YELLOW}scheduling.mode=performance_first disables sticky behavior -> switching to balance for this test.${C_RESET}\n"
  cfg="$(printf '%s' "$cfg" | jq '.proxy.scheduling.mode = "Balance"')"
  config_changed="true"
fi

if [[ "$config_changed" == "true" ]]; then
  if [[ "$has_sticky_patch" == "true" ]]; then
    if [[ "$has_persist_snake" == "true" ]]; then
      persist_target="$(printf '%s' "$cfg" | jq -r '.proxy.persist_session_bindings')"
    else
      persist_target="$(printf '%s' "$cfg" | jq -r '.proxy.persistSessionBindings')"
    fi
    sched_mode="$(printf '%s' "$cfg" | jq -r '.proxy.scheduling.mode')"
    max_wait=60
    mw="$(printf '%s' "$cfg" | jq -r '.proxy.scheduling.max_wait_seconds // .proxy.scheduling.maxWaitSeconds // 60')"
    [[ -n "$mw" ]] && max_wait="$mw"

    payload="$(jq -n \
      --argjson persist "$([[ "$persist_target" == "true" ]] && echo true || echo false)" \
      --arg mode "$sched_mode" \
      --argjson mw "$max_wait" \
      '{persist_session_bindings: $persist, scheduling: {mode: $mode, max_wait_seconds: $mw}}')"
    api_post_json "/api/proxy/sticky" "$payload" >/dev/null
    printf "${C_GREEN}Sticky config updated via /api/proxy/sticky (hot-applied).${C_RESET}\n"
  else
    payload="$(jq -n --argjson cfg "$cfg" '{config: $cfg}')"
    api_post_json "/api/config" "$payload" >/dev/null
    printf "${C_YELLOW}Config updated. Restarting server so token manager picks up changes...${C_RESET}\n"
    stop_server
    start_server
    if ! wait_service_ready; then
      die "Service did not become ready after config restart."
    fi
  fi
else
  printf "${C_GREEN}Config looks good for persistence test.${C_RESET}\n"
fi

write_step 3 "Neutralize preferred-account override (if set)"
preferred="$(api_get "/api/proxy/preferred-account" || true)"
preferred_val=""
if [[ -n "$preferred" ]]; then
  preferred_val="$(printf '%s' "$preferred" | jq -r '. // empty' 2>/dev/null || printf '%s' "$preferred" | tr -d '[:space:]"')"
fi
if [[ -n "$preferred_val" && "$preferred_val" != "null" && "$preferred_val" != "" ]]; then
  original_preferred_account="$preferred_val"
  should_restore_preferred="true"
  printf "${C_YELLOW}Preferred account was set to: %s. Temporarily clearing it for sticky-session validation.${C_RESET}\n" "$original_preferred_account"
  api_post_json "/api/proxy/preferred-account" '{"accountId": null}' >/dev/null
else
  printf "${C_GREEN}No preferred account override detected.${C_RESET}\n"
fi

write_step 4 "Ensure at least one linked account exists"
accounts_resp="$(api_get "/api/accounts")"
account_count="$(printf '%s' "$accounts_resp" | jq '.accounts | length' 2>/dev/null || echo 0)"

if [[ "$account_count" -eq 0 ]]; then
  printf "${C_YELLOW}No linked accounts found.${C_RESET}\n"
  if [[ "$AUTO_LOGIN" == "true" ]]; then
    printf "${C_YELLOW}Starting OAuth login flow...${C_RESET}\n"
    start_login_flow
    pause_if_needed "Complete browser OAuth login now, then press Enter"
    account_ready="false"
    for _ in $(seq 1 30); do
      sleep 2
      accounts_resp="$(api_get "/api/accounts")"
      account_count="$(printf '%s' "$accounts_resp" | jq '.accounts | length' 2>/dev/null || echo 0)"
      if [[ "$account_count" -gt 0 ]]; then
        account_ready="true"
        break
      fi
    done
    [[ "$account_ready" == "true" ]] || die "No accounts linked after OAuth flow."
  else
    die "No linked accounts found. Re-run with --auto-login or link account(s) first."
  fi
fi

printf "${C_GREEN}Linked accounts: %d${C_RESET}\n" "$account_count"
if [[ "$account_count" -lt 2 ]]; then
  printf "${C_YELLOW}Note: only one account linked. This still tests persistence, but account-stickiness proof is weaker than multi-account.${C_RESET}\n"
fi

# Build email->id map for later cross-reference
email_to_id_json="$(printf '%s' "$accounts_resp" | jq '[.accounts[] | select(.email and .id) | {key: .email, value: .id}] | from_entries' 2>/dev/null || echo '{}')"

write_step 5 "Create deterministic test session and send pre-restart request"
run_id="$(date -u +%Y%m%d-%H%M%S)"
test_prompt="${PROMPT} run=${run_id} please answer in one short sentence."
session_id="$(get_session_id_from_prompt "$test_prompt")"
printf "${C_GRAY}Derived session_id: %s${C_RESET}\n" "$session_id"

result="$(invoke_test_request_with_fallback "$test_prompt")"
before_status="$(echo "$result" | cut -d'|' -f1)"
before_email="$(echo "$result" | cut -d'|' -f2)"
selected_model="$(echo "$result" | cut -d'|' -f5)"
printf "${C_GREEN}Selected working model for this test run: %s${C_RESET}\n" "$selected_model"

[[ "$before_status" == "200" ]] || die "Pre-restart request failed with status $before_status."
[[ -n "$before_email" ]] || die "Pre-restart response did not include X-Account-Email; cannot validate binding."
printf "${C_GREEN}Pre-restart account: %s${C_RESET}\n" "$before_email"

write_step 6 "Verify session binding file entry exists before restart"
bound_id_before="$(get_binding_map_value "$session_id")" || \
  die "Session id '$session_id' not found in $DATA_DIR/session_bindings.json"
printf "${C_GREEN}session_bindings.json maps %s -> %s${C_RESET}\n" "$session_id" "$bound_id_before"

expected_id="$(printf '%s' "$email_to_id_json" | jq -r --arg e "$before_email" '.[$e] // empty' 2>/dev/null || true)"
if [[ -n "$expected_id" && "$expected_id" != "$bound_id_before" ]]; then
  printf "${C_YELLOW}Warning: header email maps to account id '%s', but file has '%s'.${C_RESET}\n" "$expected_id" "$bound_id_before"
fi

pause_if_needed

write_step 7 "Stop container (simulate downtime) and start again"
stop_server
start_server
if ! wait_service_ready; then
  die "Service did not become ready after restart."
fi
printf "${C_GREEN}Service restarted and healthy.${C_RESET}\n"

write_step 8 "Send same-session request after restart"
after_result="$(invoke_test_request "$test_prompt" "$selected_model")"
after_status="$(echo "$after_result" | cut -d'|' -f1)"
after_email="$(echo "$after_result" | cut -d'|' -f2)"

[[ "$after_status" == "200" ]] || die "Post-restart request failed with status $after_status."
[[ -n "$after_email" ]] || die "Post-restart response did not include X-Account-Email; cannot validate binding."
printf "${C_GREEN}Post-restart account: %s${C_RESET}\n" "$after_email"

write_step 9 "Re-check binding file and conclude"
bound_id_after="$(get_binding_map_value "$session_id")" || \
  die "Session id '$session_id' missing from binding file after restart."

same_email="false"
same_file_binding="false"
[[ "$before_email" == "$after_email" ]] && same_email="true"
[[ "$bound_id_before" == "$bound_id_after" ]] && same_file_binding="true"

echo ""
printf "${C_CYAN}Result summary:${C_RESET}\n"
printf "  session_id:          %s\n" "$session_id"
printf "  pre account email:   %s\n" "$before_email"
printf "  post account email:  %s\n" "$after_email"
printf "  file binding before: %s\n" "$bound_id_before"
printf "  file binding after:  %s\n" "$bound_id_after"

if [[ "$same_email" == "true" && "$same_file_binding" == "true" ]]; then
  echo ""
  printf "${C_GREEN}PASS: Session binding persisted and restored across restart.${C_RESET}\n"
else
  die "FAIL: Binding continuity check failed (email match: $same_email, file binding match: $same_file_binding)."
fi
