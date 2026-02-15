#!/usr/bin/env bash
# Verifies prompt-generation routes are disabled in a running Gephyr instance.
#
# Sends authenticated POST requests to routes that should be disabled when
# GEPHYR_DISABLE_PROMPT_ROUTES=true was set at startup. Expects each route
# to return 404/405 (not found / method not allowed).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BASE_URL="http://127.0.0.1:8045"
API_KEY_ARG=""
MODEL="gemini-3-flash"
TRACE_PATH=""

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/verify-prompt-routes-disabled.sh [options]

Options:
  --base-url <url>   Default: http://127.0.0.1:8045
  --api-key <key>    API key (or set API_KEY / GEPHYR_API_KEY env)
  --model <name>     Default: gemini-3-flash
  --trace <path>     Optional trace JSONL for supplemental upstream check
  -h, --help         Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE_URL="$2"; shift 2 ;;
    --api-key) API_KEY_ARG="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --trace) TRACE_PATH="$2"; shift 2 ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

cd "$REPO_ROOT"
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required." >&2; exit 1; }

# Load .env.local
ENV_FILE="$REPO_ROOT/.env.local"
if [[ -f "$ENV_FILE" ]]; then
  while IFS= read -r raw; do
    line="${raw#"${raw%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "${line:0:1}" == "#" || "$line" != *"="* ]] && continue
    k="${line%%=*}"; v="${line#*=}"
    k="$(printf '%s' "$k" | tr -d '\r' | xargs)"
    v="$(printf '%s' "$v" | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g")"
    [[ -n "$k" ]] && export "${k}=${v}"
  done < "$ENV_FILE"
fi

# Resolve API key
resolve_api_key() {
  [[ -n "$API_KEY_ARG" ]] && { echo "$API_KEY_ARG"; return; }
  [[ -n "${API_KEY:-}" ]] && { echo "$API_KEY"; return; }
  [[ -n "${GEPHYR_API_KEY:-}" ]] && { echo "$GEPHYR_API_KEY"; return; }

  local data_dir="${DATA_DIR:-$HOME/.gephyr}"
  local config_path="$data_dir/config.json"
  if [[ -f "$config_path" ]] && command -v python3 >/dev/null 2>&1; then
    local key
    key="$(python3 -c "import json; print(json.load(open('$config_path')).get('proxy',{}).get('api_key',''))" 2>/dev/null || true)"
    [[ -n "$key" ]] && { echo "$key"; return; }
  fi

  echo "ERROR: API key not found. Pass --api-key or set API_KEY/GEPHYR_API_KEY." >&2
  exit 1
}

RESOLVED_KEY="$(resolve_api_key)"

# Post helper — returns "http_code body"
post_json() {
  local url="$1" body="$2"
  local resp http_code resp_body
  resp="$(curl -sS -w '\n%{http_code}' \
    -H "Authorization: Bearer $RESOLVED_KEY" \
    -H "Content-Type: application/json" \
    -X POST -d "$body" --max-time 30 \
    "$url" 2>/dev/null || echo -e '\n000')"
  http_code="$(printf '%s' "$resp" | tail -n 1)"
  resp_body="$(printf '%s' "$resp" | sed '$d')"
  echo "$http_code"
}

gemini_body="{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"ping\"}]}]}"
openai_chat_body="{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}],\"stream\":false}"
openai_completions_body="{\"model\":\"$MODEL\",\"prompt\":\"ping\",\"max_tokens\":1}"
openai_responses_body="{\"model\":\"$MODEL\",\"input\":\"ping\"}"

declare -a test_names test_urls test_bodies
test_names=("/v1/chat/completions" "/v1/completions" "/v1/responses" "/v1beta/models/:model:generateContent" "/v1beta/models/:model:streamGenerateContent")
test_urls=("$BASE_URL/v1/chat/completions" "$BASE_URL/v1/completions" "$BASE_URL/v1/responses" "$BASE_URL/v1beta/models/$MODEL:generateContent" "$BASE_URL/v1beta/models/$MODEL:streamGenerateContent?alt=sse")
test_bodies=("$openai_chat_body" "$openai_completions_body" "$openai_responses_body" "$gemini_body" "$gemini_body")

echo -e "\033[36mProbing disabled prompt routes at $BASE_URL ...\033[0m"
failed=false
printf "%-50s %-10s %-10s\n" "Route" "Status" "DisabledOK"
printf "%-50s %-10s %-10s\n" "-----" "------" "----------"

for i in "${!test_names[@]}"; do
  status="$(post_json "${test_urls[$i]}" "${test_bodies[$i]}")"
  if [[ "$status" == "404" || "$status" == "405" ]]; then
    ok="True"
  else
    ok="False"
    failed=true
  fi
  printf "%-50s %-10s %-10s\n" "${test_names[$i]}" "$status" "$ok"
done

# Supplemental trace check
if [[ -n "$TRACE_PATH" ]]; then
  [[ -f "$TRACE_PATH" ]] || { echo "ERROR: Trace file not found: $TRACE_PATH" >&2; exit 1; }
  echo ""
  hits="$(grep -cE 'v1internal:generateContent|v1internal:streamGenerateContent|generativelanguage\.googleapis\.com/.+:generateContent|generativelanguage\.googleapis\.com/.+:streamGenerateContent' "$TRACE_PATH" 2>/dev/null || echo "0")"
  if [[ "$hits" -gt 0 ]]; then
    echo -e "\033[33mSupplemental trace check: FOUND prompt upstream signatures ($hits hits).\033[0m"
    grep -E 'v1internal:generateContent|v1internal:streamGenerateContent|generativelanguage\.googleapis\.com/.+:generateContent|generativelanguage\.googleapis\.com/.+:streamGenerateContent' "$TRACE_PATH" 2>/dev/null | head -n 10
  else
    echo -e "\033[32mSupplemental trace check: no prompt upstream signatures found.\033[0m"
  fi
fi

echo ""
if [[ "$failed" == "true" ]]; then
  echo "ERROR: One or more prompt routes still responded as active (expected only 404/405). Ensure Gephyr was started with GEPHYR_DISABLE_PROMPT_ROUTES=true." >&2
  exit 1
fi

echo -e "\033[32mPASS: Prompt routes are disabled at HTTP surface (404/405 for all probes).\033[0m"
