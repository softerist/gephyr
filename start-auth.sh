#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_LOCAL="$SCRIPT_DIR/.env.local"

COMMAND="login"
PORT="${PORT:-8045}"
CONTAINER_NAME="${CONTAINER_NAME:-gephyr}"
IMAGE="${IMAGE:-gephyr:latest}"
DATA_DIR="${GEPHYR_DATA_DIR:-$HOME/.gephyr}"
LOG_LINES=120
MODEL="gpt-4o-mini"
PROMPT="hello from gephyr"
ENABLE_ADMIN_API="false"
NO_BROWSER="false"
NO_RESTART_AFTER_ROTATE="false"

print_help() {
  cat <<'EOF'
Usage:
  ./start-auth.sh [command] [options]

Commands:
  help         Show this help
  start        Start container
  stop         Stop and remove container
  restart      Restart container
  status       Show container status
  logs         Show container logs
  health       Call /healthz with API key
  login        Start with admin API, fetch /api/auth/url, open browser (default)
  oauth/auth   Alias for login
  accounts     Call /api/accounts
  api-test     Run one API test completion
  rotate-key   Generate new API key, save to .env.local, and optionally restart
  logout       Remove linked account(s) via admin API
  logout-and-stop  Logout accounts, then stop container

Options:
  --admin-api            Enable admin API on start/restart (default false)
  --port <port>          Host port (default 8045)
  --container <name>     Container name (default gephyr)
  --image <image>        Docker image (default gephyr:latest)
  --data-dir <path>      Host data dir (default $HOME/.gephyr)
  --tail <n>             Log lines for logs command (default 120)
  --model <name>         Model for api-test (default gpt-4o-mini)
  --prompt <text>        Prompt for api-test
  --no-browser           Do not open browser for login command
  --no-restart           Rotate key without restart
  -h, --help             Show help

Examples:
  ./start-auth.sh start
  ./start-auth.sh login
  ./start-auth.sh logs --tail 200
  ./start-auth.sh rotate-key
  ./start-auth.sh logout
  ./start-auth.sh logout-and-stop

Troubleshooting:
  If health returns 401, your local GEPHYR_API_KEY does not match the running container.
  Use:
    ./start-auth.sh restart
  Or rotate via rotate-key and let it restart automatically.

OAuth Login:
  The `login` command requires Google OAuth credentials available inside the container:
    GEPHYR_GOOGLE_OAUTH_CLIENT_ID
    (optional) GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET
EOF
}

load_env_local() {
  [[ -f "$ENV_LOCAL" ]] || return 0
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "${line:0:1}" == "#" || "$line" != *"="* ]] && continue
    local key="${line%%=*}"
    local value="${line#*=}"
    key="$(echo "$key" | xargs)"
    value="$(echo "$value" | sed -E "s/^['\"]|['\"]$//g")"
    if [[ -n "$key" && -n "$value" && -z "${!key:-}" ]]; then
      export "$key=$value"
    fi
  done < "$ENV_LOCAL"
}

save_env_value() {
  local key="$1"
  local value="$2"
  [[ -f "$ENV_LOCAL" ]] || echo "# Local-only secrets for Gephyr scripts" > "$ENV_LOCAL"
  awk -v k="$key" -v v="$value" '
    BEGIN { updated = 0 }
    $0 ~ "^" k "=" { print k "=" v; updated = 1; next }
    { print }
    END { if (!updated) print k "=" v }
  ' "$ENV_LOCAL" > "${ENV_LOCAL}.tmp"
  mv "${ENV_LOCAL}.tmp" "$ENV_LOCAL"
}

ensure_api_key() {
  if [[ -z "${GEPHYR_API_KEY:-}" ]]; then
    echo "Missing GEPHYR_API_KEY. Set env var or create .env.local with GEPHYR_API_KEY=..." >&2
    exit 1
  fi
}

container_exists() {
  docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}$"
}

remove_container_if_exists() {
  if container_exists; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
  fi
}

start_container() {
  local admin_api="$1"
  ensure_api_key
  mkdir -p "$DATA_DIR"
  remove_container_if_exists

  local extra_env=()
  if [[ -n "${GEPHYR_GOOGLE_OAUTH_CLIENT_ID:-}" ]]; then
    extra_env+=(-e "GEPHYR_GOOGLE_OAUTH_CLIENT_ID=${GEPHYR_GOOGLE_OAUTH_CLIENT_ID}")
  fi
  if [[ -n "${GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET:-}" ]]; then
    extra_env+=(-e "GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET=${GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET}")
  fi

  docker run --rm -d --name "$CONTAINER_NAME" \
    -p "127.0.0.1:${PORT}:8045" \
    -e API_KEY="$GEPHYR_API_KEY" \
    -e AUTH_MODE=strict \
    -e ABV_ENABLE_ADMIN_API="$admin_api" \
    -e ALLOW_LAN_ACCESS=true \
    "${extra_env[@]}" \
    -v "${DATA_DIR}:/home/gephyr/.gephyr" \
    "$IMAGE" >/dev/null

  echo "Started container: $CONTAINER_NAME"
  echo "Admin API enabled: $admin_api"
}

stop_container() {
  if container_exists; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
    echo "Stopped container: $CONTAINER_NAME"
  else
    echo "Container not found: $CONTAINER_NAME"
  fi
}

wait_service_ready() {
  ensure_api_key
  for _ in $(seq 1 40); do
    code="$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer ${GEPHYR_API_KEY}" \
      "http://127.0.0.1:${PORT}/healthz" || true)"
    [[ "$code" == "200" ]] && return 0
    sleep 0.5
  done
  return 1
}

show_status() {
  echo -e "NAMES\tSTATUS\tPORTS\tIMAGE"
  docker ps -a --format "{{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}" | awk -F '\t' -v n="$CONTAINER_NAME" '$1 == n { print }'
}

show_logs() {
  container_exists || { echo "Container not found: $CONTAINER_NAME" >&2; exit 1; }
  docker logs --tail "$LOG_LINES" "$CONTAINER_NAME"
}

show_health() {
  ensure_api_key
  curl -sS -H "Authorization: Bearer ${GEPHYR_API_KEY}" "http://127.0.0.1:${PORT}/healthz"
  echo
}

show_accounts() {
  ensure_api_key
  curl -sS -H "Authorization: Bearer ${GEPHYR_API_KEY}" "http://127.0.0.1:${PORT}/api/accounts"
  echo
}

logout_accounts() {
  ensure_api_key

  local accounts_json http_code
  accounts_json="$(curl -sS -w $'\n%{http_code}' \
    -H "Authorization: Bearer ${GEPHYR_API_KEY}" \
    "http://127.0.0.1:${PORT}/api/accounts")"
  http_code="$(printf '%s' "$accounts_json" | tail -n 1)"
  accounts_json="$(printf '%s' "$accounts_json" | sed '$d')"

  if [[ "$http_code" == "404" ]]; then
    echo "Logout requires admin API. Restart with admin API enabled, then run logout again." >&2
    exit 1
  elif [[ "$http_code" == "401" ]]; then
    echo "Logout failed with 401. API key mismatch. Run restart or rotate-key." >&2
    exit 1
  elif [[ "$http_code" -ge 400 ]]; then
    echo "Failed to query accounts for logout. HTTP $http_code" >&2
    exit 1
  fi

  local ids=()
  if command -v python3 >/dev/null 2>&1; then
    mapfile -t ids < <(
      python3 -c 'import json,sys
data=json.loads(sys.stdin.read() or "{}")
for a in data.get("accounts", []):
    v=a.get("id")
    if v:
        print(v)' <<< "$accounts_json"
    )
  else
    mapfile -t ids < <(
      printf '%s' "$accounts_json" |
        grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]+"' |
        sed -E 's/.*"([^"]+)"$/\1/'
    )
  fi

  if [[ ${#ids[@]} -eq 0 ]]; then
    echo "No linked accounts found."
    return 0
  fi

  local removed=0
  for id in "${ids[@]}"; do
    if curl -sS -o /dev/null -w "%{http_code}" \
      -X DELETE \
      -H "Authorization: Bearer ${GEPHYR_API_KEY}" \
      "http://127.0.0.1:${PORT}/api/accounts/${id}" | grep -Eq '^2[0-9][0-9]$'; then
      echo "Removed account: $id"
      removed=$((removed + 1))
    else
      echo "Failed to remove account: $id" >&2
    fi
  done

  echo "Logout completed. Removed ${removed} account(s)."
}

logout_and_stop() {
  logout_accounts
  stop_container
}

api_test() {
  ensure_api_key
  local safe_prompt="${PROMPT//\"/\\\"}"
  local body
  body="$(printf '{"model":"%s","messages":[{"role":"user","content":"%s"}]}' "$MODEL" "$safe_prompt")"
  curl -sS \
    -H "Authorization: Bearer ${GEPHYR_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "http://127.0.0.1:${PORT}/v1/chat/completions"
  echo
}

open_url() {
  local url="$1"
  if [[ "$NO_BROWSER" == "true" ]]; then
    return 0
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 || true
  elif command -v wslview >/dev/null 2>&1; then
    wslview "$url" >/dev/null 2>&1 || true
  fi
}

oauth_flow() {
  start_container "true"
  if ! wait_service_ready; then
    echo "Service did not become ready on http://127.0.0.1:${PORT}" >&2
    exit 1
  fi

  local oauth_json oauth_url
  oauth_json="$(curl -sS -H "Authorization: Bearer ${GEPHYR_API_KEY}" "http://127.0.0.1:${PORT}/api/auth/url")"
  oauth_url="$(printf '%s' "$oauth_json" | sed -nE 's/.*"url"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')"
  oauth_url="${oauth_url//\\\//\/}"

  if [[ -z "$oauth_url" ]]; then
    echo "Failed to extract OAuth URL from response: $oauth_json" >&2
    exit 1
  fi

  echo "OAuth URL:"
  echo "$oauth_url"
  open_url "$oauth_url"
}

generate_key() {
  local raw
  raw="$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | head -c 32)"
  echo "gph_${raw}"
}

rotate_key() {
  local new_key
  new_key="$(generate_key)"
  export GEPHYR_API_KEY="$new_key"
  save_env_value "GEPHYR_API_KEY" "$new_key"
  echo "Generated new API key and saved it to .env.local"

  if [[ "$NO_RESTART_AFTER_ROTATE" == "true" ]]; then
    echo "No restart requested. Restart manually to apply the new key."
    return 0
  fi

  start_container "$ENABLE_ADMIN_API"
  if wait_service_ready; then
    show_health
  else
    echo "Container restarted but health check failed." >&2
    exit 1
  fi
}

if [[ $# -gt 0 && "${1:0:1}" != "-" ]]; then
  COMMAND="$1"
  shift
fi

if [[ "$COMMAND" == "?" || "$COMMAND" == "/help" || "$COMMAND" == "-?" ]]; then
  COMMAND="help"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-api) ENABLE_ADMIN_API="true"; shift ;;
    --port) PORT="$2"; shift 2 ;;
    --container) CONTAINER_NAME="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --tail) LOG_LINES="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --prompt) PROMPT="$2"; shift 2 ;;
    --no-browser) NO_BROWSER="true"; shift ;;
    --no-restart) NO_RESTART_AFTER_ROTATE="true"; shift ;;
    -h|--help|-?|\?|/help) COMMAND="help"; shift ;;
    *)
      echo "Unknown argument: $1" >&2
      print_help
      exit 1
      ;;
  esac
done

load_env_local

case "$COMMAND" in
  help) print_help ;;
  start)
    start_container "$ENABLE_ADMIN_API"
    wait_service_ready && show_health || { echo "Service did not become ready." >&2; exit 1; }
    ;;
  stop) stop_container ;;
  restart)
    stop_container
    start_container "$ENABLE_ADMIN_API"
    wait_service_ready && show_health || { echo "Service did not become ready." >&2; exit 1; }
    ;;
  status) show_status ;;
  logs) show_logs ;;
  health) show_health ;;
  login|oauth|auth) oauth_flow ;;
  accounts) show_accounts ;;
  api-test) api_test ;;
  rotate-key) rotate_key ;;
  logout) logout_accounts ;;
  logout-and-stop) logout_and_stop ;;
  *)
    echo "Unknown command: $COMMAND" >&2
    print_help
    exit 1
    ;;
esac
