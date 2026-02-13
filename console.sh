#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_LOCAL="$SCRIPT_DIR/.env.local"

COMMAND="start"
PORT="${PORT:-8045}"
CONTAINER_NAME="${CONTAINER_NAME:-gephyr}"
IMAGE="${IMAGE:-gephyr:latest}"
DATA_DIR="${DATA_DIR:-$HOME/.gephyr}"
LOG_LINES=120
MODEL="gpt-5.3-codex"
PROMPT="hello from gephyr"
ENABLE_ADMIN_API="false"
NO_BROWSER="false"
NO_RESTART_AFTER_ROTATE="false"
AGGRESSIVE_REPAIR="false"
JSON_OUTPUT="false"
QUIET="false"
NO_CACHE="false"

print_help() {
  cat <<'EOF'
Usage:
  ./console.sh [command] [options]

Commands:
  help         Show this help
  start        Start container
  stop         Stop and remove container
  restart      Restart container
  status       Show container status
  logs         Show container logs
  health       Call /healthz with API key
  check        Run account token health check (refresh expiring tokens)
  canary       Show/Run TLS stealth canary probe (use --run to trigger)
  login        Start with admin API, fetch /api/auth/url, open browser
  oauth/auth   Alias for login
  accounts     Call /api/accounts
  api-test     Run one API test completion
  rotate-key   Generate new API key, save to .env.local, and optionally restart
  docker-repair  Repair Docker builder cache issues (e.g., missing snapshot errors)
  rebuild      Rebuild Docker image from source
  update       Pull latest code, rebuild image, and restart container
  version      Show version from Cargo.toml
  accounts-signout-all  Sign out all linked accounts (revoke + local token clear/disable)
  accounts-signout-all-and-stop  Sign out all linked accounts, then stop container
  accounts-delete-all   Delete local account records (does not revoke)
  accounts-delete-all-and-stop  Delete local accounts, then stop container

Options:
  --admin-api            Enable admin API on start/restart (default false)
  --port <port>          Host port (default 8045)
  --container <name>     Container name (default gephyr)
  --image <image>        Docker image (default gephyr:latest)
  --data-dir <path>      Host data dir (default $HOME/.gephyr)
  --tail <n>             Log lines for logs command (default 120)
  --model <name>         Model for api-test (default gpt-5.3-codex)
  --prompt <text>        Prompt for api-test
  --no-browser           Do not open browser for login command
  --no-restart           Rotate key without restart
  --aggressive           For docker-repair: remove all builder cache (slower next build)
  --json                 Output machine-readable JSON (for health, accounts)
  --quiet                Suppress non-essential output (for CI/automation)
  --no-cache             For rebuild: build without Docker cache
  -h, --help             Show help

Examples:
  ./console.sh start
  ./console.sh login
  ./console.sh logs --tail 200
  ./console.sh rotate-key
  ./console.sh rebuild
  ./console.sh rebuild --no-cache
  ./console.sh docker-repair
  ./console.sh docker-repair --aggressive
  ./console.sh accounts-signout-all
  ./console.sh accounts-signout-all-and-stop
  ./console.sh accounts-delete-all
  ./console.sh accounts-delete-all-and-stop

Troubleshooting:
  If health returns 401, your local API_KEY does not match the running container.
  Use:
    ./console.sh restart
  Or rotate via rotate-key and let it restart automatically.

OAuth Login:
  The `login` command requires Google OAuth credentials available inside the container:
    GOOGLE_OAUTH_CLIENT_ID
    (optional) GOOGLE_OAUTH_CLIENT_SECRET
  Optional identity/scheduler hardening envs are also passed through when set:
    ALLOW_LAN_ACCESS
    ALLOWED_GOOGLE_DOMAINS
    TLS_BACKEND
    TLS_CANARY_URL
    TLS_CANARY_TIMEOUT_SECS
    TLS_CANARY_REQUIRED
    SCHEDULER_REFRESH_JITTER_MIN_SECONDS
    SCHEDULER_REFRESH_JITTER_MAX_SECONDS
    SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS
    SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS
    STARTUP_HEALTH_DELAY_MIN_SECONDS
    STARTUP_HEALTH_DELAY_MAX_SECONDS
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
  if [[ -z "${API_KEY:-}" && -f "$ENV_LOCAL" ]]; then
    local legacy
    legacy="$(grep -E '^[A-Za-z_][A-Za-z0-9_]*_API_KEY=' "$ENV_LOCAL" | head -n 1 | cut -d '=' -f2- | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g")"
    if [[ -n "${legacy:-}" ]]; then
      export API_KEY="$legacy"
    fi
  fi

  if [[ -z "${API_KEY:-}" ]]; then
    echo "Missing API_KEY. Set env var or create .env.local with API_KEY=..." >&2
    exit 1
  fi
}

ensure_request_ids() {
  if [[ -z "${CONSOLE_CORRELATION_ID:-}" ]]; then
    if command -v python3 >/dev/null 2>&1; then
      CONSOLE_CORRELATION_ID="console.sh-$(python3 -c 'import uuid; print(uuid.uuid4())')"
    else
      CONSOLE_CORRELATION_ID="console.sh-$(date +%s)"
    fi
    export CONSOLE_CORRELATION_ID
    CONSOLE_REQUEST_SEQ=0
    export CONSOLE_REQUEST_SEQ
  fi
  CONSOLE_REQUEST_SEQ=$((CONSOLE_REQUEST_SEQ + 1))
  export CONSOLE_REQUEST_SEQ
  CONSOLE_REQUEST_ID="${CONSOLE_CORRELATION_ID}:${CONSOLE_REQUEST_SEQ}"
  export CONSOLE_REQUEST_ID
}

container_exists() {
  docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}$"
}

remove_container_if_exists() {
  if container_exists; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
  fi
}

print_container_not_found_help() {
  echo "Next steps:"
  echo "  1) Start it: ./console.sh start"
  echo "  2) If image is missing, build it:"
  echo "     docker build -t \"$IMAGE\" -f docker/Dockerfile ."
}

start_container() {
  local admin_api="$1"
  ensure_api_key
  mkdir -p "$DATA_DIR"
  remove_container_if_exists

  if [[ -z "${GOOGLE_OAUTH_CLIENT_ID:-}" && -f "$ENV_LOCAL" ]]; then
    local legacy
    legacy="$(grep -E '^[A-Za-z_][A-Za-z0-9_]*_OAUTH_CLIENT_ID=' "$ENV_LOCAL" | head -n 1 | cut -d '=' -f2- | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g")"
    if [[ -n "${legacy:-}" ]]; then
      export GOOGLE_OAUTH_CLIENT_ID="$legacy"
    fi
  fi
  if [[ -z "${GOOGLE_OAUTH_CLIENT_SECRET:-}" && -f "$ENV_LOCAL" ]]; then
    local legacy
    legacy="$(grep -E '^[A-Za-z_][A-Za-z0-9_]*_OAUTH_CLIENT_SECRET=' "$ENV_LOCAL" | head -n 1 | cut -d '=' -f2- | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g")"
    if [[ -n "${legacy:-}" ]]; then
      export GOOGLE_OAUTH_CLIENT_SECRET="$legacy"
    fi
  fi

  local extra_env=()
  if [[ -n "${GOOGLE_OAUTH_CLIENT_ID:-}" ]]; then
    extra_env+=(-e "GOOGLE_OAUTH_CLIENT_ID=${GOOGLE_OAUTH_CLIENT_ID}")
  fi
  if [[ -n "${GOOGLE_OAUTH_CLIENT_SECRET:-}" ]]; then
    extra_env+=(-e "GOOGLE_OAUTH_CLIENT_SECRET=${GOOGLE_OAUTH_CLIENT_SECRET}")
  fi
  local runtime_env=()
  local runtime_env_names=(
    ENCRYPTION_KEY
    WEB_PASSWORD
    PUBLIC_URL
    MAX_BODY_SIZE
    SHUTDOWN_DRAIN_TIMEOUT_SECS
    ADMIN_STOP_SHUTDOWN
    ALLOWED_GOOGLE_DOMAINS
    TLS_BACKEND
    TLS_CANARY_URL
    TLS_CANARY_TIMEOUT_SECS
    TLS_CANARY_REQUIRED
    SCHEDULER_REFRESH_JITTER_MIN_SECONDS
    SCHEDULER_REFRESH_JITTER_MAX_SECONDS
    SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS
    SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS
    STARTUP_HEALTH_DELAY_MIN_SECONDS
    STARTUP_HEALTH_DELAY_MAX_SECONDS
  )
  local var_name var_value
  for var_name in "${runtime_env_names[@]}"; do
    var_value="${!var_name:-}"
    if [[ -n "$var_value" ]]; then
      runtime_env+=(-e "${var_name}=${var_value}")
    fi
  done

  # In Docker, the service must bind 0.0.0.0 to be reachable via port mapping.
  # Host exposure is still restricted by "-p 127.0.0.1:...".
  #
  # Some users set ALLOW_LAN_ACCESS=false in their local env for native runs; if we passed
  # that through to the container, the service would bind 127.0.0.1 inside the container
  # and become unreachable via the published port.
  local allow_lan="true"
  if [[ -n "${ALLOW_LAN_ACCESS:-}" ]]; then
    case "${ALLOW_LAN_ACCESS,,}" in
      0|false|no|off)
        echo "WARN: ALLOW_LAN_ACCESS=${ALLOW_LAN_ACCESS} would break Docker port mapping; forcing ALLOW_LAN_ACCESS=true for docker run." >&2
        ;;
    esac
  fi

  docker run --rm -d --name "$CONTAINER_NAME" \
    -p "127.0.0.1:${PORT}:8045" \
    -e API_KEY="$API_KEY" \
    -e AUTH_MODE=strict \
    -e ENABLE_ADMIN_API="$admin_api" \
    -e ALLOW_LAN_ACCESS="$allow_lan" \
    "${extra_env[@]}" \
    "${runtime_env[@]}" \
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
    print_container_not_found_help
  fi
}

wait_service_ready() {
  ensure_api_key
  for _ in $(seq 1 40); do
    code="$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer ${API_KEY}" \
      "http://127.0.0.1:${PORT}/healthz" || true)"
    [[ "$code" == "200" ]] && return 0
    if [[ "$code" == "401" ]]; then
      echo "Health check failed with 401 (API key mismatch). Run restart or rotate-key." >&2
      return 1
    fi
    sleep 0.5
  done
  return 1
}

show_status() {
  local C='\033[36m' G='\033[90m' W='\033[0m' GR='\033[32m' R='\033[31m' Y='\033[33m'

  echo ""
  echo -e "${C}═══════════════════════════════════════════════════════════════${W}"
  echo -e "${C}                      GEPHYR STATUS                            ${W}"
  echo -e "${C}═══════════════════════════════════════════════════════════════${W}"
  echo ""

  # Docker Container Status
  echo -e "${G}┌─ Docker Container ─────────────────────────────────────────────${W}"
  local row
  row="$(docker ps -a --format "{{.Names}}|{{.Status}}|{{.Ports}}|{{.Image}}" | awk -F '|' -v n="$CONTAINER_NAME" '$1 == n { print }')"
  local is_up="false"
  if [[ -n "$row" ]]; then
    IFS='|' read -r c_name c_status c_ports c_image <<< "$row"
    echo -e "  ${G}Container:  ${W}${c_name}"
    if [[ "$c_status" == Up* ]]; then
      echo -e "  ${G}Status:     ${GR}${c_status}${W}"
      is_up="true"
    else
      echo -e "  ${G}Status:     ${R}${c_status}${W}"
    fi
    echo -e "  ${G}Ports:      ${W}${c_ports}"
    echo -e "  ${G}Image:      ${W}${c_image}"
  else
    echo -e "  ${R}Container not found: ${CONTAINER_NAME}${W}"
    print_container_not_found_help
  fi
  echo ""

  # API Configuration
  echo -e "${G}┌─ API Configuration ────────────────────────────────────────────${W}"
  echo -e "  ${G}Base URL:   ${Y}http://127.0.0.1:${PORT}${W}"
  if [[ -n "${API_KEY:-}" ]]; then
    local klen=${#API_KEY}
    local head=${API_KEY:0:8}
    local tail=${API_KEY:$((klen > 4 ? klen - 4 : 0))}
    echo -e "  ${G}API Key:    ${Y}${head}...${tail}${W}"
  else
    echo -e "  ${G}API Key:    ${R}(not set)${W}"
  fi
  echo ""

  # Health Check + Linked Accounts (if container is running)
  if [[ "$is_up" == "true" ]]; then
    echo -e "${G}┌─ Service Health ───────────────────────────────────────────────${W}"
    local health_json="" health_ok="false"
    if [[ -n "${API_KEY:-}" ]]; then
      health_json="$(curl -sS -H "Authorization: Bearer ${API_KEY}" \
        "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || true)"
      if [[ -n "$health_json" ]] && echo "$health_json" | grep -q '"status"'; then
        health_ok="true"
        echo -e "  ${G}Health:     ${GR}OK${W}"
        local version
        version="$(printf '%s' "$health_json" | sed -nE 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')"
        if [[ -n "$version" ]]; then
          echo -e "  ${G}Version:    ${W}${version}"
        fi
      else
        echo -e "  ${G}Health:     ${R}FAILED (API key mismatch or service error)${W}"
      fi
    else
      echo -e "  ${G}Health:     ${R}(API key not set)${W}"
    fi
    echo ""

    # Linked Accounts
    echo -e "${G}┌─ Linked Accounts ──────────────────────────────────────────────${W}"
    local accounts_fetched="false"
    local acct_http_code=""
    if [[ -n "${API_KEY:-}" ]]; then
      local acct_raw
      acct_raw="$(curl -sS -w $'\n%{http_code}' -H "Authorization: Bearer ${API_KEY}" \
        "http://127.0.0.1:${PORT}/api/accounts" 2>/dev/null || true)"
      acct_http_code="$(printf '%s' "$acct_raw" | tail -n 1)"
      local acct_json
      acct_json="$(printf '%s' "$acct_raw" | sed '$d')"
      if [[ -n "$acct_json" ]] && echo "$acct_json" | grep -q '"accounts"'; then
        accounts_fetched="true"
        if command -v python3 >/dev/null 2>&1; then
          python3 - <<'PY' "$acct_json"
import json, sys, time, re
from datetime import datetime, timezone

raw = sys.argv[1] if len(sys.argv) > 1 else "{}"
try:
    data = json.loads(raw or "{}")
except Exception:
    print("  \033[90m(parse error)\033[0m")
    raise SystemExit(0)

accounts = data.get("accounts", [])
current = data.get("current_account_id", "")
if not isinstance(accounts, list) or len(accounts) == 0:
    print("  \033[90m(none)\033[0m")
    raise SystemExit(0)

def time_ago(ts):
    if not ts or ts <= 0:
        return "(unknown)"
    elapsed = time.time() - ts
    if elapsed < 60:
        return "just now"
    elif elapsed < 3600:
        return f"{int(elapsed // 60)}m ago"
    elif elapsed < 86400:
        return f"{int(elapsed // 3600)}h ago"
    else:
        return f"{int(elapsed // 86400)}d ago"

def bar(pct, width=20):
    pct = max(0, min(100, pct))
    filled = int(pct / 100.0 * width)
    empty = width - filled
    if pct >= 70:
        color = "\033[32m"
    elif pct >= 30:
        color = "\033[33m"
    else:
        color = "\033[31m"
    return f"{color}{'█' * filled}{'░' * empty}\033[0m"

# First pass: compute column widths
max_email = max((len(a.get("email", "")) for a in accounts), default=5)
max_name = max((len(a.get("name") or "-") for a in accounts), default=1)
max_model = 10
for a in accounts:
    q = a.get("quota")
    if q:
        for m in q.get("models", []):
            sn = len(re.sub(r'^models/', '', m.get("name", "")))
            if sn > max_model:
                max_model = sn
name_pad = max_name + 2  # +2 for parens
model_pad = max_model + 2

model_order = ['claude-opus', 'claude-sonnet', 'gemini-3-pro-high', 'gemini-3-pro-low', 'gemini-3-flash']
def model_sort_key(m):
    n = re.sub(r'^models/', '', m.get("name", ""))
    for i, prefix in enumerate(model_order):
        if prefix in n:
            return (i, n)
    return (999, n)

# Second pass: render
for a in accounts:
    marker = "►" if a.get("id") == current else " "
    email = a.get("email", "?").ljust(max_email)
    name = a.get("name") or "-"
    name_str = f"({name})".ljust(name_pad)
    if a.get("disabled"):
        status, color = "disabled", "\033[31m"
    elif a.get("proxy_disabled"):
        status, color = "proxy-off", "\033[33m"
    else:
        status, color = "active", "\033[32m"
    print(f"  \033[36m{marker} \033[0m{email}  \033[90m{name_str}\033[0m  {color}[{status}]\033[0m")

    token_expiry = a.get("token_expiry", 0)
    if token_expiry and token_expiry > 0:
        from datetime import timezone
        expiry_dt = datetime.fromtimestamp(token_expiry, tz=timezone.utc)
        local_dt = expiry_dt.astimezone()
        remaining_sec = token_expiry - time.time()
        expiry_str = local_dt.strftime("%Y-%m-%d %H:%M:%S")
        if remaining_sec <= 0:
            expiry_color, label = "\033[31m", "EXPIRED"
        elif remaining_sec <= 1800:
            expiry_color, label = "\033[33m", f"expires in {int(remaining_sec // 60)}m"
        else:
            total_min = int(remaining_sec // 60)
            if total_min >= 60:
                label = f"expires in {total_min // 60}h {total_min % 60}m"
            else:
                label = f"expires in {total_min}m"
            expiry_color = "\033[32m"
        print(f"      \033[90mToken: \033[0m{expiry_str} {expiry_color}({label})\033[0m")

    q = a.get("quota")
    if q:
        tier = q.get("subscription_tier") or "unknown"
        ago = time_ago(q.get("last_updated", 0))
        if q.get("is_forbidden"):
            print(f"      \033[90mTier: \033[0m{tier}  \033[31m[FORBIDDEN]\033[0m")
        else:
            print(f"      \033[90mTier: \033[0m{tier}\033[90m | Updated: {ago}\033[0m")
            sorted_models = sorted(q.get("models", []), key=model_sort_key)
            for m in sorted_models:
                pct = m.get("percentage", 0)
                short = re.sub(r'^models/', '', m.get("name", "?"))
                padded = short.ljust(model_pad)
                pct_str = f"{pct}%".rjust(4)
                reset_hint = ""
                if pct <= 50 and m.get("reset_time"):
                    try:
                        rt = datetime.fromisoformat(m["reset_time"].replace("Z", "+00:00"))
                        reset_hint = f"  \033[90m⟳ {rt.astimezone().strftime('%H:%M')}\033[0m"
                    except Exception:
                        pass
                print(f"      \033[90m{padded} \033[0m{bar(pct)}  \033[0m{pct_str}{reset_hint}")
    else:
        print(f"      \033[90m(quota data not fetched yet, try again in a few moments...)\033[0m")
PY
        else
          # Fallback: no python3, just show raw count
          local count
          count="$(printf '%s' "$acct_json" | grep -o '"email"' | wc -l | tr -d ' ')"
          echo -e "  ${W}${count} account(s) linked${W}"
        fi
      fi
    fi
    if [[ "$accounts_fetched" == "false" ]]; then
      if [[ "$health_ok" == "true" ]]; then
        local loaded
        loaded="$(printf '%s' "$health_json" | sed -nE 's/.*"accounts_loaded"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p')"
        if [[ -n "$loaded" ]]; then
          echo -e "  ${W}${loaded} account(s) loaded${W}"
          echo -e "  ${G}(start with --admin-api to see full account details)${W}"
        elif [[ "$acct_http_code" == "404" ]]; then
          echo -e "  ${G}(admin API not enabled — start with --admin-api to view accounts)${W}"
        elif [[ "$acct_http_code" == "401" ]]; then
          echo -e "  ${R}(admin API returned 401 — API key mismatch; run restart or rotate-key)${W}"
        elif [[ -n "$acct_http_code" ]]; then
          echo -e "  ${Y}(could not query accounts — HTTP ${acct_http_code})${W}"
        else
          echo -e "  ${G}(admin API not reachable)${W}"
        fi
      else
        echo -e "  ${R}(health check failed — cannot determine account status)${W}"
      fi
    fi
    echo ""
  fi

  echo -e "${C}═══════════════════════════════════════════════════════════════${W}"
  echo ""
}


show_logs() {
  if ! container_exists; then
    echo "Container not found: $CONTAINER_NAME" >&2
    print_container_not_found_help >&2
    exit 1
  fi
  docker logs --tail "$LOG_LINES" "$CONTAINER_NAME"
}

show_health() {
  ensure_api_key
  local result
  result="$(curl -sS -H "Authorization: Bearer ${API_KEY}" "http://127.0.0.1:${PORT}/healthz")"
  if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo "$result"
  else
    echo "$result" | python3 -m json.tool 2>/dev/null || echo "$result"
  fi
}

show_account_health_check() {
  ensure_api_key
  echo ""
  echo -e "  \033[36mRunning account health check...\033[0m"
  echo ""
  local payload
  payload="$(curl -sS -X POST -H "Authorization: Bearer ${API_KEY}" \
    "http://127.0.0.1:${PORT}/api/accounts/health-check" 2>/dev/null || true)"

  if [[ -z "$payload" ]]; then
    echo -e "  \033[31mHealth check failed: no response\033[0m"
    return 1
  fi

  if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo "$payload"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'HEALTHEOF' "$payload"
import sys, json

try:
    data = json.loads(sys.argv[1])
except Exception:
    print("  \033[31mFailed to parse response\033[0m")
    sys.exit(1)

GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
RED    = "\033[31m"
RESET  = "\033[0m"

total   = data.get("total", 0)
skipped = data.get("skipped", 0)
refreshed = data.get("refreshed", 0)
disabled  = data.get("disabled", 0)
errors    = data.get("network_errors", 0)

summary = f"  Total: {total} | Skipped: {skipped} | Refreshed: {refreshed} | Disabled: {disabled} | Errors: {errors}"
if disabled > 0 or errors > 0:
    print(f"{YELLOW}{summary}{RESET}")
else:
    print(f"{GREEN}{summary}{RESET}")
print()

STATUS_COLORS = {
    "ok": GREEN,
    "refreshed": CYAN,
    "disabled": RED,
    "error": YELLOW,
}

for acct in data.get("accounts", []):
    s = acct.get("status", "unknown")
    color = STATUS_COLORS.get(s, "")
    tag = f"[{s.upper()}]".ljust(12)
    detail = f" -- {acct['detail']}" if acct.get("detail") else ""
    print(f"    {color}{tag} {acct.get('email','?')}{detail}{RESET}")
print()
HEALTHEOF
  else
    echo "$payload" | python3 -m json.tool 2>/dev/null || echo "$payload"
  fi
}

show_tls_canary() {
  ensure_api_key
  local run="false"
  for arg in "$@"; do
    if [[ "$arg" == "--run" ]]; then run="true"; fi
  done

  local method="GET"
  local endpoint="/api/proxy/tls-canary"
  if [[ "$run" == "true" ]]; then
    method="POST"
    endpoint="/api/proxy/tls-canary/run"
    echo ""
    echo -e "  \033[36mRunning TLS startup canary probe...\033[0m"
    echo ""
  fi

  local payload
  payload="$(curl -sS -X "$method" -H "Authorization: Bearer ${API_KEY}" \
    "http://127.0.0.1:${PORT}${endpoint}" 2>/dev/null || true)"

  if [[ -z "$payload" ]]; then
    echo -e "  \033[31mCanary check failed: no response\033[0m"
    return 1
  fi

  if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo "$payload"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'CANARYEOF' "$payload" "$run"
import sys, json, datetime

try:
    data = json.loads(sys.argv[1])
    is_run = sys.argv[2] == "true"
except Exception:
    print("  \033[31mFailed to parse response\033[0m")
    sys.exit(1)

snapshot = data.get("tls_canary") if is_run else data

GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
RED    = "\033[31m"
GRAY   = "\033[90m"
RESET  = "\033[0m"

print(f"\n  {CYAN}TLS Canary Snapshot:{RESET}\n")

conf = snapshot.get("configured", False)
req  = snapshot.get("required", False)

print(f"    Configured: {GREEN if conf else GRAY}{conf}{RESET}")
print(f"    Required:   {YELLOW if req else GRAY}{req}{RESET}")
print(f"    URL:        {snapshot.get('url', 'None')}")
print(f"    Timeout:    {snapshot.get('timeout_seconds', 0)}s")

ts = snapshot.get("last_checked_unix")
if ts:
    dt = datetime.datetime.fromtimestamp(ts)
    print(f"    Last Check: {dt.strftime('%Y-%m-%d %H:%M:%S')}")

status = snapshot.get("last_http_status")
if status:
    color = GREEN if status < 400 else RED
    print(f"    HTTP Status: {color}{status}{RESET}")

err = snapshot.get("last_error")
if err:
    print(f"    Last Error: {RED}{err}{RESET}")
elif conf:
    print(f"    Status:     {GREEN}OK{RESET}")
print()
CANARYEOF
  else
    echo "$payload" | python3 -m json.tool 2>/dev/null || echo "$payload"
  fi
}

show_accounts() {
  ensure_api_key
  local payload
  payload="$(curl -sS -H "Authorization: Bearer ${API_KEY}" "http://127.0.0.1:${PORT}/api/accounts")"

  if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo "$payload"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$payload"
import json,sys
raw = sys.argv[1] if len(sys.argv) > 1 else "{}"
try:
    data = json.loads(raw or "{}")
except Exception:
    print(raw)
    raise SystemExit(0)

accounts = data.get("accounts", [])
current = data.get("current_account_id")

if not isinstance(accounts, list) or len(accounts) == 0:
    print("No linked accounts.")
    if current:
        print(f"current_account_id: {current}")
    raise SystemExit(0)

print("id\temail\tname\tis_current\tdisabled\tproxy_disabled\tlast_used")
for a in accounts:
    print(
        f"{a.get('id','')}\t{a.get('email','')}\t{a.get('name','') or ''}\t"
        f"{a.get('is_current', False)}\t{a.get('disabled', False)}\t"
        f"{a.get('proxy_disabled', False)}\t{a.get('last_used','')}"
    )
if current:
    print(f"\ncurrent_account_id: {current}")
PY
  else
    echo "$payload"
  fi
}

wait_oauth_account_link() {
  local timeout_sec="${1:-180}"
  local poll_sec="${2:-2}"
  local elapsed=0

  ensure_api_key

  echo "Waiting for OAuth callback/account link (timeout: ${timeout_sec}s)..."
  echo "Complete login in your browser; script continues automatically after account is linked."

  while (( elapsed < timeout_sec )); do
    local payload
    payload="$(curl -sS -H "Authorization: Bearer ${API_KEY}" "http://127.0.0.1:${PORT}/api/accounts" || true)"
    local count="0"

    if command -v python3 >/dev/null 2>&1; then
      count="$(python3 - <<'PY' "$payload"
import json,sys
raw = sys.argv[1] if len(sys.argv) > 1 else "{}"
try:
    data = json.loads(raw or "{}")
except Exception:
    print(0)
    raise SystemExit(0)
arr = data.get("accounts", [])
print(len(arr) if isinstance(arr, list) else 0)
PY
)"
    else
      count="$(printf '%s' "$payload" | grep -o '"id"' | wc -l | tr -d ' ')"
    fi

    if [[ "${count}" =~ ^[0-9]+$ ]] && (( count > 0 )); then
      echo "OAuth account linked (${count} account(s) found)."
      return 0
    fi

    sleep "$poll_sec"
    elapsed=$((elapsed + poll_sec))
  done

  echo "Warning: timed out waiting for OAuth account linkage. Run ./console.sh accounts after completing OAuth."
  return 1
}

remove_accounts() {
  ensure_api_key
  ensure_request_ids

  local accounts_json http_code
  accounts_json="$(curl -sS -w $'\n%{http_code}' \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "x-correlation-id: ${CONSOLE_CORRELATION_ID}" \
    -H "x-request-id: ${CONSOLE_REQUEST_ID}" \
    "http://127.0.0.1:${PORT}/api/accounts")"
  http_code="$(printf '%s' "$accounts_json" | tail -n 1)"
  accounts_json="$(printf '%s' "$accounts_json" | sed '$d')"

  if [[ "$http_code" == "404" ]]; then
    echo "Admin API not enabled. Restarting container with admin API..." >&2
    stop_container
    start_container "true"
    if ! wait_service_ready; then
      echo "Service did not become ready after restart." >&2
      exit 1
    fi
    # Retry after restart
    accounts_json="$(curl -sS -w $'\n%{http_code}' \
      -H "Authorization: Bearer ${API_KEY}" \
      -H "x-correlation-id: ${CONSOLE_CORRELATION_ID}" \
      -H "x-request-id: ${CONSOLE_REQUEST_ID}" \
      "http://127.0.0.1:${PORT}/api/accounts")"
    http_code="$(printf '%s' "$accounts_json" | tail -n 1)"
    accounts_json="$(printf '%s' "$accounts_json" | sed '$d')"
  fi

  if [[ "$http_code" == "401" ]]; then
    echo "Accounts delete-all failed with 401. API key mismatch. Run restart or rotate-key." >&2
    exit 1
  elif [[ "$http_code" -ge 400 ]]; then
    echo "Failed to query accounts for accounts-delete-all. HTTP $http_code" >&2
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
      -H "Authorization: Bearer ${API_KEY}" \
      -H "x-correlation-id: ${CONSOLE_CORRELATION_ID}" \
      -H "x-request-id: ${CONSOLE_REQUEST_ID}" \
      "http://127.0.0.1:${PORT}/api/accounts/${id}" | grep -Eq '^2[0-9][0-9]$'; then
      echo "Removed account: $id"
      removed=$((removed + 1))
    else
      echo "Failed to remove account: $id" >&2
    fi
  done

  echo "Accounts delete-all completed. Removed ${removed} account(s)."
}

logout_all_accounts() {
  ensure_api_key
  ensure_request_ids

  local body payload http_code
  body='{"revokeRemote":true,"deleteLocal":false}'
  payload="$(curl -sS -w $'\n%{http_code}' \
    -X POST \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "x-correlation-id: ${CONSOLE_CORRELATION_ID}" \
    -H "x-request-id: ${CONSOLE_REQUEST_ID}" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "http://127.0.0.1:${PORT}/api/accounts/logout-all")"
  http_code="$(printf '%s' "$payload" | tail -n 1)"
  payload="$(printf '%s' "$payload" | sed '$d')"

  if [[ "$http_code" == "404" ]]; then
    echo "Admin API not enabled. Restarting container with admin API..." >&2
    stop_container
    start_container "true"
    if ! wait_service_ready; then
      echo "Service did not become ready after restart." >&2
      exit 1
    fi
    payload="$(curl -sS -w $'\n%{http_code}' \
      -X POST \
      -H "Authorization: Bearer ${API_KEY}" \
      -H "x-correlation-id: ${CONSOLE_CORRELATION_ID}" \
      -H "x-request-id: ${CONSOLE_REQUEST_ID}" \
      -H "Content-Type: application/json" \
      -d "$body" \
      "http://127.0.0.1:${PORT}/api/accounts/logout-all")"
    http_code="$(printf '%s' "$payload" | tail -n 1)"
    payload="$(printf '%s' "$payload" | sed '$d')"
  fi

  if [[ "$http_code" == "401" ]]; then
    echo "Logout-all failed with 401. API key mismatch. Run restart or rotate-key." >&2
    exit 1
  elif [[ "$http_code" -ge 400 ]]; then
    echo "Logout-all failed. HTTP $http_code" >&2
    exit 1
  fi

  echo "$payload"
}

logout_and_stop() {
  logout_all_accounts
  stop_container
}

remove_accounts_and_stop() {
  remove_accounts
  stop_container
}

accounts_signout_all() { logout_all_accounts; }
accounts_signout_all_and_stop() { logout_and_stop; }
accounts_delete_all() { remove_accounts; }
accounts_delete_all_and_stop() { remove_accounts_and_stop; }

api_test() {
  ensure_api_key
  local safe_prompt="${PROMPT//\"/\\\"}"
  local body
  body="$(printf '{"model":"%s","messages":[{"role":"user","content":"%s"}]}' "$MODEL" "$safe_prompt")"
  curl -sS \
    -H "Authorization: Bearer ${API_KEY}" \
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
  oauth_json="$(curl -sS -H "Authorization: Bearer ${API_KEY}" "http://127.0.0.1:${PORT}/api/auth/url")"
  oauth_url="$(printf '%s' "$oauth_json" | sed -nE 's/.*"url"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')"
  oauth_url="${oauth_url//\\\//\/}"

  if [[ -z "$oauth_url" ]]; then
    echo "Failed to extract OAuth URL from response: $oauth_json" >&2
    exit 1
  fi

  echo "OAuth URL:"
  echo "$oauth_url"
  open_url "$oauth_url"
  wait_oauth_account_link 180 2 || true
}

generate_key() {
  local raw
  raw="$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | head -c 32)"
  echo "gph_${raw}"
}

rotate_key() {
  local new_key
  new_key="$(generate_key)"
  export API_KEY="$new_key"
  save_env_value "API_KEY" "$new_key"
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

docker_repair() {
  local prune_flag="-f"
  if [[ "$AGGRESSIVE_REPAIR" == "true" ]]; then
    prune_flag="-af"
    echo "Mode: aggressive (will remove all builder cache)."
  else
    echo "Mode: safe (prunes unused builder cache)."
  fi

  echo "Running Docker builder repair..."
  if ! docker buildx inspect --bootstrap >/dev/null 2>&1; then
    echo "Failed to bootstrap Docker buildx. Restart Docker and retry." >&2
    exit 1
  fi

  docker buildx prune "$prune_flag"
  docker builder prune "$prune_flag"

  echo
  echo "Builder repair completed."
  echo "Next step: retry your image build."
  echo "  docker build -t \"$IMAGE\" -f docker/Dockerfile ."
}

rebuild() {
  local dockerfile="$SCRIPT_DIR/docker/Dockerfile"
  if [[ ! -f "$dockerfile" ]]; then
    echo "Dockerfile not found at: $dockerfile" >&2
    exit 1
  fi

  if [[ "$QUIET" != "true" ]]; then
    echo "Building Docker image: $IMAGE"
    if [[ "$NO_CACHE" == "true" ]]; then
      echo "Mode: no-cache (clean build)"
    fi
  fi

  local build_args=("build" "-t" "$IMAGE" "-f" "docker/Dockerfile" ".")
  if [[ "$NO_CACHE" == "true" ]]; then
    build_args=("build" "--no-cache" "-t" "$IMAGE" "-f" "docker/Dockerfile" ".")
  fi

  docker "${build_args[@]}"

  if [[ "$QUIET" != "true" ]]; then
    echo
    echo "Build completed: $IMAGE"
  fi
}

update_gephyr() {
  local repo_root="$SCRIPT_DIR"

  # 1. Pre-flight: warn about uncommitted changes
  local git_status
  git_status="$(git -C "$repo_root" status --porcelain 2>/dev/null || true)"
  if [[ -n "$git_status" ]]; then
    echo ""
    echo -e "\033[33m  WARNING: You have uncommitted changes:\033[0m"
    while IFS= read -r line; do
      echo -e "\033[33m    $line\033[0m"
    done <<< "$git_status"
    echo ""
    read -rp "  Continue with update? (y/N) " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" && "$confirm" != "yes" ]]; then
      echo "Update cancelled."
      return 0
    fi
  fi

  # 2. Pre-flight: check if container is running and healthy
  local was_running="false"
  local was_admin_enabled="false"
  if container_exists; then
    local row
    row="$(docker ps --format '{{.Names}}|{{.Status}}' | awk -F '|' -v n="$CONTAINER_NAME" '$1 == n { print }')"
    if [[ -n "$row" && "$row" == *"Up"* ]]; then
      was_running="true"
      echo -e "\033[36mContainer is running. Checking health before update...\033[0m"
      if [[ -n "${API_KEY:-}" ]]; then
        local hcode
        hcode="$(curl -s -o /dev/null -w "%{http_code}" \
          -H "Authorization: Bearer ${API_KEY}" \
          "http://127.0.0.1:${PORT}/healthz" || true)"
        if [[ "$hcode" == "200" ]]; then
          echo -e "  Health: \033[32mOK\033[0m"
        else
          echo -e "  Health: \033[33mFAILED — proceeding anyway\033[0m"
        fi
        # Check if admin API is enabled
        local acode
        acode="$(curl -s -o /dev/null -w "%{http_code}" \
          -H "Authorization: Bearer ${API_KEY}" \
          "http://127.0.0.1:${PORT}/api/accounts" || true)"
        if [[ "$acode" == "200" ]]; then
          was_admin_enabled="true"
        fi
      fi
    fi
  fi

  # 3. Git pull
  echo ""
  echo -e "\033[36mPulling latest changes...\033[0m"
  local pull_output
  pull_output="$(git -C "$repo_root" pull 2>&1)" || {
    echo -e "\033[31m  git pull failed:\033[0m"
    echo -e "\033[31m  $pull_output\033[0m"
    echo "Resolve conflicts and retry." >&2
    exit 1
  }
  echo "  $pull_output"

  # 4. Rebuild
  echo ""
  echo -e "\033[36mRebuilding Docker image...\033[0m"
  rebuild

  # 5. Restart if was running
  if [[ "$was_running" == "true" ]]; then
    echo ""
    echo -e "\033[36mRestarting container...\033[0m"
    local admin_flag="$ENABLE_ADMIN_API"
    if [[ "$was_admin_enabled" == "true" ]]; then
      admin_flag="true"
    fi
    stop_container
    start_container "$admin_flag"
    if wait_service_ready; then
      echo -e "  \033[32mService is healthy.\033[0m"
      show_status
    else
      echo "Service did not become ready after update." >&2
      exit 1
    fi
  else
    echo ""
    echo -e "\033[32mUpdate complete. Container was not running; start it with: ./console.sh start\033[0m"
  fi
}

show_version() {
  local cargo_toml="$SCRIPT_DIR/Cargo.toml"
  if [[ ! -f "$cargo_toml" ]]; then
    echo "Cargo.toml not found at: $cargo_toml" >&2
    exit 1
  fi

  local version
  version="$(grep -E '^version\s*=' "$cargo_toml" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"

  if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo "{\"version\": \"$version\", \"image\": \"$IMAGE\"}"
  else
    echo "gephyr $version"
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
    --aggressive) AGGRESSIVE_REPAIR="true"; shift ;;
    --json) JSON_OUTPUT="true"; shift ;;
    --quiet) QUIET="true"; shift ;;
    --no-cache) NO_CACHE="true"; shift ;;
    -h|--help|-?|\?|/help) COMMAND="help"; shift ;;
    *)
      echo "Unknown argument: $1" >&2
      print_help
      exit 1
      ;;
  esac
done

load_env_local

# Check if Docker daemon is running
check_docker_available() {
  if ! docker info >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

assert_docker_running() {
  if ! check_docker_available; then
    echo ""
    echo -e "\033[31m╔══════════════════════════════════════════════════════════════════╗\033[0m"
    echo -e "\033[31m║                     DOCKER IS NOT RUNNING                        ║\033[0m"
    echo -e "\033[31m╠══════════════════════════════════════════════════════════════════╣\033[0m"
    echo -e "\033[33m║  The Docker daemon is not accessible.                            ║\033[0m"
    echo -e "\033[33m║                                                                  ║\033[0m"
    echo -e "\033[33m║  Please ensure:                                                  ║\033[0m"
    echo -e "\033[33m║    1. Docker is installed                                        ║\033[0m"
    echo -e "\033[33m║    2. Docker daemon is running (systemctl start docker)          ║\033[0m"
    echo -e "\033[33m║    3. Your user has permission to access Docker                  ║\033[0m"
    echo -e "\033[33m║                                                                  ║\033[0m"
    echo -e "\033[33m║  On Linux:   sudo systemctl start docker                         ║\033[0m"
    echo -e "\033[33m║  On macOS:   Open Docker Desktop from /Applications              ║\033[0m"
    echo -e "\033[31m╚══════════════════════════════════════════════════════════════════╝\033[0m"
    echo ""
    echo "Docker daemon is not running. Please start Docker and try again." >&2
    exit 1
  fi
}

# Commands that require Docker
DOCKER_COMMANDS="start stop restart status logs health login oauth auth accounts api-test rotate-key docker-repair rebuild update accounts-signout-all accounts-signout-all-and-stop accounts-delete-all accounts-delete-all-and-stop"

# Check Docker for commands that need it
if echo "$DOCKER_COMMANDS" | grep -qw "$COMMAND"; then
  assert_docker_running
fi

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
  check) show_account_health_check ;;
  canary) show_tls_canary "$@" ;;
  login|oauth|auth) oauth_flow ;;
  accounts) show_accounts ;;
  api-test) api_test ;;
  rotate-key) rotate_key ;;
  docker-repair) docker_repair ;;
  rebuild) rebuild ;;
  update) update_gephyr ;;
  version) show_version ;;
  accounts-signout-all) accounts_signout_all ;;
  accounts-signout-all-and-stop) accounts_signout_all_and_stop ;;
  accounts-delete-all) accounts_delete_all ;;
  accounts-delete-all-and-stop) accounts_delete_all_and_stop ;;
  *)
    echo "Unknown command: $COMMAND" >&2
    print_help
    exit 1
    ;;
esac
