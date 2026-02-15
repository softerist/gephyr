#!/usr/bin/env bash
set -euo pipefail

check_docker_available() {
  docker info >/dev/null 2>&1
}

print_docker_unavailable() {
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
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLE_SCRIPT="$SCRIPT_DIR/console.sh"
ALLOW_GUARD_SCRIPT="$SCRIPT_DIR/scripts/check-allow-attributes.sh"

SKIP_BUILD=false
USE_BUILD_CACHE=false
SKIP_LOGIN=false
NO_BROWSER=false
RUN_API_TEST=false
DISABLE_ADMIN_AFTER=false
IMAGE="gephyr:latest"
MODEL="gpt-5.3-codex"
PROMPT="hello from gephyr"
PORT="${PORT:-8045}"

print_help() {
  cat <<'EOF'
Usage:
  ./test-clean.sh [options]

Options:
  --skip-build           Skip docker build
  --cache-build          Build with Docker cache (default is --no-cache)
  --skip-login           Skip OAuth login step
  --no-browser           Do not auto-open browser during login
  --run-api-test         Run api-test after accounts check
  --disable-admin-after  Restart with admin API disabled at the end
  --image <image>        Docker image tag (default gephyr:latest)
  --port <port>          Host port (default 8045)
  --model <name>         Model used by --run-api-test
  --prompt <text>        Prompt used by --run-api-test
  -h, --help             Show help

Examples:
  ./test-clean.sh
  ./test-clean.sh --port 8045
  ./test-clean.sh --run-api-test --model gpt-5.2-chat-latest
  ./test-clean.sh --skip-login --cache-build
EOF
}

step() {
  local name="$1"
  shift
  echo "==> $name"
  "$@"
  echo
}

build_with_guidance() {
  if "$@"; then
    return 0
  fi

  echo ""
  echo "Docker build failed."
  echo "Try repairing builder cache, then retry:"
  echo "  ./console.sh docker-repair"
  echo "If still failing, use aggressive mode:"
  echo "  ./console.sh docker-repair --aggressive"
  exit 1
}

wait_oauth_account_link() {
  local timeout_sec="${1:-180}"
  local poll_sec="${2:-2}"
  local elapsed=0
  local next_progress=10
  local api_key="${API_KEY:-}"
  local status_endpoint_supported=true
  local last_known_phase=""

  if [[ -z "$api_key" && -f "$SCRIPT_DIR/.env.local" ]]; then
    api_key="$(grep -E '^API_KEY=' "$SCRIPT_DIR/.env.local" | tail -n 1 | cut -d '=' -f2- | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g")"
  fi

  if [[ -z "$api_key" ]]; then
    echo "WARNING: [W-OAUTH-MISSING-API-KEY] Skipping OAuth wait: API_KEY is missing (env and .env.local)." >&2
    return 1
  fi

  echo "Waiting for OAuth callback/account link (timeout: ${timeout_sec}s)..."
  echo "Complete login in your browser, then this script will continue automatically."

  while (( elapsed < timeout_sec )); do
    # --- Phase 1: try /api/auth/status (preferred) ---
    if [[ "$status_endpoint_supported" == "true" ]]; then
      local status_resp http_code
      status_resp="$(curl -sS -w '\n%{http_code}' -H "Authorization: Bearer ${api_key}" \
        "http://127.0.0.1:${PORT}/api/auth/status" 2>/dev/null || echo -e '\n000')"
      http_code="$(printf '%s' "$status_resp" | tail -n 1)"
      local status_body
      status_body="$(printf '%s' "$status_resp" | sed '$d')"

      if [[ "$http_code" == "401" ]]; then
        echo "WARNING: [E-OAUTH-STATUS-401] /api/auth/status returned 401 Unauthorized. Verify API_KEY in shell/.env.local and restart container." >&2
        return 1
      elif [[ "$http_code" == "404" ]]; then
        echo "WARNING: [W-OAUTH-STATUS-UNSUPPORTED] OAuth status endpoint not available on this runtime; falling back to legacy /api/accounts polling." >&2
        status_endpoint_supported=false
      elif [[ "$http_code" == "200" ]]; then
        local phase=""
        if command -v python3 >/dev/null 2>&1; then
          phase="$(python3 -c "import json,sys; d=json.loads(sys.argv[1] or '{}'); print(d.get('phase','').lower())" "$status_body" 2>/dev/null || true)"
        else
          phase="$(printf '%s' "$status_body" | sed -nE 's/.*"phase"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | tr '[:upper:]' '[:lower:]')"
        fi

        [[ -n "$phase" ]] && last_known_phase="$phase"

        if [[ "$phase" == "linked" ]]; then
          local acct_email=""
          if command -v python3 >/dev/null 2>&1; then
            acct_email="$(python3 -c "import json,sys; d=json.loads(sys.argv[1] or '{}'); print(d.get('account_email',''))" "$status_body" 2>/dev/null || true)"
          fi
          if [[ -n "$acct_email" ]]; then
            echo "OAuth account linked ($acct_email)."
          else
            echo "OAuth account linked."
          fi
          return 0
        elif [[ "$phase" == "failed" ]]; then
          local detail=""
          if command -v python3 >/dev/null 2>&1; then
            detail="$(python3 -c "import json,sys; d=json.loads(sys.argv[1] or '{}'); print(d.get('detail','unknown_error'))" "$status_body" 2>/dev/null || true)"
          fi
          echo "WARNING: OAuth wait aborted [E-OAUTH-FLOW-FAILED]: ${detail:-unknown_error}" >&2
          return 1
        elif [[ "$phase" == "cancelled" ]]; then
          local detail=""
          if command -v python3 >/dev/null 2>&1; then
            detail="$(python3 -c "import json,sys; d=json.loads(sys.argv[1] or '{}'); print(d.get('detail','oauth_flow_cancelled'))" "$status_body" 2>/dev/null || true)"
          fi
          echo "WARNING: OAuth wait aborted [E-OAUTH-FLOW-CANCELLED]: ${detail:-oauth_flow_cancelled}" >&2
          return 1
        fi
      fi
    fi

    # --- Phase 2: fallback to /api/accounts polling ---
    if [[ "$status_endpoint_supported" != "true" ]]; then
      local payload acct_http
      payload="$(curl -sS -w '\n%{http_code}' -H "Authorization: Bearer ${api_key}" \
        "http://127.0.0.1:${PORT}/api/accounts" 2>/dev/null || echo -e '\n000')"
      acct_http="$(printf '%s' "$payload" | tail -n 1)"
      local acct_body
      acct_body="$(printf '%s' "$payload" | sed '$d')"

      if [[ "$acct_http" == "401" ]]; then
        echo "WARNING: [E-OAUTH-ACCOUNTS-401] /api/accounts returned 401 Unauthorized. Verify API_KEY in shell/.env.local and restart container." >&2
        return 1
      elif [[ "$acct_http" == "404" ]]; then
        echo "WARNING: [E-OAUTH-ACCOUNTS-404] /api/accounts returned 404. Ensure admin API is enabled (ENABLE_ADMIN_API=true)." >&2
        return 1
      fi

      local count="0"
      if command -v python3 >/dev/null 2>&1; then
        count="$(python3 - <<'PY' "$acct_body"
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
        count="$(printf '%s' "$acct_body" | grep -o '"id"' | wc -l | tr -d ' ')"
      fi

      if [[ "${count}" =~ ^[0-9]+$ ]] && (( count > 0 )); then
        echo "OAuth account linked (${count} account(s) found)."
        return 0
      fi
    fi

    sleep "$poll_sec"
    elapsed=$((elapsed + poll_sec))

    if (( elapsed >= next_progress )); then
      if [[ -n "$last_known_phase" ]]; then
        echo "Still waiting for OAuth linkage... ${elapsed}s elapsed (phase: ${last_known_phase})."
      else
        echo "Still waiting for OAuth linkage... ${elapsed}s elapsed."
      fi

      # Scan docker logs for known error patterns
      local recent_logs
      recent_logs="$(docker logs --tail 160 gephyr 2>&1 || true)"
      if printf '%s' "$recent_logs" | grep -qE "encryption_key_unavailable|Failed to save account in background OAuth"; then
        echo "WARNING: [E-CRYPTO-KEY-UNAVAILABLE] OAuth callback succeeded but account persistence failed (missing/invalid ENCRYPTION_KEY). Remediation: set ENCRYPTION_KEY in .env.local, restart container, then rerun login." >&2
        return 1
      fi
      if printf '%s' "$recent_logs" | grep -q "OAuth callback state mismatch"; then
        echo "WARNING: [E-OAUTH-STATE-MISMATCH] OAuth callback state mismatch detected. Restart login flow and complete only the latest opened OAuth URL." >&2
        return 1
      fi
      if printf '%s' "$recent_logs" | grep -q "Background OAuth exchange failed:"; then
        echo "WARNING: [E-OAUTH-TOKEN-EXCHANGE] OAuth wait aborted: token exchange failed. Check network/proxy settings and Google OAuth client credentials." >&2
        return 1
      fi
      if printf '%s' "$recent_logs" | grep -q "Background OAuth error: Google did not return a refresh_token"; then
        echo "WARNING: [E-OAUTH-REFRESH-MISSING] OAuth wait aborted: Google returned no refresh_token. Revoke prior app consent and retry." >&2
        return 1
      fi
      if printf '%s' "$recent_logs" | grep -q "Failed to fetch user info in background OAuth:"; then
        echo "WARNING: [E-OAUTH-USER-INFO] OAuth wait aborted: token accepted but user-info lookup failed." >&2
        return 1
      fi

      next_progress=$((next_progress + 10))
    fi
  done

  echo "WARNING: [W-OAUTH-TIMEOUT] Timed out waiting for OAuth account linkage. You can still finish OAuth and rerun ./console.sh accounts." >&2
  return 1
}

if [[ ! -f "$CONSOLE_SCRIPT" ]]; then
  echo "Missing script: $CONSOLE_SCRIPT" >&2
  exit 1
fi
if [[ ! -f "$ALLOW_GUARD_SCRIPT" ]]; then
  echo "Missing script: $ALLOW_GUARD_SCRIPT" >&2
  exit 1
fi

if [[ $# -gt 0 ]]; then
  case "$1" in
    status|health|accounts|login|restart|api-test)
      echo "Forwarding to console.sh: $*"
      exec bash "$CONSOLE_SCRIPT" "$@"
      ;;
  esac
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build) SKIP_BUILD=true; shift ;;
    --cache-build) USE_BUILD_CACHE=true; shift ;;
    --skip-login) SKIP_LOGIN=true; shift ;;
    --no-browser) NO_BROWSER=true; shift ;;
    --run-api-test) RUN_API_TEST=true; shift ;;
    --disable-admin-after) DISABLE_ADMIN_AFTER=true; shift ;;
    --image) IMAGE="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --prompt) PROMPT="$2"; shift 2 ;;
    -h|--help|-?|\?|/help) print_help; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      print_help
      exit 1
      ;;
  esac
done

if ! check_docker_available; then
  print_docker_unavailable
  exit 1
fi

step "Running allow-attribute guard" bash "$ALLOW_GUARD_SCRIPT"

if [[ "$SKIP_BUILD" != "true" ]]; then
  if [[ "$USE_BUILD_CACHE" == "true" ]]; then
    step "Building image $IMAGE (with cache)" build_with_guidance docker build -t "$IMAGE" -f docker/Dockerfile .
  else
    step "Building image $IMAGE (--no-cache)" build_with_guidance docker build --no-cache -t "$IMAGE" -f docker/Dockerfile .
  fi
fi

step "Restarting container with admin API enabled" bash "$CONSOLE_SCRIPT" restart --admin-api --image "$IMAGE" --port "$PORT"
step "Health check" bash "$CONSOLE_SCRIPT" health --port "$PORT"

if [[ "$SKIP_LOGIN" != "true" ]]; then
  # Check for ENCRYPTION_KEY before login to warn early
  if [[ -z "${ENCRYPTION_KEY:-}" ]]; then
    _has_encryption_key=false
    if [[ -f "$SCRIPT_DIR/.env.local" ]]; then
      _enc_val="$(grep -E '^ENCRYPTION_KEY=' "$SCRIPT_DIR/.env.local" | tail -n 1 | cut -d '=' -f2- | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g")"
      [[ -n "$_enc_val" ]] && _has_encryption_key=true
    fi
    if [[ "$_has_encryption_key" != "true" ]]; then
      echo "WARNING: [W-CRYPTO-KEY-MISSING] ENCRYPTION_KEY is not set. In Docker/container environments machine UID may be unavailable, so OAuth callback may succeed in browser while account save fails. Remediation: set ENCRYPTION_KEY, restart container, then rerun login." >&2
    fi
  fi

  if [[ "$NO_BROWSER" == "true" ]]; then
    step "Starting OAuth login flow" bash "$CONSOLE_SCRIPT" login --no-browser --image "$IMAGE" --port "$PORT"
  else
    step "Starting OAuth login flow" bash "$CONSOLE_SCRIPT" login --image "$IMAGE" --port "$PORT"
  fi
  step "Waiting for OAuth account linkage" wait_oauth_account_link 180 2 || true
fi

step "List accounts" bash "$CONSOLE_SCRIPT" accounts --port "$PORT"

if [[ "$RUN_API_TEST" == "true" ]]; then
  step "Run API test" bash "$CONSOLE_SCRIPT" api-test --model "$MODEL" --prompt "$PROMPT" --port "$PORT"
fi

if [[ "$DISABLE_ADMIN_AFTER" == "true" ]]; then
  step "Restarting with admin API disabled" bash "$CONSOLE_SCRIPT" restart --image "$IMAGE" --port "$PORT"
fi

echo "test-clean completed."
