#!/usr/bin/env bash
set -euo pipefail

# Check Docker availability early to fail fast with a single message
if ! docker info >/dev/null 2>&1; then
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
  exit 1
fi

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

wait_oauth_account_link() {
  local timeout_sec="${1:-180}"
  local poll_sec="${2:-2}"
  local elapsed=0
  local next_progress=10
  local api_key="${GEPHYR_API_KEY:-}"

  if [[ -z "$api_key" && -f "$SCRIPT_DIR/.env.local" ]]; then
    api_key="$(grep -E '^GEPHYR_API_KEY=' "$SCRIPT_DIR/.env.local" | tail -n 1 | cut -d '=' -f2- | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g")"
  fi

  if [[ -z "$api_key" ]]; then
    echo "Warning: skipping OAuth wait because GEPHYR_API_KEY is missing (env and .env.local)."
    return 1
  fi

  echo "Waiting for OAuth callback/account link (timeout: ${timeout_sec}s)..."
  echo "Complete login in your browser; script continues automatically after account is linked."

  while (( elapsed < timeout_sec )); do
    local payload
    payload="$(curl -sS -H "Authorization: Bearer ${api_key}" "http://127.0.0.1:${PORT}/api/accounts" || true)"
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
    if (( elapsed >= next_progress )); then
      echo "Still waiting for OAuth linkage... ${elapsed}s elapsed."
      next_progress=$((next_progress + 10))
    fi
  done

  echo "Warning: timed out waiting for OAuth account linkage. Finish OAuth and run ./console.sh accounts."
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

step "Running allow-attribute guard" bash "$ALLOW_GUARD_SCRIPT"

if [[ "$SKIP_BUILD" != "true" ]]; then
  if [[ "$USE_BUILD_CACHE" == "true" ]]; then
    step "Building image $IMAGE (with cache)" docker build -t "$IMAGE" -f docker/Dockerfile .
  else
    step "Building image $IMAGE (--no-cache)" docker build --no-cache -t "$IMAGE" -f docker/Dockerfile .
  fi
fi

step "Restarting container with admin API enabled" bash "$CONSOLE_SCRIPT" restart --admin-api --image "$IMAGE" --port "$PORT"
step "Health check" bash "$CONSOLE_SCRIPT" health --port "$PORT"

if [[ "$SKIP_LOGIN" != "true" ]]; then
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
