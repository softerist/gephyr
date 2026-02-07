#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLE_SCRIPT="$SCRIPT_DIR/console.sh"

SKIP_BUILD=false
USE_BUILD_CACHE=false
SKIP_LOGIN=false
NO_BROWSER=false
RUN_API_TEST=false
DISABLE_ADMIN_AFTER=false
IMAGE="gephyr:latest"
MODEL="gpt-4o-mini"
PROMPT="hello from gephyr"

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
  --model <name>         Model used by --run-api-test
  --prompt <text>        Prompt used by --run-api-test
  -h, --help             Show help

Examples:
  ./test-clean.sh
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

if [[ ! -f "$CONSOLE_SCRIPT" ]]; then
  echo "Missing script: $CONSOLE_SCRIPT" >&2
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

if [[ "$SKIP_BUILD" != "true" ]]; then
  if [[ "$USE_BUILD_CACHE" == "true" ]]; then
    step "Building image $IMAGE (with cache)" docker build -t "$IMAGE" -f docker/Dockerfile .
  else
    step "Building image $IMAGE (--no-cache)" docker build --no-cache -t "$IMAGE" -f docker/Dockerfile .
  fi
fi

step "Restarting container with admin API enabled" bash "$CONSOLE_SCRIPT" restart --admin-api --image "$IMAGE"
step "Health check" bash "$CONSOLE_SCRIPT" health

if [[ "$SKIP_LOGIN" != "true" ]]; then
  if [[ "$NO_BROWSER" == "true" ]]; then
    step "Starting OAuth login flow" bash "$CONSOLE_SCRIPT" login --no-browser --image "$IMAGE"
  else
    step "Starting OAuth login flow" bash "$CONSOLE_SCRIPT" login --image "$IMAGE"
  fi
fi

step "List accounts" bash "$CONSOLE_SCRIPT" accounts

if [[ "$RUN_API_TEST" == "true" ]]; then
  step "Run API test" bash "$CONSOLE_SCRIPT" api-test --model "$MODEL" --prompt "$PROMPT"
fi

if [[ "$DISABLE_ADMIN_AFTER" == "true" ]]; then
  step "Restarting with admin API disabled" bash "$CONSOLE_SCRIPT" restart --image "$IMAGE"
fi

echo "test-clean completed."
