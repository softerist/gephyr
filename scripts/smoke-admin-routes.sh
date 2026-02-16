#!/usr/bin/env bash
# Minimal operator smoke: restart -> health -> /api/version/routes
set -euo pipefail

SRC_PATH="${BASH_SOURCE[0]}"
# If invoked from Windows into WSL, the path may be like "F:\repo\...". Convert when possible.
if command -v wslpath >/dev/null 2>&1; then
  if [[ "$SRC_PATH" == *":\\"* ]]; then
    SRC_PATH="$(wslpath -u "$SRC_PATH")"
  fi
fi

SCRIPT_DIR="$(cd "$(dirname "$SRC_PATH")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONSOLE_SCRIPT="$REPO_ROOT/console.sh"
ENV_FILE="$REPO_ROOT/.env.local"

PORT="${PORT:-8045}"
IMAGE="${IMAGE:-gephyr:latest}"

die() { echo "ERROR: $1" >&2; exit 1; }

load_env_local() {
  [[ -f "$ENV_FILE" ]] || return 0
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    [[ "$line" != *"="* ]] && continue
    local k="${line%%=*}"
    local v="${line#*=}"
    k="$(printf '%s' "$k" | tr -d '\r' | xargs)"
    v="$(printf '%s' "$v" | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g")"
    [[ -n "$k" ]] && export "${k}=${v}"
  done < "$ENV_FILE"
}

ensure_api_key() {
  [[ -n "${API_KEY:-}" ]] && return 0
  load_env_local
  if [[ -z "${API_KEY:-}" && -f "$ENV_FILE" ]]; then
    local legacy
    legacy="$(grep -E '^[A-Za-z_][A-Za-z0-9_]*_API_KEY=' "$ENV_FILE" | head -n 1 | cut -d '=' -f2- | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g")"
    [[ -n "${legacy:-}" ]] && export API_KEY="$legacy"
  fi
  [[ -n "${API_KEY:-}" ]] || die "Missing API_KEY. Set API_KEY in env or .env.local."
}

command -v docker >/dev/null 2>&1 || die "docker is required"
command -v curl >/dev/null 2>&1 || die "curl is required"
[[ -f "$CONSOLE_SCRIPT" ]] || die "console.sh not found at $CONSOLE_SCRIPT"

echo "==> Restarting container (admin API enabled)"
"$CONSOLE_SCRIPT" restart --admin-api --port "$PORT" --image "$IMAGE" >/dev/null

echo "==> Health check (/health)"
"$CONSOLE_SCRIPT" health --port "$PORT" --quiet >/dev/null

ensure_api_key

echo "==> Fetching /api/version/routes"
cid="smoke-admin-routes-$(date +%s)"
rid="${cid}:1"
payload="$(curl -sS -w $'\n%{http_code}' \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "x-correlation-id: ${cid}" \
  -H "x-request-id: ${rid}" \
  "http://127.0.0.1:${PORT}/api/version/routes")"
http_code="$(printf '%s' "$payload" | tail -n 1)"
body="$(printf '%s' "$payload" | sed '$d')"

[[ "$http_code" == "200" ]] || die "/api/version/routes failed. HTTP $http_code"

if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY' "$body"
import json,sys
data=json.loads(sys.argv[1] or "{}")
routes=data.get("routes")
assert isinstance(routes, dict) and len(routes) > 0
print(f"OK smoke-admin-routes (routes keys: {len(routes)})")
PY
else
  printf '%s' "$body" | grep -q '"routes"' || die "/api/version/routes payload missing routes"
  echo "OK smoke-admin-routes"
fi
