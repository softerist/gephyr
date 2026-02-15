#!/usr/bin/env bash
# Configures Antigravity IDE proxy settings.
# Linux equivalent of set-antigravity-ide-proxy.ps1 (uses ~/.config instead of APPDATA).
set -euo pipefail

PROXY_URL=""
PORT=8879
SETTINGS_PATH=""
PROXY_SUPPORT="override"
CLEAR=false
PRINT_ONLY=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/set-antigravity-ide-proxy.sh [options]

Options:
  --proxy-url <url>          Proxy URL. Default: http://127.0.0.1:<port>
  --port <n>                 Port for default proxy URL. Default: 8879
  --settings-path <path>     Explicit path to settings.json
  --proxy-support <mode>     override|on|off. Default: override
  --clear                    Remove proxy settings
  --print-only               Print current settings only
  -h, --help                 Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy-url) PROXY_URL="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --settings-path) SETTINGS_PATH="$2"; shift 2 ;;
    --proxy-support) PROXY_SUPPORT="$2"; shift 2 ;;
    --clear) CLEAR=true; shift ;;
    --print-only) PRINT_ONLY=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required." >&2; exit 1; }

[[ -n "$PROXY_URL" ]] || PROXY_URL="http://127.0.0.1:$PORT"

resolve_settings_path() {
  if [[ -n "$SETTINGS_PATH" ]]; then
    echo "$SETTINGS_PATH"
    return
  fi
  # Linux: ~/.config/Antigravity/User/settings.json
  # macOS: ~/Library/Application Support/Antigravity/User/settings.json
  local config_dir="${XDG_CONFIG_HOME:-$HOME/.config}"
  if [[ "$(uname)" == "Darwin" ]]; then
    config_dir="$HOME/Library/Application Support"
  fi
  echo "$config_dir/Antigravity/User/settings.json"
}

settings_abs="$(resolve_settings_path)"
settings_dir="$(dirname "$settings_abs")"
mkdir -p "$settings_dir"

raw="{}"
[[ -f "$settings_abs" ]] && raw="$(cat "$settings_abs")"

python3 - <<PY "$settings_abs" "$raw" "$PRINT_ONLY" "$CLEAR" "$PROXY_URL" "$PROXY_SUPPORT"
import json, sys, os, shutil
from datetime import datetime

settings_abs = sys.argv[1]
raw = sys.argv[2]
print_only = sys.argv[3] == "true"
clear = sys.argv[4] == "true"
proxy_url = sys.argv[5]
proxy_support = sys.argv[6]

try:
    obj = json.loads(raw or "{}")
except Exception:
    print(f"ERROR: Failed to parse settings JSON at '{settings_abs}'", file=sys.stderr)
    sys.exit(1)

if print_only:
    print(f"Settings: {settings_abs}")
    print(f"http.proxy: {obj.get('http.proxy', '(not set)')}")
    print(f"http.proxySupport: {obj.get('http.proxySupport', '(not set)')}")
    sys.exit(0)

if clear:
    obj.pop("http.proxy", None)
    obj.pop("http.proxySupport", None)
else:
    obj["http.proxy"] = proxy_url
    obj["http.proxySupport"] = proxy_support

# Backup before writing
backup = ""
if os.path.exists(settings_abs):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = f"{settings_abs}.bak-{stamp}"
    shutil.copy2(settings_abs, backup)

with open(settings_abs, "w") as f:
    json.dump(obj, f, indent=2)

if clear:
    print(f"Cleared Antigravity IDE proxy settings in: {settings_abs}")
else:
    print(f"Set Antigravity IDE proxy settings in: {settings_abs}")
    print(f"  http.proxy={proxy_url}")
    print(f"  http.proxySupport={proxy_support}")
if backup:
    print(f"Backup: {backup}")
PY
