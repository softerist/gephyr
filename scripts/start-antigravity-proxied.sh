#!/usr/bin/env bash
# Launches Antigravity with proxy environment variables.
# Linux equivalent of start-antigravity-proxied.ps1 (replaces cmd.exe + Electron launcher).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PORT=8877
ANTIGRAVITY_EXE=""
NO_PROXY="localhost,127.0.0.1,lh3.googleusercontent.com,.googleusercontent.com"
STOP_EXISTING=false
SET_IDE_PROXY=false
IDE_PROXY_SUPPORT="override"
SETTINGS_PATH=""

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/start-antigravity-proxied.sh [options]

Options:
  --port <n>                   Proxy port. Default: 8877
  --antigravity-exe <path>     Path to Antigravity binary
  --no-proxy <csv>             NO_PROXY list. Default: localhost,127.0.0.1,...
  --stop-existing              Kill running Antigravity processes first
  --set-ide-proxy              Also configure IDE proxy settings
  --ide-proxy-support <mode>   override|on|off. Default: override
  --settings-path <path>       Explicit settings.json path for IDE proxy
  -h, --help                   Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --antigravity-exe) ANTIGRAVITY_EXE="$2"; shift 2 ;;
    --no-proxy) NO_PROXY="$2"; shift 2 ;;
    --stop-existing) STOP_EXISTING=true; shift ;;
    --set-ide-proxy) SET_IDE_PROXY=true; shift ;;
    --ide-proxy-support) IDE_PROXY_SUPPORT="$2"; shift 2 ;;
    --settings-path) SETTINGS_PATH="$2"; shift 2 ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

# Resolve Antigravity executable
if [[ -z "$ANTIGRAVITY_EXE" ]]; then
  # Linux common locations
  candidates=(
    "/usr/share/antigravity/antigravity"
    "/opt/Antigravity/antigravity"
    "$HOME/.local/share/applications/antigravity"
  )
  # Also check flatpak / snap / PATH
  if command -v antigravity >/dev/null 2>&1; then
    ANTIGRAVITY_EXE="$(command -v antigravity)"
  else
    for c in "${candidates[@]}"; do
      if [[ -f "$c" ]]; then
        ANTIGRAVITY_EXE="$c"
        break
      fi
    done
  fi
  if [[ -z "$ANTIGRAVITY_EXE" ]]; then
    echo "ERROR: Antigravity executable not found. Pass --antigravity-exe <path>." >&2
    exit 1
  fi
fi

[[ -f "$ANTIGRAVITY_EXE" ]] || { echo "ERROR: Antigravity executable not found: $ANTIGRAVITY_EXE" >&2; exit 1; }

if [[ "$STOP_EXISTING" == "true" ]]; then
  pkill -f "$(basename "$ANTIGRAVITY_EXE")" 2>/dev/null || true
  sleep 0.3
fi

ca_cer="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [[ ! -f "$ca_cer" ]]; then
  # Try .cer variant
  ca_cer="$HOME/.mitmproxy/mitmproxy-ca-cert.cer"
fi
[[ -f "$ca_cer" ]] || { echo "ERROR: mitmproxy CA certificate not found at ~/.mitmproxy/" >&2; exit 1; }

proxy="http://127.0.0.1:$PORT"

if [[ "$SET_IDE_PROXY" == "true" ]]; then
  setter="$SCRIPT_DIR/set-antigravity-ide-proxy.sh"
  if [[ -f "$setter" ]]; then
    set_args=(--proxy-url "$proxy" --proxy-support "$IDE_PROXY_SUPPORT")
    [[ -n "$SETTINGS_PATH" ]] && set_args+=(--settings-path "$SETTINGS_PATH")
    bash "$setter" "${set_args[@]}" || echo "WARNING: Failed to set Antigravity IDE proxy." >&2
  else
    echo "WARNING: Missing IDE proxy setter script: $setter" >&2
  fi
fi

echo "Launching Antigravity with proxy env:"
echo "  HTTP_PROXY=$proxy"
echo "  HTTPS_PROXY=$proxy"
echo "  http_proxy=$proxy"
echo "  https_proxy=$proxy"
echo "  ALL_PROXY=$proxy"
echo "  NO_PROXY=$NO_PROXY"
echo "  NODE_EXTRA_CA_CERTS=$ca_cer"
echo "  GOOGLE_CLOUD_DISABLE_DIRECT_PATH=1"

# Launch with proxy env vars and --proxy-server for Electron/Chromium
HTTP_PROXY="$proxy" \
HTTPS_PROXY="$proxy" \
http_proxy="$proxy" \
https_proxy="$proxy" \
ALL_PROXY="$proxy" \
NO_PROXY="$NO_PROXY" \
NODE_EXTRA_CA_CERTS="$ca_cer" \
GOOGLE_CLOUD_DISABLE_DIRECT_PATH=1 \
  nohup "$ANTIGRAVITY_EXE" --proxy-server="$proxy" >/dev/null 2>&1 &

echo "Antigravity started (PID: $!)."
