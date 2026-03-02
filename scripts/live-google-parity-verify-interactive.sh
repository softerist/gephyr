#!/usr/bin/env bash
# Live Google Parity Verify - Interactive Launcher (Linux/Bash equivalent)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARITY_SCRIPT="$SCRIPT_DIR/live-google-parity-verify.sh"

if [[ ! -f "$PARITY_SCRIPT" ]]; then
  echo "Error: Parity script not found at $PARITY_SCRIPT" >&2
  exit 1
fi

read_default() {
  local prompt="$1" default="$2"
  read -p "$prompt [$default]: " val
  echo "${val:-$default}"
}

read_yesno() {
  local prompt="$1" default="$2"
  local hint="y/N"
  [[ "$default" == "true" ]] && hint="Y/n"
  
  while true; do
    read -p "$prompt ($hint): " val
    [[ -z "$val" ]] && echo "$default" && return
    case "${val,,}" in
      y|yes|1) echo "true"; return ;;
      n|no|0) echo "false"; return ;;
      *) echo "Please answer y or n." >&2 ;;
    esac
  done
}

echo "Live Google Parity Verify - Interactive Launcher"
echo "Script: $PARITY_SCRIPT"

echo ""
echo "Select run mode:"
echo "  1) Gephyr scope (recommended default)"
echo "  2) Antigravity scope (allowlist + UA scoped)"
echo "  3) Raw baseline (no scope transform)"
read -p "Mode [1]: " mode_choice
mode_choice="${mode_choice:-1}"

scope="Gephyr"
known_good_path="output/known_good.gephyr_scope.jsonl"
known_good_source_path="output/known_good.jsonl"
allowlist_path="scripts/allowlists/antigravity_google_endpoints_default_chat.txt"

case "$mode_choice" in
  1) scope="Gephyr"; known_good_path="output/known_good.gephyr_scope.jsonl" ;;
  2) scope="Antigravity"; known_good_path="output/known_good.antigravity_scope.jsonl" ;;
  3) scope="Raw"; known_good_path="output/known_good.jsonl" ;;
  *) echo "Invalid choice. Defaulting to mode 1." ;;
esac

config_path=$(read_default "Config path" "$HOME/.gephyr/config.json")
out_gephyr_path=$(read_default "Gephyr outbound trace output path" "output/gephyr_google_outbound_headers.jsonl")
startup_timeout=$(read_default "Startup timeout (seconds)" "60")
require_oauth=$(read_yesno "Require OAuth relink flow" "true")
# Note: live-google-parity-verify.sh (bash) doesn't support all extended flow flags yet,
# but we'll include what it DOES support.

if [[ "$scope" == "Raw" ]]; then
  known_good_path=$(read_default "Known-good path (raw)" "$known_good_path")
else
  known_good_source_path=$(read_default "Known-good source path" "$known_good_source_path")
  known_good_path=$(read_default "Scoped known-good output path" "$known_good_path")
fi

ARGS=(
  "--config-path" "$config_path"
  "--known-good-path" "$known_good_path"
  "--out-gephyr-path" "$out_gephyr_path"
  "--startup-timeout-seconds" "$startup_timeout"
)

[[ "$require_oauth" == "true" ]] && ARGS+=("--require-oauth-relink")

echo ""
echo "Command preview:"
echo "bash $PARITY_SCRIPT ${ARGS[*]}"

run_now=$(read_yesno "Run now" "true")
if [[ "$run_now" != "true" ]]; then
  echo "Cancelled."
  exit 0
fi

bash "$PARITY_SCRIPT" "${ARGS[@]}"
