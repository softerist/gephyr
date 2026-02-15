#!/usr/bin/env bash
# Captures known-good Google API traffic through mitmproxy.
# Linux equivalent of capture-known-good-mitmproxy.ps1.
# Replaces Windows Registry proxy, netsh winhttp, and certutil with
# gsettings (GNOME), env vars, and update-ca-certificates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PORT=8877
KNOWN_GOOD_PATH="output/known_good.jsonl"
GEPHYR_PATH="output/gephyr_google_outbound_headers.jsonl"
MITMDUMP_PATH=""
CAPTURE_ALL=false
CAPTURE_NOISE=false
TRUST_CERT=false
SKIP_DIFF=false
REQUIRE_STREAM=false
SELF_TEST_PROXY=false
LAUNCH_ANTIGRAVITY_PROXIED=false
ANTIGRAVITY_EXE=""
NO_PROXY_VAL=""
STOP_EXISTING_ANTIGRAVITY=false
MANAGE_ANTIGRAVITY_IDE_PROXY=false
ANTIGRAVITY_IDE_PROXY_SUPPORT="override"
ANTIGRAVITY_SETTINGS_PATH=""
KEEP_ANTIGRAVITY_IDE_PROXY=false
MANAGE_ENV_PROXY=false
KEEP_ENV_PROXY=false
TARGET_HOSTS=()
TARGET_SUFFIXES=()
UA_CONTAINS=()
UA_EXCLUDE_CONTAINS=()

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/capture-known-good-mitmproxy.sh [options]

Options:
  --port <n>                       Proxy port. Default: 8877
  --known-good-path <path>         Output JSONL path. Default: output/known_good.jsonl
  --gephyr-path <path>             Gephyr trace JSONL. Default: output/gephyr_google_outbound_headers.jsonl
  --mitmdump-path <path>           Explicit mitmdump binary path
  --target-hosts <host>            Repeatable. Additional target hosts
  --target-suffixes <suffix>       Repeatable. Additional target suffixes
  --capture-all                    Capture all hosts (wide open)
  --capture-noise                  Include noise endpoints
  --trust-cert                     Install mitmproxy CA into system trust
  --skip-diff                      Skip diff report
  --require-stream                 Require streamGenerateContent in capture
  --self-test-proxy                Send self-test request through proxy
  --launch-antigravity-proxied     Launch Antigravity with proxy env
  --antigravity-exe <path>         Antigravity binary path
  --no-proxy <csv>                 NO_PROXY override
  --stop-existing-antigravity      Kill existing Antigravity
  --manage-antigravity-ide-proxy   Set IDE proxy during capture
  --antigravity-ide-proxy-support <mode>  override|on|off
  --antigravity-settings-path <path>      Explicit settings.json
  --keep-antigravity-ide-proxy     Don't restore IDE proxy after capture
  --manage-env-proxy               Export http_proxy/https_proxy for this session
  --keep-env-proxy                 Don't unset proxy env after capture
  --ua-contains <substr>           Repeatable. UA substring allowlist
  --ua-exclude-contains <substr>   Repeatable. UA substring denylist
  -h, --help                       Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --known-good-path) KNOWN_GOOD_PATH="$2"; shift 2 ;;
    --gephyr-path) GEPHYR_PATH="$2"; shift 2 ;;
    --mitmdump-path) MITMDUMP_PATH="$2"; shift 2 ;;
    --target-hosts) TARGET_HOSTS+=("$2"); shift 2 ;;
    --target-suffixes) TARGET_SUFFIXES+=("$2"); shift 2 ;;
    --capture-all) CAPTURE_ALL=true; shift ;;
    --capture-noise) CAPTURE_NOISE=true; shift ;;
    --trust-cert) TRUST_CERT=true; shift ;;
    --skip-diff) SKIP_DIFF=true; shift ;;
    --require-stream) REQUIRE_STREAM=true; shift ;;
    --self-test-proxy) SELF_TEST_PROXY=true; shift ;;
    --launch-antigravity-proxied) LAUNCH_ANTIGRAVITY_PROXIED=true; shift ;;
    --antigravity-exe) ANTIGRAVITY_EXE="$2"; shift 2 ;;
    --no-proxy) NO_PROXY_VAL="$2"; shift 2 ;;
    --stop-existing-antigravity) STOP_EXISTING_ANTIGRAVITY=true; shift ;;
    --manage-antigravity-ide-proxy) MANAGE_ANTIGRAVITY_IDE_PROXY=true; shift ;;
    --antigravity-ide-proxy-support) ANTIGRAVITY_IDE_PROXY_SUPPORT="$2"; shift 2 ;;
    --antigravity-settings-path) ANTIGRAVITY_SETTINGS_PATH="$2"; shift 2 ;;
    --keep-antigravity-ide-proxy) KEEP_ANTIGRAVITY_IDE_PROXY=true; shift ;;
    --manage-env-proxy) MANAGE_ENV_PROXY=true; shift ;;
    --keep-env-proxy) KEEP_ENV_PROXY=true; shift ;;
    --ua-contains) UA_CONTAINS+=("$2"); shift 2 ;;
    --ua-exclude-contains) UA_EXCLUDE_CONTAINS+=("$2"); shift 2 ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

cd "$PROJECT_ROOT"

# Resolve paths relative to project root
resolve_path() {
  local p="$1"
  [[ "$p" == /* ]] && echo "$p" || echo "$PROJECT_ROOT/$p"
}

# Resolve mitmdump
resolve_mitmdump() {
  if [[ -n "$MITMDUMP_PATH" ]]; then
    [[ -f "$MITMDUMP_PATH" ]] || { echo "ERROR: Mitmdump path not found: $MITMDUMP_PATH" >&2; exit 1; }
    echo "$MITMDUMP_PATH"; return
  fi
  if command -v mitmdump >/dev/null 2>&1; then
    command -v mitmdump; return
  fi
  local candidates=(
    "$HOME/.local/bin/mitmdump"
    "/usr/local/bin/mitmdump"
    "/usr/bin/mitmdump"
  )
  for c in "${candidates[@]}"; do
    [[ -f "$c" ]] && { echo "$c"; return; }
  done
  echo "ERROR: Could not find mitmdump. Run: bash scripts/setup-mitmproxy.sh" >&2
  exit 1
}

mitmdump_exe="$(resolve_mitmdump)"
mkdir -p "$PROJECT_ROOT/output"

known_good_abs="$(resolve_path "$KNOWN_GOOD_PATH")"
gephyr_abs="$(resolve_path "$GEPHYR_PATH")"
known_good_dir="$(dirname "$known_good_abs")"
mkdir -p "$known_good_dir"

capture_temp="$known_good_abs.tmp"
diag_abs="$PROJECT_ROOT/output/known_good_capture_hosts.json"
mitmdump_stderr_log="$PROJECT_ROOT/output/mitmdump_stderr.log"
mitmdump_stdout_log="$PROJECT_ROOT/output/mitmdump_stdout.log"

rm -f "$capture_temp" "$diag_abs" "$mitmdump_stderr_log" "$mitmdump_stdout_log"

addon_path="$SCRIPT_DIR/mitm-google-capture.py"
[[ -f "$addon_path" ]] || { echo "ERROR: Missing addon script: $addon_path" >&2; exit 1; }

# Check port availability
port_listeners="$(ss -tlnH "sport = :$PORT" 2>/dev/null || true)"
if [[ -n "$port_listeners" ]]; then
  # Try to kill stale mitmdump/python
  stale_pids="$(lsof -ti :$PORT 2>/dev/null || true)"
  for pid in $stale_pids; do
    pname="$(ps -p "$pid" -o comm= 2>/dev/null || echo "?")"
    if [[ "$pname" == "mitmdump" || "$pname" == "python"* ]]; then
      echo "Stopping existing listener on $PORT: PID=$pid Name=$pname"
      kill "$pid" 2>/dev/null || true
    fi
  done
  sleep 0.25
  port_listeners="$(ss -tlnH "sport = :$PORT" 2>/dev/null || true)"
  if [[ -n "$port_listeners" ]]; then
    echo "ERROR: Port 127.0.0.1:$PORT is already in use. Stop that process or use --port <free_port>." >&2
    exit 1
  fi
fi

# Sanitize tokens
sanitize_host() {
  local s="$1"
  s="${s#\'}" ; s="${s%\'}" ; s="${s#\"}" ; s="${s%\"}"
  s="$(printf '%s' "$s" | sed -E 's|^https?://||')"
  s="${s%%/*}"
  echo "$s"
}

sanitize_suffix() {
  local s="$1"
  s="${s#\'}" ; s="${s%\'}" ; s="${s#\"}" ; s="${s%\"}"
  [[ -n "$s" && "${s:0:1}" != "." ]] && s=".$s"
  echo "$s"
}

sanitize_ua() {
  local s="$1"
  s="${s#\'}" ; s="${s%\'}" ; s="${s#\"}" ; s="${s%\"}"
  echo "$s"
}

# Set environment for addon
export GEPHYR_MITM_OUT="$capture_temp"
export GEPHYR_MITM_DIAG_OUT="$diag_abs"
unset GEPHYR_MITM_CAPTURE_ALL GEPHYR_MITM_CAPTURE_NOISE GEPHYR_MITM_TARGET_HOSTS GEPHYR_MITM_TARGET_SUFFIXES GEPHYR_MITM_UA_CONTAINS GEPHYR_MITM_UA_EXCLUDE_CONTAINS 2>/dev/null || true

if [[ ${#TARGET_HOSTS[@]} -gt 0 ]]; then
  sanitized=()
  for h in "${TARGET_HOSTS[@]}"; do sanitized+=("$(sanitize_host "$h")"); done
  export GEPHYR_MITM_TARGET_HOSTS="$(IFS=,; echo "${sanitized[*]}")"
fi
if [[ ${#TARGET_SUFFIXES[@]} -gt 0 ]]; then
  sanitized=()
  for s in "${TARGET_SUFFIXES[@]}"; do sanitized+=("$(sanitize_suffix "$s")"); done
  export GEPHYR_MITM_TARGET_SUFFIXES="$(IFS=,; echo "${sanitized[*]}")"
fi
[[ "$CAPTURE_ALL" == "true" ]] && export GEPHYR_MITM_CAPTURE_ALL=1
[[ "$CAPTURE_NOISE" == "true" ]] && export GEPHYR_MITM_CAPTURE_NOISE=1
if [[ ${#UA_CONTAINS[@]} -gt 0 ]]; then
  sanitized=()
  for u in "${UA_CONTAINS[@]}"; do sanitized+=("$(sanitize_ua "$u")"); done
  export GEPHYR_MITM_UA_CONTAINS="$(IFS=,; echo "${sanitized[*]}")"
fi
if [[ ${#UA_EXCLUDE_CONTAINS[@]} -gt 0 ]]; then
  sanitized=()
  for u in "${UA_EXCLUDE_CONTAINS[@]}"; do sanitized+=("$(sanitize_ua "$u")"); done
  export GEPHYR_MITM_UA_EXCLUDE_CONTAINS="$(IFS=,; echo "${sanitized[*]}")"
fi

echo "Starting mitmdump on 127.0.0.1:$PORT ..."
"$mitmdump_exe" --listen-host 127.0.0.1 --listen-port "$PORT" --set block_global=false -s "$addon_path" \
  > "$mitmdump_stdout_log" 2> "$mitmdump_stderr_log" &
mitmdump_pid=$!

ide_proxy_was_set=false
ide_settings_original=""
env_proxy_was_set=false

cleanup() {
  # Unset addon env vars
  unset GEPHYR_MITM_OUT GEPHYR_MITM_DIAG_OUT GEPHYR_MITM_CAPTURE_ALL GEPHYR_MITM_CAPTURE_NOISE \
    GEPHYR_MITM_TARGET_HOSTS GEPHYR_MITM_TARGET_SUFFIXES GEPHYR_MITM_UA_CONTAINS GEPHYR_MITM_UA_EXCLUDE_CONTAINS 2>/dev/null || true

  if [[ -n "${mitmdump_pid:-}" ]]; then
    echo "Stopping mitmdump ..."
    kill "$mitmdump_pid" 2>/dev/null || true
    sleep 0.25
    kill -9 "$mitmdump_pid" 2>/dev/null || true
    wait "$mitmdump_pid" 2>/dev/null || true
  fi

  if [[ "$ide_proxy_was_set" == "true" && "$KEEP_ANTIGRAVITY_IDE_PROXY" != "true" ]]; then
    if [[ -n "$ide_settings_original" ]]; then
      local ide_path
      ide_path="$(bash "$SCRIPT_DIR/set-antigravity-ide-proxy.sh" --print-only 2>/dev/null | grep '^Settings:' | sed 's/^Settings: //' || true)"
      if [[ -n "$ide_path" ]]; then
        local stamp
        stamp="$(date +%Y%m%d-%H%M%S)"
        cp "$ide_path" "$ide_path.gephyr-before-restore-$stamp" 2>/dev/null || true
        echo "$ide_settings_original" > "$ide_path"
        echo "Restored Antigravity IDE proxy settings after capture."
      fi
    else
      bash "$SCRIPT_DIR/set-antigravity-ide-proxy.sh" --clear 2>/dev/null || true
      echo "Cleared Antigravity IDE proxy settings after capture."
    fi
  fi

  if [[ "$env_proxy_was_set" == "true" && "$KEEP_ENV_PROXY" != "true" ]]; then
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY 2>/dev/null || true
    echo "Unset session proxy env vars."
  fi
}
trap cleanup EXIT

sleep 0.7
if ! kill -0 "$mitmdump_pid" 2>/dev/null; then
  echo "ERROR: mitmdump exited early. Check output/mitmdump_stdout.log and output/mitmdump_stderr.log." >&2
  exit 1
fi

ca_pem="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
echo ""
echo "Do this now (baseline client, not Gephyr):"
echo "1) Configure proxy in client/system to 127.0.0.1:$PORT"
echo "2) Trust mitmproxy certificate:"
if [[ -f "$ca_pem" ]]; then
  echo "   sudo cp $ca_pem /usr/local/share/ca-certificates/mitmproxy-ca.crt && sudo update-ca-certificates"
  if [[ "$TRUST_CERT" == "true" ]]; then
    if command -v update-ca-certificates >/dev/null 2>&1; then
      sudo cp "$ca_pem" /usr/local/share/ca-certificates/mitmproxy-ca.crt 2>/dev/null && \
        sudo update-ca-certificates 2>/dev/null && \
        echo "   Installed certificate into system trust store." || \
        echo "   WARNING: Failed to install certificate. Run the command above manually as root." >&2
    elif command -v trust >/dev/null 2>&1; then
      sudo trust anchor "$ca_pem" 2>/dev/null && echo "   Installed certificate via trust anchor." || \
        echo "   WARNING: Failed to install certificate." >&2
    else
      echo "   WARNING: No known cert installer found. Manually add $ca_pem to your trust store." >&2
    fi
  fi
else
  echo "   Open http://mitm.it from the proxied client and install cert"
fi
if [[ "$REQUIRE_STREAM" == "true" ]]; then
  echo "3) Trigger baseline flows: login/refresh + loadCodeAssist + fetch models + generate/stream"
else
  echo "3) Trigger baseline flows: login/refresh + loadCodeAssist + fetch models"
  echo "   (If you want to capture chat/prompt traffic too, do a generate/stream action before stopping capture.)"
fi
echo ""
echo "Tip: if your baseline client ignores system proxy, launch Antigravity with explicit proxy env:"
echo "   bash scripts/start-antigravity-proxied.sh --port $PORT --stop-existing"
echo ""

if [[ -n "${GEPHYR_MITM_TARGET_HOSTS:-}" || -n "${GEPHYR_MITM_TARGET_SUFFIXES:-}" ]]; then
  echo "Capture target hosts: ${GEPHYR_MITM_TARGET_HOSTS:-}"
  echo "Capture target suffixes: ${GEPHYR_MITM_TARGET_SUFFIXES:-}"
  echo ""
fi
if [[ -n "${GEPHYR_MITM_CAPTURE_ALL:-}" ]]; then
  echo "Capture mode: ALL HOSTS (wide open)"
  [[ -n "${GEPHYR_MITM_CAPTURE_NOISE:-}" ]] && echo "Capture noise: enabled (includes tokeninfo, etc.)"
  echo ""
fi
if [[ -n "${GEPHYR_MITM_UA_CONTAINS:-}" ]]; then
  echo "Capture filter: user-agent must contain one of: $GEPHYR_MITM_UA_CONTAINS"
  echo ""
fi
if [[ -n "${GEPHYR_MITM_UA_EXCLUDE_CONTAINS:-}" ]]; then
  echo "Capture filter: user-agent must NOT contain any of: $GEPHYR_MITM_UA_EXCLUDE_CONTAINS"
  echo ""
fi

# Manage IDE proxy
if [[ "$MANAGE_ANTIGRAVITY_IDE_PROXY" == "true" ]]; then
  setter="$SCRIPT_DIR/set-antigravity-ide-proxy.sh"
  if [[ -f "$setter" ]]; then
    # Snapshot current settings
    ide_settings_original="$(bash "$setter" --print-only 2>/dev/null || true)"
    set_args=(--proxy-url "http://127.0.0.1:$PORT" --proxy-support "$ANTIGRAVITY_IDE_PROXY_SUPPORT")
    [[ -n "$ANTIGRAVITY_SETTINGS_PATH" ]] && set_args+=(--settings-path "$ANTIGRAVITY_SETTINGS_PATH")
    bash "$setter" "${set_args[@]}" 2>/dev/null && ide_proxy_was_set=true && echo "Antigravity IDE proxy configured for this capture." || echo "WARNING: Failed to set Antigravity IDE proxy." >&2
    if [[ "$ide_proxy_was_set" == "true" && "$KEEP_ANTIGRAVITY_IDE_PROXY" != "true" ]]; then
      echo "It will be restored automatically after you press Enter."
    fi
  fi
  echo ""
fi

# Manage env proxy
if [[ "$MANAGE_ENV_PROXY" == "true" ]]; then
  proxy_url="http://127.0.0.1:$PORT"
  export http_proxy="$proxy_url" https_proxy="$proxy_url" HTTP_PROXY="$proxy_url" HTTPS_PROXY="$proxy_url" ALL_PROXY="$proxy_url"
  env_proxy_was_set=true
  echo "Set session proxy env vars: http_proxy=$proxy_url"
  [[ "$KEEP_ENV_PROXY" != "true" ]] && echo "They will be unset automatically after you press Enter."
  echo ""
fi

# Launch Antigravity proxied
if [[ "$LAUNCH_ANTIGRAVITY_PROXIED" == "true" ]]; then
  launcher="$SCRIPT_DIR/start-antigravity-proxied.sh"
  if [[ -f "$launcher" ]]; then
    launch_args=(--port "$PORT")
    [[ "$STOP_EXISTING_ANTIGRAVITY" == "true" ]] && launch_args+=(--stop-existing)
    [[ -n "$ANTIGRAVITY_EXE" ]] && launch_args+=(--antigravity-exe "$ANTIGRAVITY_EXE")
    [[ -n "$NO_PROXY_VAL" ]] && launch_args+=(--no-proxy "$NO_PROXY_VAL")
    bash "$launcher" "${launch_args[@]}" 2>/dev/null && echo "Launched Antigravity proxied (best-effort)." || echo "WARNING: Failed to launch Antigravity proxied." >&2
  fi
  echo ""
fi

# Self-test proxy
if [[ "$SELF_TEST_PROXY" == "true" ]]; then
  status="$(curl -sS -o /dev/null -w '%{http_code}' --proxy "http://127.0.0.1:$PORT" \
    'https://oauth2.googleapis.com/tokeninfo?access_token=invalid' --max-time 10 2>/dev/null || echo "000")"
  echo "Proxy self-test request sent (tokeninfo, HTTP $status)."
  echo ""
fi

read -r -p "Press Enter when capture is complete "

# Cleanup runs via trap, but we need to stop mitmdump before post-processing
kill "$mitmdump_pid" 2>/dev/null || true
sleep 0.25
kill -9 "$mitmdump_pid" 2>/dev/null || true
wait "$mitmdump_pid" 2>/dev/null || true
mitmdump_pid=""  # Prevent double-kill in cleanup

# Post-processing
if [[ ! -f "$capture_temp" ]]; then
  diag_summary=""
  if [[ -f "$diag_abs" ]] && command -v python3 >/dev/null 2>&1; then
    diag_summary="$(python3 -c "
import json
d=json.load(open('$diag_abs'))
top=[f\"{h['host']} ({h['count']})\" for h in d.get('top_hosts',[])[:10]]
print(f\"Capture diagnostics: total requests seen={d.get('total_requests_seen',0)}, target requests seen={d.get('total_target_requests_seen',0)}\")
print(f\"Top observed hosts: {', '.join(top)}\")
" 2>/dev/null || true)"
  fi

  [[ -f "$mitmdump_stderr_log" ]] && { echo "=== mitmdump stderr ==="; cat "$mitmdump_stderr_log"; echo "======================="; }
  [[ -f "$mitmdump_stdout_log" ]] && { echo "=== mitmdump stdout ==="; cat "$mitmdump_stdout_log"; echo "======================="; }

  msg="Known-good trace was not produced at: $known_good_abs"
  msg+=$'\n'"No requests to Google APIs reached the proxy."
  msg+=$'\n'"Ensure your client is configured to use proxy 127.0.0.1:$PORT and the mitmproxy CA is trusted."
  [[ -n "$diag_summary" ]] && msg+=$'\n'"$diag_summary"
  echo "ERROR: $msg" >&2
  exit 1
fi

line_count="$(wc -l < "$capture_temp")"
if [[ "$line_count" -eq 0 ]]; then
  rm -f "$capture_temp"
  echo "ERROR: Known-good trace is empty. No Google requests reached mitmproxy." >&2
  exit 1
fi

if [[ "$REQUIRE_STREAM" == "true" ]]; then
  if ! grep -q "streamGenerateContent" "$capture_temp" 2>/dev/null; then
    stamp="$(date +%Y%m%d-%H%M%S)"
    failed_path="$known_good_abs.missing-stream-$stamp.jsonl"
    mv "$capture_temp" "$failed_path" 2>/dev/null || failed_path="$capture_temp"
    echo "ERROR: Known-good capture did not include streamGenerateContent." >&2
    echo "Saved for inspection at: $failed_path" >&2
    exit 1
  fi
fi

if [[ -f "$known_good_abs" ]]; then
  stamp="$(date +%Y%m%d-%H%M%S)"
  backup_path="$known_good_abs.bak-$stamp"
  mv "$known_good_abs" "$backup_path"
  echo "Backed up previous known-good trace to: $backup_path"
fi
mv "$capture_temp" "$known_good_abs"

echo "Known-good trace saved: $known_good_abs ($line_count lines)"

if [[ -f "$diag_abs" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -c "
import json
d=json.load(open('$diag_abs'))
top_uas=[f\"{u['user_agent']} ({u['count']})\" for u in d.get('top_target_user_agents',[])[:6]]
if top_uas: print(f\"Top target user-agents: {' | '.join(top_uas)}\")
" 2>/dev/null || true
fi

if [[ "$SKIP_DIFF" != "true" ]]; then
  [[ -f "$gephyr_abs" ]] || { echo "ERROR: Gephyr capture JSONL missing: $gephyr_abs" >&2; exit 1; }
  echo "Running diff against Gephyr capture ..."
  bash "$SCRIPT_DIR/diff-google-traces.sh" --gephyr "$gephyr_abs" --known-good "$known_good_abs"
  echo "Done. See:"
  echo "  output/google_trace_diff_report.txt"
  echo "  output/google_trace_diff_report.json"
fi
