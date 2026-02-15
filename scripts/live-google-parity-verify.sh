#!/usr/bin/env bash
# Live Google outbound parity verification.
# Builds gephyr, starts it, exercises API paths, extracts google_outbound_headers
# from logs, then runs diff-google-traces.sh.
# Linux equivalent of live-google-parity-verify.ps1.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIG_PATH="$HOME/.gephyr/config.json"
KNOWN_GOOD_PATH="output/known_good.jsonl"
OUT_GEPHYR_PATH="output/gephyr_google_outbound_headers.jsonl"
STARTUP_TIMEOUT_SECONDS=60
REQUIRE_OAUTH_RELINK=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/live-google-parity-verify.sh [options]

Options:
  --config-path <path>                 Default: ~/.gephyr/config.json
  --known-good-path <path>             Default: output/known_good.jsonl
  --out-gephyr-path <path>             Default: output/gephyr_google_outbound_headers.jsonl
  --startup-timeout-seconds <n>        Default: 60
  --require-oauth-relink               Force OAuth relink flow
  -h, --help                           Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config-path) CONFIG_PATH="$2"; shift 2 ;;
    --known-good-path) KNOWN_GOOD_PATH="$2"; shift 2 ;;
    --out-gephyr-path) OUT_GEPHYR_PATH="$2"; shift 2 ;;
    --startup-timeout-seconds) STARTUP_TIMEOUT_SECONDS="$2"; shift 2 ;;
    --require-oauth-relink) REQUIRE_OAUTH_RELINK=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "ERROR: cargo is required." >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required." >&2; exit 1; }

[[ -f "$CONFIG_PATH" ]] || { echo "ERROR: Config not found: $CONFIG_PATH" >&2; exit 1; }
[[ -f "$KNOWN_GOOD_PATH" ]] || { echo "ERROR: Known-good trace not found: $KNOWN_GOOD_PATH" >&2; exit 1; }

# Load ENCRYPTION_KEY
get_env_value() {
  local path="$1" name="$2"
  [[ -f "$path" ]] || return 1
  local val
  val="$(grep -E "^\\s*${name}\\s*=" "$path" | tail -n 1 | cut -d '=' -f2- | tr -d '\r' | sed -E "s/^['\"]|['\"]$//g" | xargs)"
  [[ -n "$val" ]] && echo "$val"
}

if [[ -z "${ENCRYPTION_KEY:-}" ]]; then
  enc_val="$(get_env_value ".env.local" "ENCRYPTION_KEY" || true)"
  if [[ -n "$enc_val" ]]; then
    export ENCRYPTION_KEY="$enc_val"
    echo "Loaded ENCRYPTION_KEY from .env.local for this run."
  fi
fi
[[ -n "${ENCRYPTION_KEY:-}" ]] || { echo "ERROR: ENCRYPTION_KEY is not set and was not found in .env.local." >&2; exit 1; }

# Read config
api_key="$(python3 -c "import json; print(json.load(open('$CONFIG_PATH'))['proxy']['api_key'])")"
port="$(python3 -c "import json; print(json.load(open('$CONFIG_PATH'))['proxy']['port'])")"
api_base="http://127.0.0.1:$port"

api_call() {
  local method="$1" path="$2"
  shift 2
  local body="${1:-}"
  if [[ -n "$body" ]]; then
    curl -sS -X "$method" -H "Authorization: Bearer $api_key" -H "Content-Type: application/json" \
      -d "$body" --max-time 120 "$api_base$path"
  else
    curl -sS -X "$method" -H "Authorization: Bearer $api_key" --max-time 30 "$api_base$path"
  fi
}

echo "Building latest gephyr binary ..."
cargo build --bin gephyr >/dev/null

echo "Starting Gephyr with ENABLE_ADMIN_API=true and RUST_LOG=debug ..."
# Kill existing gephyr processes
pkill -x gephyr 2>/dev/null && echo "Stopped existing gephyr process." || true

gephyr_pid=""
gephyr_log="$(mktemp)"

cleanup() {
  if [[ -n "$gephyr_pid" ]]; then
    kill "$gephyr_pid" 2>/dev/null || true
    wait "$gephyr_pid" 2>/dev/null || true
    echo "Stopped Gephyr process."
  fi
  rm -f "$gephyr_log"
}
trap cleanup EXIT

ENABLE_ADMIN_API=true ABV_ENABLE_ADMIN_API=true ENCRYPTION_KEY="$ENCRYPTION_KEY" RUST_LOG=debug \
  ./target/debug/gephyr > "$gephyr_log" 2>&1 &
gephyr_pid=$!

# Wait for API
deadline=$((SECONDS + STARTUP_TIMEOUT_SECONDS))
is_up=false
while [[ $SECONDS -lt $deadline ]]; do
  if api_call GET /api/health >/dev/null 2>&1; then
    is_up=true
    break
  fi
  sleep 0.7
done

if [[ "$is_up" != "true" ]]; then
  echo "Gephyr startup output (tail):"
  tail -n 60 "$gephyr_log"
  echo "ERROR: Gephyr admin API did not become reachable on $api_base" >&2
  exit 1
fi
echo "API is up at $api_base"

# Start proxy
api_call POST /api/proxy/start "" 2>/dev/null && echo "Proxy service start requested." || echo "Proxy start returned error (continuing)."

# Show outbound policy
policy="$(api_call GET /api/proxy/google/outbound-policy)"
echo "Effective mode: $(echo "$policy" | python3 -c "import json,sys; print(json.load(sys.stdin).get('mode','?'))")"

# Enable debug logging if needed
log_enabled="$(echo "$policy" | python3 -c "import json,sys; print(json.load(sys.stdin).get('debug',{}).get('log_google_outbound_headers', False))" 2>/dev/null || echo "False")"
if [[ "$log_enabled" != "True" ]]; then
  echo "Enabling debug.log_google_outbound_headers via /api/config ..."
  live_config="$(api_call GET /api/config)"
  updated="$(echo "$live_config" | python3 -c "
import json,sys
c = json.load(sys.stdin)
c.setdefault('proxy',{}).setdefault('debug_logging',{})['log_google_outbound_headers'] = True
print(json.dumps({'config': c}))")"
  api_call POST /api/config "$updated" >/dev/null
fi

cutoff="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Cutoff UTC: $cutoff"

# OAuth relink
if [[ "$REQUIRE_OAUTH_RELINK" == "true" ]]; then
  echo "Preparing OAuth relink URL ..."
  oauth_resp="$(api_call GET /api/auth/url)"
  oauth_url="$(echo "$oauth_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('url',''))")"
  if [[ -z "$oauth_url" ]]; then
    echo "ERROR: OAuth prepare did not return a URL." >&2
    exit 1
  fi
  echo "Open this URL and complete Google consent:"
  echo "$oauth_url"
  xdg-open "$oauth_url" 2>/dev/null || open "$oauth_url" 2>/dev/null || echo "Auto-open failed. Open the URL manually."
  read -r -p "After consent completes in browser, press Enter to continue "

  for i in $(seq 1 90); do
    status_resp="$(api_call GET /api/auth/status 2>/dev/null || echo '{}')"
    phase="$(echo "$status_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('phase',''))" 2>/dev/null || true)"
    detail="$(echo "$status_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('detail',''))" 2>/dev/null || true)"
    echo "OAuth status [$i/90]: phase=$phase detail=$detail"
    [[ "$phase" == "linked" ]] && break
    [[ "$phase" == "failed" || "$phase" == "rejected" || "$phase" == "cancelled" ]] && break
    sleep 2
  done
fi

# Exercise accounts
accounts_json="$(api_call GET /api/accounts)"
account_ids="$(echo "$accounts_json" | python3 -c "import json,sys; data=json.load(sys.stdin); [print(a['id']) for a in data.get('accounts',[])]" 2>/dev/null || true)"
current_id="$(echo "$accounts_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('current_account_id',''))" 2>/dev/null || true)"
account_count="$(echo "$account_ids" | grep -c . 2>/dev/null || echo 0)"
echo "Accounts found: $account_count"
echo "Active account id: $current_id"

if [[ -n "$account_ids" ]]; then
  while IFS= read -r tid; do
    [[ -z "$tid" ]] && continue
    api_call POST /api/accounts/switch "{\"accountId\":\"$tid\"}" >/dev/null 2>&1 && echo "Switch account call [$tid]: OK" || echo "Switch account call [$tid] failed (continuing)."
    api_call GET "/api/accounts/$tid/quota" >/dev/null 2>&1 && echo "Quota fetch call [$tid]: OK" || echo "Quota fetch [$tid] failed (continuing)."
  done <<< "$account_ids"
fi

# Chat probe
chat_resp="$(api_call POST /v1/chat/completions '{"model":"gemini-3-flash","messages":[{"role":"user","content":"ping from live parity verify"}],"max_tokens":32}' 2>/dev/null || echo '')"
if [[ -n "$chat_resp" ]]; then
  content_len="$(echo "$chat_resp" | python3 -c "import json,sys; c=json.load(sys.stdin)['choices'][0]['message']['content']; print(len(c if isinstance(c,str) else ' '.join(c)))" 2>/dev/null || echo "?")"
  echo "Chat call: OK (content_length=$content_len)"
else
  echo "Chat call failed."
fi

# Extract outbound headers from log
[[ -f "$OUT_GEPHYR_PATH" ]] && rm -f "$OUT_GEPHYR_PATH"

log_file=""
if [[ -d "$HOME/.gephyr/logs" ]]; then
  log_file="$(ls -t "$HOME/.gephyr/logs"/app.log* 2>/dev/null | head -n 1 || true)"
fi

extract_outbound_records() {
  local source="$1" cutoff_ts="$2" out="$3"
  python3 - <<PYEOF "$source" "$cutoff_ts" "$out"
import json, sys, re
from datetime import datetime, timezone

source = sys.argv[1]
cutoff_str = sys.argv[2]
out_path = sys.argv[3]

ansi_re = re.compile(r'\x1B\[[0-9;]*[A-Za-z]')
pattern = re.compile(
    r'^(?P<ts>\S+)\s+DEBUG\s+.*google_outbound_headers\s+.*endpoint=(?:"(?P<ep1>[^"]+)"|(?P<ep2>\S+))\s+.*mode=(?:"(?P<m1>[^"]+)"|(?P<m2>\S+))\s+.*headers=(?P<hdr>\{.*\})$'
)

try:
    cutoff = datetime.fromisoformat(cutoff_str.replace("Z", "+00:00"))
except Exception:
    cutoff = datetime.now(timezone.utc)

count = 0
with open(source) as f, open(out_path, "a") as out_f:
    for raw in f:
        line = ansi_re.sub("", raw.strip())
        m = pattern.match(line)
        if not m:
            continue
        try:
            ts = datetime.fromisoformat(m.group("ts").replace("Z", "+00:00"))
        except Exception:
            continue
        if ts < cutoff:
            continue
        endpoint = m.group("ep1") or m.group("ep2")
        mode = m.group("m1") or m.group("m2")
        try:
            headers = json.loads(m.group("hdr"))
        except Exception:
            continue
        record = {"timestamp": m.group("ts"), "endpoint": endpoint, "mode": mode, "headers": headers}
        out_f.write(json.dumps(record) + "\n")
        count += 1

print(f"Extracted {count} outbound header records.")
PYEOF
}

if [[ -n "$log_file" ]]; then
  echo "Using log file: $log_file"
  extract_outbound_records "$log_file" "$cutoff" "$OUT_GEPHYR_PATH"
fi

if [[ ! -f "$OUT_GEPHYR_PATH" ]]; then
  echo "Falling back to gephyr process log output."
  extract_outbound_records "$gephyr_log" "$cutoff" "$OUT_GEPHYR_PATH"
fi

if [[ ! -f "$OUT_GEPHYR_PATH" ]] || [[ ! -s "$OUT_GEPHYR_PATH" ]]; then
  echo "ERROR: No gephyr_google_outbound_headers records were found after cutoff." >&2
  exit 1
fi

line_count="$(wc -l < "$OUT_GEPHYR_PATH")"
echo "Gephyr trace rows: $line_count"
python3 -c "
import json, sys
seen = set()
with open('$OUT_GEPHYR_PATH') as f:
    for line in f:
        ep = json.loads(line.strip()).get('endpoint','')
        if ep and ep not in seen:
            seen.add(ep)
            print(f'  endpoint: {ep}')
"

bash "$SCRIPT_DIR/diff-google-traces.sh" --known-good "$KNOWN_GOOD_PATH" --gephyr "$OUT_GEPHYR_PATH" --ignore-connection-header

txt="output/google_trace_diff_report.txt"
if [[ -f "$txt" ]]; then
  echo ""
  echo "Diff report head:"
  head -n 80 "$txt"
fi
