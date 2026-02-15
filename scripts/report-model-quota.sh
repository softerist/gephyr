#!/usr/bin/env bash
# Reports per-account model quota for a target model in a running Gephyr instance.
set -euo pipefail

MODEL="gemini-2.5-pro"
BASE_URL="http://127.0.0.1:8045"
API_KEY_ARG=""
REFRESH=false
PROBE=false
PROMPT="quota check"

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/report-model-quota.sh [options]

Options:
  --model <name>     Target model. Default: gemini-2.5-pro
  --base-url <url>   Default: http://127.0.0.1:8045
  --api-key <key>    API key (or set API_KEY env var)
  --refresh          Refresh quota per account before reporting
  --probe            Send one probe request against the target model
  --prompt <text>    Prompt used for --probe. Default: "quota check"
  -h, --help         Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model) MODEL="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --api-key) API_KEY_ARG="$2"; shift 2 ;;
    --refresh) REFRESH=true; shift ;;
    --probe) PROBE=true; shift ;;
    --prompt) PROMPT="$2"; shift 2 ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required." >&2; exit 1; }

# Resolve API key
resolve_api_key() {
  [[ -n "$API_KEY_ARG" ]] && { echo "$API_KEY_ARG"; return; }
  [[ -n "${API_KEY:-}" ]] && { echo "$API_KEY"; return; }
  local config_path="$HOME/.gephyr/config.json"
  if [[ -f "$config_path" ]]; then
    local key
    key="$(python3 -c "import json; print(json.load(open('$config_path')).get('proxy',{}).get('api_key',''))" 2>/dev/null || true)"
    [[ -n "$key" ]] && { echo "$key"; return; }
  fi
  echo "ERROR: Config not found or proxy.api_key missing. Provide --api-key explicitly." >&2
  exit 1
}

RESOLVED_KEY="$(resolve_api_key)"

api_get() {
  curl -sS -H "Authorization: Bearer $RESOLVED_KEY" --max-time 30 "$BASE_URL$1"
}

api_post() {
  local path="$1" body="$2"
  curl -sS -w '\n%{http_code}' \
    -H "Authorization: Bearer $RESOLVED_KEY" \
    -H "Content-Type: application/json" \
    -X POST -d "$body" --max-time 120 \
    "$BASE_URL$path" 2>/dev/null || echo -e '\n000'
}

echo -e "\033[36mFetching accounts from $BASE_URL ...\033[0m"
account_json="$(api_get "/api/accounts")"

if [[ "$REFRESH" == "true" ]]; then
  echo -e "\033[36mRefreshing quota per account ...\033[0m"
  for acc_id in $(python3 -c "import json,sys; [print(a['id']) for a in json.loads(sys.argv[1]).get('accounts',[])]" "$account_json" 2>/dev/null); do
    api_get "/api/accounts/$acc_id/quota" >/dev/null 2>&1 || echo "WARNING: Quota refresh failed for $acc_id" >&2
  done
  account_json="$(api_get "/api/accounts")"
fi

probe_resp=""
probe_http=""
if [[ "$PROBE" == "true" ]]; then
  echo -e "\033[36mRunning one probe request for $MODEL ...\033[0m"
  probe_body="{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"$PROMPT\"}]}"
  full_resp="$(curl -sS -w '\n%{http_code}' -D - \
    -H "Authorization: Bearer $RESOLVED_KEY" \
    -H "Content-Type: application/json" \
    -X POST -d "$probe_body" --max-time 120 \
    "$BASE_URL/v1/chat/completions" 2>/dev/null || echo -e '\n000')"
  probe_http="$(printf '%s' "$full_resp" | tail -n 1)"
  probe_resp="$(printf '%s' "$full_resp" | sed '$d')"
fi

mkdir -p output
stamp="$(date +%Y-%m-%d_%H%M%S)"
out_json="output/model_quota_report_${stamp}.json"

python3 - <<PY "$account_json" "$MODEL" "$PROBE" "$probe_resp" "$probe_http" "$out_json" "$BASE_URL"
import json, sys
from datetime import datetime, timezone

account_json = sys.argv[1]
target_raw = sys.argv[2]
do_probe = sys.argv[3] == "true"
probe_resp = sys.argv[4]
probe_http = sys.argv[5]
out_json = sys.argv[6]
base_url = sys.argv[7]

def normalize_model(name):
    if not name:
        return ""
    return name.strip().lower().replace("models/", "")

def parse_reset_seconds(reset_time):
    if not reset_time:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(reset_time.replace("Z", "+00:00"))
        sec = int((dt - datetime.now(timezone.utc)).total_seconds())
        return max(0, sec)
    except Exception:
        return None

target = normalize_model(target_raw)
data = json.loads(account_json or "{}")
accounts = data.get("accounts", [])

rows = []
for acc in accounts:
    quota_models = []
    if acc.get("quota") and acc["quota"].get("models"):
        quota_models = acc["quota"]["models"]

    matched = None
    for m in quota_models:
        if normalize_model(m.get("name","")) == target:
            matched = m
            break

    alternatives = sorted(
        [m for m in quota_models if m.get("percentage",0) > 0 and normalize_model(m.get("name","")) != target],
        key=lambda x: -x.get("percentage",0)
    )[:3]

    rows.append({
        "account_id": acc.get("id",""),
        "email": acc.get("email",""),
        "disabled": bool(acc.get("disabled")),
        "proxy_disabled": bool(acc.get("proxy_disabled")),
        "target_model": target,
        "target_present": matched is not None,
        "target_percentage": int(matched["percentage"]) if matched else None,
        "target_reset_time": matched.get("reset_time") if matched else None,
        "target_reset_seconds": parse_reset_seconds(matched.get("reset_time")) if matched else None,
        "alternatives": [f"{m['name']}:{m['percentage']}%" for m in alternatives],
        "protected_models": acc.get("protected_models", []),
        "quota_last_updated": acc["quota"].get("last_updated") if acc.get("quota") else None,
        "subscription_tier": acc["quota"].get("subscription_tier") if acc.get("quota") else None,
    })

eligible = [r for r in rows if not r["disabled"] and not r["proxy_disabled"] and (r["target_percentage"] or 0) > 0]

summary = {
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "base_url": base_url,
    "target_model": target,
    "accounts_total": len(rows),
    "accounts_with_target_quota": len([r for r in rows if r["target_present"] and (r["target_percentage"] or 0) > 0]),
    "eligible_accounts_with_target_quota": len(eligible),
    "all_target_zero_or_missing": len(eligible) == 0,
}

probe_result = None
if do_probe:
    probe_result = {"status": int(probe_http) if probe_http.isdigit() else -1}

report = {"summary": summary, "accounts": rows, "probe": probe_result}
with open(out_json, "w") as f:
    json.dump(report, f, indent=2)

# Print table
print("")
print("\033[32mTarget model report:\033[0m")
print(f"{'Email':<35} {'%':>4} {'Reset Secs':>10} {'Disabled':>8} {'ProxyOff':>8}")
print(f"{'-'*35} {'----':>4} {'----------':>10} {'--------':>8} {'--------':>8}")
for r in rows:
    pct = str(r["target_percentage"]) if r["target_percentage"] is not None else "-"
    rs = str(r["target_reset_seconds"]) if r["target_reset_seconds"] is not None else "-"
    print(f"{r['email']:<35} {pct:>4} {rs:>10} {str(r['disabled']):>8} {str(r['proxy_disabled']):>8}")

print("")
print(f"Summary: {json.dumps(summary)}")
if probe_result:
    print(f"Probe:   {json.dumps(probe_result)}")
print(f"Saved:   {out_json}")
PY
