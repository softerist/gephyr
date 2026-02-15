#!/usr/bin/env bash
# Validates observed Google endpoints in a trace JSONL against an allowlist.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TRACE_PATH=""
ALLOWLIST_PATH="scripts/allowlists/antigravity_google_endpoints_default_chat.txt"
OUT_JSON="output/antigravity_allowed_endpoint_validation.json"
OUT_TEXT="output/antigravity_allowed_endpoint_validation.txt"
NO_THROW=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/validate-antigravity-allowed-google-endpoints.sh --trace <path> [options]

Options:
  --trace <path>         REQUIRED. Path to JSONL trace file
  --allowlist <path>     Default: scripts/allowlists/antigravity_google_endpoints_default_chat.txt
  --out-json <path>      Default: output/antigravity_allowed_endpoint_validation.json
  --out-text <path>      Default: output/antigravity_allowed_endpoint_validation.txt
  --no-throw             Do not exit with error on validation failure
  -h, --help             Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --trace) TRACE_PATH="$2"; shift 2 ;;
    --allowlist) ALLOWLIST_PATH="$2"; shift 2 ;;
    --out-json) OUT_JSON="$2"; shift 2 ;;
    --out-text) OUT_TEXT="$2"; shift 2 ;;
    --no-throw) NO_THROW=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

cd "$REPO_ROOT"

[[ -n "$TRACE_PATH" ]] || { echo "ERROR: --trace is required." >&2; show_usage; exit 2; }
[[ -f "$TRACE_PATH" ]] || { echo "ERROR: Trace file not found: $TRACE_PATH" >&2; exit 1; }
[[ -f "$ALLOWLIST_PATH" ]] || { echo "ERROR: Allowlist file not found: $ALLOWLIST_PATH" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required for this validator." >&2; exit 1; }

mkdir -p "$(dirname "$OUT_JSON")" "$(dirname "$OUT_TEXT")"

python3 - <<'PY' "$TRACE_PATH" "$ALLOWLIST_PATH" "$OUT_JSON" "$OUT_TEXT" "$NO_THROW"
import json, sys, re
from datetime import datetime
from urllib.parse import urlparse

trace_path = sys.argv[1]
allowlist_path = sys.argv[2]
out_json = sys.argv[3]
out_text = sys.argv[4]
no_throw = sys.argv[5] == "true"

def is_google_endpoint(ep):
    if not ep:
        return False
    return bool(re.match(r'(?i)^https?://[^/]*(googleapis\.com|google\.com)(?::\d+)?/', ep))

def normalize_endpoint(ep):
    if not ep:
        return ep
    try:
        u = urlparse(ep)
    except Exception:
        return ep
    host = u.hostname.lower() if u.hostname else ""
    if host == "daily-cloudcode-pa.googleapis.com":
        host = "cloudcode-pa.googleapis.com"
    port_part = "" if u.port in (None, 80, 443) else f":{u.port}"
    path_query = u.path
    if u.query:
        path_query += "?" + u.query
    return f"{u.scheme.lower()}://{host}{port_part}{path_query}"

# Load allowlist
with open(allowlist_path) as f:
    allowed = set()
    for line in f:
        line = line.strip()
        if line and not line.startswith("#"):
            allowed.add(normalize_endpoint(line))

# Parse trace
observed_google = set()
with open(trace_path) as f:
    for raw in f:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        ep = obj.get("endpoint", "")
        if not ep:
            continue
        norm = normalize_endpoint(ep)
        if is_google_endpoint(norm):
            observed_google.add(norm)

# Remove capture self-test noise
noise = normalize_endpoint("https://oauth2.googleapis.com/tokeninfo?access_token=%3Credacted%3E")
observed_google.discard(noise)

unknown = sorted(e for e in observed_google if e not in allowed)
missing = sorted(e for e in allowed if e not in observed_google)
observed_allowed = sorted(e for e in observed_google if e in allowed)
pass_result = len(unknown) == 0

result = {
    "generated_at": datetime.now().isoformat(),
    "trace_path": trace_path,
    "allowlist_path": allowlist_path,
    "allowed_count": len(allowed),
    "observed_google_count": len(observed_google),
    "observed_allowed_count": len(observed_allowed),
    "unknown_google_endpoints": unknown,
    "missing_allowed_endpoints": missing,
    "observed_allowed_endpoints": observed_allowed,
    "pass": pass_result,
}

with open(out_json, "w") as f:
    json.dump(result, f, indent=2)

lines = []
lines.append("Antigravity Allowed Google Endpoint Validation")
lines.append(f"Generated: {result['generated_at']}")
lines.append(f"Trace: {trace_path}")
lines.append(f"Allowlist: {allowlist_path}")
lines.append(f"Allowed endpoints: {len(allowed)}")
lines.append(f"Observed Google endpoints: {len(observed_google)}")
lines.append(f"Observed allowed endpoints: {len(observed_allowed)}")
lines.append(f"Pass: {pass_result}")
lines.append("")
lines.append("Unknown Google endpoints:")
if not unknown:
    lines.append("  (none)")
else:
    for u in unknown:
        lines.append(f"  {u}")
lines.append("")
lines.append("Missing allowlist endpoints (informational):")
if not missing:
    lines.append("  (none)")
else:
    for m in missing:
        lines.append(f"  {m}")

with open(out_text, "w") as f:
    f.write("\n".join(lines) + "\n")

print("Validation report written:")
print(f"  {out_text}")
print(f"  {out_json}")
print(f"Pass: {pass_result}")

if not no_throw and not pass_result:
    print(f"ERROR: Unexpected Google endpoints detected. See: {out_text}", file=sys.stderr)
    sys.exit(1)
PY
