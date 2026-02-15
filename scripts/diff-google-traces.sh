#!/usr/bin/env bash
# Diffs Google outbound headers between Gephyr proxy and known-good captures.
# Supports JSONL, HAR, and SAZ (Fiddler archive) input formats.
set -euo pipefail

GEPHYR_PATH="output/gephyr_google_outbound_headers.jsonl"
KNOWN_GOOD_PATH=""
OUT_JSON="output/google_trace_diff_report.json"
OUT_TEXT="output/google_trace_diff_report.txt"
IGNORE_HEADERS="content-length"
IGNORE_CONNECTION_HEADER=false
IGNORE_DEVICE_HEADERS=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/diff-google-traces.sh --known-good <path> [options]

Options:
  --gephyr <path>              Gephyr trace JSONL. Default: output/gephyr_google_outbound_headers.jsonl
  --known-good <path>          REQUIRED. Path to known-good trace (JSONL, HAR, or SAZ)
  --out-json <path>            Default: output/google_trace_diff_report.json
  --out-text <path>            Default: output/google_trace_diff_report.txt
  --ignore-headers <csv>       Comma-separated headers to ignore. Default: content-length
  --ignore-connection-header   Also ignore the 'connection' header
  --ignore-device-headers      Also ignore device-id headers (x-machine-id, x-mac-machine-id, etc.)
  -h, --help                   Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gephyr) GEPHYR_PATH="$2"; shift 2 ;;
    --known-good) KNOWN_GOOD_PATH="$2"; shift 2 ;;
    --out-json) OUT_JSON="$2"; shift 2 ;;
    --out-text) OUT_TEXT="$2"; shift 2 ;;
    --ignore-headers) IGNORE_HEADERS="$2"; shift 2 ;;
    --ignore-connection-header) IGNORE_CONNECTION_HEADER=true; shift ;;
    --ignore-device-headers) IGNORE_DEVICE_HEADERS=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

[[ -n "$KNOWN_GOOD_PATH" ]] || { echo "ERROR: --known-good is required." >&2; show_usage; exit 2; }
[[ -f "$GEPHYR_PATH" ]] || { echo "ERROR: Gephyr trace not found: $GEPHYR_PATH" >&2; exit 1; }
[[ -f "$KNOWN_GOOD_PATH" ]] || { echo "ERROR: Known-good trace not found: $KNOWN_GOOD_PATH" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required." >&2; exit 1; }

mkdir -p "$(dirname "$OUT_JSON")" "$(dirname "$OUT_TEXT")"

python3 - <<'PY' "$GEPHYR_PATH" "$KNOWN_GOOD_PATH" "$OUT_JSON" "$OUT_TEXT" "$IGNORE_HEADERS" "$IGNORE_CONNECTION_HEADER" "$IGNORE_DEVICE_HEADERS"
import json, sys, re, os, zipfile
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict

gephyr_path = sys.argv[1]
known_good_path = sys.argv[2]
out_json = sys.argv[3]
out_text = sys.argv[4]
ignore_headers_csv = sys.argv[5]
ignore_connection = sys.argv[6] == "true"
ignore_device = sys.argv[7] == "true"

def is_google(ep):
    if not ep: return False
    return bool(re.match(r'(?i)^https?://[^/]*(googleapis\.com|google\.com)(?::\d+)?/', ep))

def normalize_endpoint(ep):
    if not ep: return ep
    try:
        u = urlparse(ep)
    except Exception: return ep
    host = (u.hostname or "").lower()
    if host == "daily-cloudcode-pa.googleapis.com":
        host = "cloudcode-pa.googleapis.com"
    port_part = "" if u.port in (None, 80, 443) else f":{u.port}"
    pq = u.path
    if u.query: pq += "?" + u.query
    return f"{u.scheme.lower()}://{host}{port_part}{pq}"

def is_noise(ep):
    if not ep: return False
    return bool(re.match(r'(?i)^https?://oauth2\.googleapis\.com/tokeninfo(?:\?|$)', ep))

def load_jsonl(path):
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                records.append(json.loads(line))
            except Exception: continue
    return records

def load_har(path):
    with open(path) as f:
        har = json.load(f)
    records = []
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        url = req.get("url", "")
        if not url: continue
        headers = {}
        for h in req.get("headers", []):
            name = h.get("name", "")
            if name: headers[name.lower()] = h.get("value", "")
        if is_google(url):
            records.append({"endpoint": url, "headers": headers, "mode": "known_good"})
    return records

def load_saz(path):
    records = []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not re.match(r'raw/\d+_c\.txt$', name): continue
            with z.open(name) as f:
                text = f.read().decode("utf-8", errors="replace")
            lines = text.splitlines()
            if not lines: continue
            first = lines[0].strip()
            m = re.match(r'^([A-Z]+)\s+(\S+)\s+HTTP/\d+\.\d+$', first)
            if not m: continue
            method, target = m.group(1), m.group(2)
            if method == "CONNECT": continue
            headers = {}
            for line in lines[1:]:
                if not line.strip(): break
                hm = re.match(r'^([^:]+):\s*(.*)$', line)
                if hm:
                    headers[hm.group(1).strip().lower()] = hm.group(2).strip()
            ep = target
            if not re.match(r'^https?://', ep):
                host = headers.get("host", "")
                if host and ep.startswith("/"):
                    scheme = "https" if ":443" in host else "http"
                    ep = f"{scheme}://{host}{ep}"
            if is_google(ep):
                records.append({"endpoint": ep, "headers": headers, "mode": "known_good"})
    return records

def load_records(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".har": return load_har(path)
    if ext == ".saz": return load_saz(path)
    return load_jsonl(path)

def build_ignore_set():
    s = set()
    for h in ignore_headers_csv.split(","):
        h = h.strip().lower()
        if h: s.add(h)
    if ignore_connection: s.add("connection")
    if ignore_device:
        s.update(["x-machine-id", "x-mac-machine-id", "x-dev-device-id", "x-sqm-id"])
    return s

BLOCKED_PREFIXES = ["sec-"]
BLOCKED_EXACT = {"origin","referer","cookie","x-real-ip","connection","transfer-encoding",
                 "upgrade","keep-alive","proxy-authenticate","proxy-authorization","te","trailers"}
def get_blocked(headers):
    blocked = set()
    for h in headers:
        if h in BLOCKED_EXACT or any(h.startswith(p) for p in BLOCKED_PREFIXES) or h.startswith("x-forwarded-"):
            blocked.add(h)
    return sorted(blocked)

def endpoint_stats(records):
    by_ep = defaultdict(lambda: {"count": 0, "headers": set()})
    for r in records:
        ep = normalize_endpoint(r.get("endpoint", ""))
        if not ep or is_noise(ep): continue
        by_ep[ep]["count"] += 1
        hdrs = r.get("headers", {})
        if isinstance(hdrs, dict):
            for k in hdrs: by_ep[ep]["headers"].add(k.lower())
    return by_ep

gephyr = load_records(gephyr_path)
known = load_records(known_good_path)
known_is_empty = len(known) == 0
if known_is_empty:
    print("WARNING: No Google HTTP requests parsed from known-good file.", file=sys.stderr)

ignore_set = build_ignore_set()
g_stats = endpoint_stats(gephyr)
k_stats = endpoint_stats(known)
all_eps = sorted(set(list(g_stats.keys()) + list(k_stats.keys())))

comparisons = []
for ep in all_eps:
    gc = g_stats[ep]["count"] if ep in g_stats else 0
    kc = k_stats[ep]["count"] if ep in k_stats else 0
    gh = sorted(g_stats[ep]["headers"]) if ep in g_stats else []
    kh = sorted(k_stats[ep]["headers"]) if ep in k_stats else []
    kh_filtered = sorted(h for h in kh if h not in ignore_set)
    gh_filtered = sorted(h for h in gh if h not in ignore_set)
    missing = sorted(h for h in kh_filtered if h not in gh_filtered)
    extra = sorted(h for h in gh_filtered if h not in kh_filtered)
    blocked = get_blocked(gh)

    if kc > 0 and gc == 0:
        cls = "missing_endpoint_not_exercised"
    elif kc > 0 and gc > 0 and missing:
        cls = "missing_headers_on_exercised_endpoint"
    elif kc == 0 and gc > 0:
        cls = "extra_endpoint_in_gephyr"
        missing, extra = [], []
    else:
        cls = "matched_or_extra_only"

    comparisons.append({
        "endpoint": ep, "classification": cls,
        "known_request_count": kc, "gephyr_request_count": gc,
        "known_header_names": kh, "gephyr_header_names": gh,
        "missing_in_gephyr": missing, "extra_in_gephyr": extra,
        "blocked_in_gephyr": blocked,
    })

cls_summary = defaultdict(int)
for c in comparisons: cls_summary[c["classification"]] += 1
cls_list = [{"classification": k, "count": v} for k, v in sorted(cls_summary.items())]

report = {
    "generated_at": datetime.now().isoformat(),
    "gephyr_path": gephyr_path,
    "known_good_path": known_good_path,
    "gephyr_records": len(gephyr),
    "known_good_records": len(known),
    "endpoint_count": len(all_eps),
    "ignored_headers": sorted(ignore_set),
    "classification_summary": cls_list,
    "endpoints": comparisons,
}
with open(out_json, "w") as f:
    json.dump(report, f, indent=2)

lines = []
lines.append("Google Trace Diff Report")
lines.append(f"Generated: {report['generated_at']}")
lines.append(f"Gephyr records: {len(gephyr)}")
lines.append(f"Known-good records: {len(known)}")
lines.append(f"Endpoints compared: {len(all_eps)}")
lines.append(f"Ignored headers in diff: {', '.join(sorted(ignore_set))}")
lines.append("Classification summary:")
for c in cls_list:
    lines.append(f"  {c['classification']}: {c['count']}")
lines.append("")
if known_is_empty:
    lines.append("WARNING: No known-good Google HTTP requests were parsed.")
    lines.append("For Fiddler SAZ captures, enable HTTPS decryption and re-capture.")
    lines.append("")
lines.append("")
for e in comparisons:
    lines.append(f"Endpoint: {e['endpoint']}")
    lines.append(f"  classification: {e['classification']}")
    lines.append(f"  exercised_known_good: {e['known_request_count']}")
    lines.append(f"  exercised_gephyr: {e['gephyr_request_count']}")
    if e["classification"] == "extra_endpoint_in_gephyr":
        lines.append("  missing_in_gephyr: ")
        lines.append("  extra_in_gephyr: ")
        lines.append("  note: endpoint not present in known-good capture; recapture known-good to diff headers.")
    else:
        lines.append(f"  missing_in_gephyr: {', '.join(e['missing_in_gephyr'])}")
        lines.append(f"  extra_in_gephyr: {', '.join(e['extra_in_gephyr'])}")
    lines.append(f"  blocked_in_gephyr: {', '.join(e['blocked_in_gephyr'])}")
    lines.append("")
with open(out_text, "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Saved JSON report: {out_json}")
print(f"Saved text report: {out_text}")
PY
