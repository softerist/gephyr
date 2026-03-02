#!/usr/bin/env bash
# Correlates MITM capture JSONL with language-server TCP connection traces.
# Linux/Bash equivalent of correlate-mitm-ls-timeline.ps1.
set -euo pipefail

MITM_PATH="output/known_good.discovery.jsonl"
CONNECTIONS_CSV_PATH="output/ls_generation_probe.language_server_windows_x64.connections.csv"
OUT_BASE="output/parity/official/live.timeline_correlation"
BUCKET_SECONDS=1
TOP=20
PROXY_PORT=8891
INCLUDE_LOOPBACK=false
RESOLVE_PTR=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/correlate-mitm-ls-timeline.sh [options]

Options:
  --mitm-path <path>           Default: output/known_good.discovery.jsonl
  --connections-csv-path <path> Default: output/ls_generation_probe.language_server_windows_x64.connections.csv
  --out-base <path>            Default: output/parity/official/live.timeline_correlation
  --bucket-seconds <n>         Default: 1
  --top <n>                    Default: 20
  --proxy-port <n>             Default: 8891
  --include-loopback           Include non-proxy loopback connections
  --resolve-ptr                Resolve PTR for top IPs
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mitm-path) MITM_PATH="$2"; shift 2 ;;
    --connections-csv-path) CONNECTIONS_CSV_PATH="$2"; shift 2 ;;
    --out-base) OUT_BASE="$2"; shift 2 ;;
    --bucket-seconds) BUCKET_SECONDS="$2"; shift 2 ;;
    --top) TOP="$2"; shift 2 ;;
    --proxy-port) PROXY_PORT="$2"; shift 2 ;;
    --include-loopback) INCLUDE_LOOPBACK=true; shift ;;
    --resolve-ptr) RESOLVE_PTR=true; shift ;;
    *) echo "Error: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { echo "Error: python3 is required." >&2; exit 1; }

mkdir -p "$(dirname "$OUT_BASE")"

python3 - <<PYEOF "$MITM_PATH" "$CONNECTIONS_CSV_PATH" "$OUT_BASE" "$BUCKET_SECONDS" "$TOP" "$PROXY_PORT" "$INCLUDE_LOOPBACK" "$RESOLVE_PTR"
import json, csv, sys, os, socket, re
from datetime import datetime, timezone
from collections import Counter, defaultdict

mitm_path = sys.argv[1]
conn_path = sys.argv[2]
out_base = sys.argv[3]
bucket_seconds = int(sys.argv[4])
top_n = int(sys.argv[5])
proxy_port = int(sys.argv[6])
include_loopback = sys.argv[7].lower() == 'true'
resolve_ptr = sys.argv[8].lower() == 'true'

def test_google_host(h):
    h = h.lower()
    return h == "google.com" or h == "www.google.com" or h.endswith(".google.com") or h.endswith(".googleapis.com")

def test_openai_chat_host(h):
    h = h.lower()
    return h in ["chatgpt.com", "chat.openai.com", "ab.chatgpt.com"]

def test_generation_endpoint(h, p):
    h = h.lower()
    p = p.lower()
    if not test_google_host(h): return False
    return any(x in p for x in ["streamgeneratecontent", "streamgeneratechat", "generatecontent", "generatechat", "generatecode", "completecode", "internalatomicagenticchat", "tabchat"])

def get_bucket_epoch(ts, size):
    return (int(ts.timestamp()) // size) * size

def to_iso(ts):
    return ts.isoformat() if ts else None

def resolve_ptr_func(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

buckets = defaultdict(lambda: {
    "mitm_total": 0, "mitm_google": 0, "mitm_cloudcode": 0, "mitm_oauth": 0,
    "mitm_generation": 0, "mitm_openai_chat": 0, "mitm_other": 0,
    "mitm_hosts": Counter(), "mitm_generation_endpoints": set(),
    "ls_rows": 0, "ls_remote_endpoints": set(), "ls_public_remote_endpoints": set(),
    "ls_proxy_remote_endpoints": set()
})

mitm_min_ts, mitm_max_ts = None, None
ls_min_ts, ls_max_ts = None, None

mitm_counts = Counter()
mitm_host_counts = Counter()
mitm_endpoint_counts = Counter()
mitm_ua_counts = Counter()

# 1. Process MITM
print(f"Reading MITM: {mitm_path}")
if os.path.exists(mitm_path):
    with open(mitm_path) as f:
        for line in f:
            try:
                obj = json.loads(line)
                ts = datetime.fromisoformat(obj['timestamp'].replace('Z', '+00:00'))
                if mitm_min_ts is None or ts < mitm_min_ts: mitm_min_ts = ts
                if mitm_max_ts is None or ts > mitm_max_ts: mitm_max_ts = ts
                
                ep = obj['endpoint']
                h = ep.split('//')[-1].split('/')[0].split(':')[0].lower()
                p = '/' + ep.split('//')[-1].split('/', 1)[-1] if '/' in ep.split('//')[-1] else '/'
                
                is_google = test_google_host(h)
                is_generation = test_generation_endpoint(h, p)
                is_openai = test_openai_chat_host(h)
                
                mitm_counts['total'] += 1
                if is_google: mitm_counts['google'] += 1
                if is_generation: mitm_counts['generation'] += 1
                if is_openai: mitm_counts['openai'] += 1
                
                mitm_host_counts[h] += 1
                mitm_endpoint_counts[ep] += 1
                ua = obj.get('headers', {}).get('user-agent', '<missing>')
                mitm_ua_counts[ua] += 1

                epoch = get_bucket_epoch(ts, bucket_seconds)
                b = buckets[epoch]
                b['mitm_total'] += 1
                if is_google: b['mitm_google'] += 1
                if is_generation: 
                    b['mitm_generation'] += 1
                    b['mitm_generation_endpoints'].add(f"{obj['method']} {p}")
                if is_openai: b['mitm_openai_chat'] += 1
                b['mitm_hosts'][h] += 1
            except: continue

# 2. Process Connections
print(f"Reading Connections: {conn_path}")
ls_remote_ip_counts = Counter()
ls_remote_endpoint_counts = Counter()
ls_rows_raw, ls_rows_scoped, ls_proxy_rows = 0, 0, 0

if os.path.exists(conn_path):
    with open(conn_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            ls_rows_raw += 1
            try:
                ts = datetime.fromisoformat(row['timestamp_utc'].replace('Z', '+00:00'))
                addr = row['remote_address']
                port = int(row['remote_port'])
                
                is_loopback = addr in ['127.0.0.1', '::1', 'localhost']
                is_proxy = is_loopback and port == proxy_port
                
                if not include_loopback and is_loopback and not is_proxy: continue
                
                ls_rows_scoped += 1
                if is_proxy: ls_proxy_rows += 1
                
                if ls_min_ts is None or ts < ls_min_ts: ls_min_ts = ts
                if ls_max_ts is None or ts > ls_max_ts: ls_max_ts = ts
                
                ls_remote_ip_counts[addr] += 1
                ep_key = f"{addr}:{port}"
                ls_remote_endpoint_counts[ep_key] += 1
                
                epoch = get_bucket_epoch(ts, bucket_seconds)
                b = buckets[epoch]
                b['ls_rows'] += 1
                b['ls_remote_endpoints'].add(ep_key)
                if not is_loopback: b['ls_public_remote_endpoints'].add(ep_key)
                if is_proxy: b['ls_proxy_remote_endpoints'].add(ep_key)
            except: continue

# 3. Analyze
timeline = []
for epoch in sorted(buckets.keys()):
    b = buckets[epoch]
    timeline.append({
        "bucket_start_utc": datetime.fromtimestamp(epoch, timezone.utc).isoformat(),
        "mitm_total": b['mitm_total'],
        "mitm_google": b['mitm_google'],
        "mitm_generation": b['mitm_generation'],
        "mitm_openai_chat": b['mitm_openai_chat'],
        "mitm_top_hosts": [{'name': n, 'count': c} for n, c in b['mitm_hosts'].most_common(5)],
        "mitm_generation_endpoints": sorted(list(b['mitm_generation_endpoints'])),
        "ls_rows": b['ls_rows'],
        "ls_unique_public_remote_endpoints": len(b['ls_public_remote_endpoints']),
        "ls_unique_proxy_remote_endpoints": len(b['ls_proxy_remote_endpoints']),
        "signals": {
            "ls_public_without_google_mitm": len(b['ls_public_remote_endpoints']) > 0 and b['mitm_google'] == 0
        }
    })

overlap_start = max(mitm_min_ts, ls_min_ts) if mitm_min_ts and ls_min_ts else None
overlap_end = min(mitm_max_ts, ls_max_ts) if mitm_max_ts and ls_max_ts else None
overlap_seconds = (overlap_end - overlap_start).total_seconds() if overlap_start and overlap_end and overlap_end > overlap_start else 0

findings = []
if mitm_counts['generation'] == 0: findings.append({"code": "NO_GENERATION_ENDPOINT", "severity": "warning", "message": "No generation endpoint observed."})
if ls_proxy_rows == 0 and ls_rows_scoped > 0: findings.append({"code": "LS_NO_PROXY_PORT_ACTIVITY", "severity": "warning", "message": "No proxy port activity observed."})

report = {
    "schema_version": "gephyr_mitm_ls_timeline_correlation_v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "ranges": {
        "mitm_start_utc": to_iso(mitm_min_ts), "mitm_end_utc": to_iso(mitm_max_ts),
        "ls_start_utc": to_iso(ls_min_ts), "ls_end_utc": to_iso(ls_max_ts),
        "overlap_seconds": overlap_seconds
    },
    "totals": {
        "mitm_records_total": mitm_counts['total'],
        "mitm_google_records": mitm_counts['google'],
        "mitm_generation_records": mitm_counts['generation'],
        "ls_rows_total_raw": ls_rows_raw,
        "ls_rows_scoped": ls_rows_scoped,
        "ls_proxy_rows": ls_proxy_rows
    },
    "top": {
        "mitm_hosts": [{'name': n, 'count': c} for n, c in mitm_host_counts.most_common(top_n)],
        "ls_remote_ips": [{'name': n, 'count': c} for n, c in ls_remote_ip_counts.most_common(top_n)]
    },
    "findings": findings,
    "timeline_buckets": timeline
}

if resolve_ptr:
    for item in report['top']['ls_remote_ips']:
        item['ptr'] = resolve_ptr_func(item['name'])

with open(f"{out_base}.json", 'w') as f: json.dump(report, f, indent=2)
with open(f"{out_base}.txt", 'w') as f:
    f.write(f"Timeline Correlation Report\nGenerated: {report['generated_at']}\n\n")
    f.write(f"Overlap Seconds: {overlap_seconds}\n")
    f.write(f"MITM Records: {report['totals']['mitm_records_total']} (gen={report['totals']['mitm_generation_records']})\n")
    f.write(f"LS Rows: {report['totals']['ls_rows_scoped']} (proxy={report['totals']['ls_proxy_rows']})\n\n")
    f.write("Findings:\n")
    for find in findings: f.write(f"  [{find['severity']}] {find['message']}\n")

print(f"Report written to {out_base}.json and .txt")
PYEOF
