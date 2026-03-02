#!/usr/bin/env bash
# Attributes TLS SNI values to language_server_windows_x64 remote IPs.
# Linux/Bash equivalent of attribute-ls-sni.ps1.
set -euo pipefail

PCAP_PATH=""
CONNECTIONS_CSV_PATH=""
OUT_BASE="output/parity/official/ls_sni_attribution"
TOP=50
RESOLVE_PTR=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/attribute-ls-sni.sh --pcap-path <path> --connections-csv-path <path> [options]

Options:
  --pcap-path <path>           Required. Path to .pcapng file.
  --connections-csv-path <path> Required. Path to connections CSV.
  --out-base <path>            Default: output/parity/official/ls_sni_attribution
  --top <n>                    Default: 50
  --resolve-ptr                Resolve PTR for top IPs (requires network)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pcap-path) PCAP_PATH="$2"; shift 2 ;;
    --connections-csv-path) CONNECTIONS_CSV_PATH="$2"; shift 2 ;;
    --out-base) OUT_BASE="$2"; shift 2 ;;
    --top) TOP="$2"; shift 2 ;;
    --resolve-ptr) RESOLVE_PTR=true; shift ;;
    *) echo "Error: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

[[ -n "$PCAP_PATH" ]] || { echo "Error: --pcap-path is required." >&2; exit 1; }
[[ -n "$CONNECTIONS_CSV_PATH" ]] || { echo "Error: --connections-csv-path is required." >&2; exit 1; }

command -v tshark >/dev/null 2>&1 || { echo "Error: tshark is required. Please install wireshark-cli/tshark." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 is required." >&2; exit 1; }

OUT_DIR=$(dirname "$OUT_BASE")
mkdir -p "$OUT_DIR"

echo "PCAP: $PCAP_PATH"
echo "CSV:  $CONNECTIONS_CSV_PATH"

# Run tshark to extract TLS SNI data
TSHARK_OUT=$(mktemp)
trap 'rm -f "$TSHARK_OUT"' EXIT

echo "Running tshark extraction ..."
tshark -r "$PCAP_PATH" -Y "tls.handshake.extensions_server_name" -T fields -E "separator=," -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name > "$TSHARK_OUT" 2>/dev/null

echo "Processing data with Python ..."
python3 - <<PYEOF "$CONNECTIONS_CSV_PATH" "$TSHARK_OUT" "$OUT_BASE" "$TOP" "$RESOLVE_PTR"
import json, csv, sys, os, socket
from datetime import datetime, timezone
from collections import Counter

csv_path = sys.argv[1]
tshark_path = sys.argv[2]
out_base = sys.argv[3]
top_n = int(sys.argv[4])
resolve_ptr = sys.argv[5].lower() == 'true'

# 1. Load LS IPs from CSV
ls_ip_counts = Counter()
try:
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            addr = row.get('remote_address')
            port = row.get('remote_port')
            if addr and addr != '127.0.0.1' and port == '443':
                ls_ip_counts[addr] += 1
except Exception as e:
    print(f"Error reading CSV: {e}", file=sys.stderr)
    sys.exit(1)

ls_ip_set = set(ls_ip_counts.keys())

# 2. Process tshark output
rows = []
with open(tshark_path, 'r') as f:
    for line in f:
        parts = line.strip().split(',')
        if len(parts) < 4: continue
        dst_ip = parts[2]
        sni = parts[3]
        if sni and dst_ip in ls_ip_set:
            rows.append({'dst_ip': dst_ip, 'sni': sni})

# 3. Aggregations
sni_counter = Counter(r['sni'] for r in rows)
ip_sni_counter = Counter(f"{r['dst_ip']}, {r['sni']}" for r in rows)

sni_top = [{'count': c, 'name': n} for n, c in sni_counter.most_common(top_n)]
ip_top = [{'count': ls_ip_counts[ip], 'ip': ip} for ip, count in ls_ip_counts.most_common(top_n)]
ip_sni_top = [{'count': c, 'name': n} for n, c in ip_sni_counter.most_common(top_n)]

sni_ips = {r['dst_ip'] for r in rows}
ips_without_sni = [ip for ip in ls_ip_counts.keys() if ip not in sni_ips]

report = {
    "schema_version": "gephyr_ls_sni_attribution_v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "inputs": {
        "pcap_path": os.path.abspath("$PCAP_PATH"),
        "connections_csv_path": os.path.abspath(csv_path)
    },
    "totals": {
        "ls_connection_rows_scoped": sum(ls_ip_counts.values()),
        "ls_unique_remote_ips": len(ls_ip_counts),
        "tls_clienthello_sni_rows_on_ls_ips": len(rows),
        "ls_ips_without_observed_sni": len(ips_without_sni)
    },
    "top": {
        "ls_remote_ips": ip_top,
        "sni": sni_top,
        "ip_sni_pairs": ip_sni_top
    },
    "ls_ips_without_sni": sorted(ips_without_sni)
}

if resolve_ptr:
    ptr_rows = []
    for item in ip_top:
        ip = item['ip']
        try:
            name, alias, addresslist = socket.gethostbyaddr(ip)
            ptr = name
        except Exception:
            ptr = None
        ptr_rows.append({'ip': ip, 'ptr': ptr})
    report['ptr'] = ptr_rows

# 4. Write output
with open(f"{out_base}.json", 'w') as f:
    json.dump(report, f, indent=2)

with open(f"{out_base}.txt", 'w') as f:
    f.write("LS SNI Attribution\n")
    f.write(f"Generated: {report['generated_at']}\n")
    f.write(f"PCAP: {report['inputs']['pcap_path']}\n")
    f.write(f"CSV:  {report['inputs']['connections_csv_path']}\n\n")
    f.write("Totals:\n")
    for k, v in report['totals'].items():
        f.write(f"  {k}={v}\n")
    f.write("\nTop LS remote IPs:\n")
    for x in ip_top:
        f.write(f"  {x['count']}  {x['ip']}\n")
    f.write("\nTop SNI on LS IPs:\n")
    for x in sni_top:
        f.write(f"  {x['count']}  {x['name']}\n")
    f.write("\nTop IP+SNI pairs:\n")
    for x in ip_sni_top:
        f.write(f"  {x['count']}  {x['name']}\n")
    f.write("\nLS IPs without observed SNI:\n")
    if not ips_without_sni:
        f.write("  (none)\n")
    else:
        for ip in ips_without_sni:
            f.write(f"  {ip}\n")

print(f"Attribution report written to {out_base}.json and .txt")
PYEOF
