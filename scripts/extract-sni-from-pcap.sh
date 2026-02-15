#!/usr/bin/env bash
# Extracts TLS SNI (Server Name Indication) from pcap files.
# Uses tshark if available, falls back to ripgrep binary scan.
set -euo pipefail

PCAP_PATH=""
TOP=50

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/extract-sni-from-pcap.sh --pcap <path-or-glob> [options]

Options:
  --pcap <path>    REQUIRED. Path to pcap file or glob pattern
  --top <n>        Show top N SNIs. Default: 50
  -h, --help       Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pcap) PCAP_PATH="$2"; shift 2 ;;
    --top) TOP="$2"; shift 2 ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

[[ -n "$PCAP_PATH" ]] || { echo "ERROR: --pcap is required." >&2; show_usage; exit 2; }

# Resolve glob to concrete files
pcaps=()
# shellcheck disable=SC2086
for f in $PCAP_PATH; do
  [[ -f "$f" ]] && pcaps+=("$f")
done
[[ ${#pcaps[@]} -gt 0 ]] || { echo "ERROR: No files matched: $PCAP_PATH" >&2; exit 1; }

echo "PCAP input: $PCAP_PATH"
echo "Resolved files: ${#pcaps[@]}"
for p in "${pcaps[@]}"; do echo "  $p"; done

if command -v tshark >/dev/null 2>&1; then
  echo "Using tshark: $(command -v tshark)"

  all_sni=()
  for pcap in "${pcaps[@]}"; do
    echo ""
    echo "=== $pcap ==="

    # TLS SNI is in ClientHello (plaintext)
    sni_lines="$(tshark -r "$pcap" -Y "tls.handshake.extensions_server_name" \
      -T fields -E "separator=," -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null || true)"

    sni_list=()
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      sni="$(printf '%s' "$line" | cut -d',' -f3 | tr -d '[:space:]')"
      [[ -n "$sni" ]] && sni_list+=("$sni")
    done <<< "$sni_lines"

    if [[ ${#sni_list[@]} -eq 0 ]]; then
      echo "WARNING: No SNI extracted for this file. Possible reasons: no TLS ClientHello captured, QUIC not decoded, or ECH in use." >&2
      continue
    fi

    echo "Top SNI (this file):"
    printf '%s\n' "${sni_list[@]}" | sort | uniq -c | sort -rn | head -n "$TOP" | awk '{printf "%6d  %s\n", $1, $2}'

    all_sni+=("${sni_list[@]}")
  done

  if [[ ${#pcaps[@]} -gt 1 && ${#all_sni[@]} -gt 0 ]]; then
    echo ""
    echo "=== Aggregated Top SNI (all files) ==="
    printf '%s\n' "${all_sni[@]}" | sort | uniq -c | sort -rn | head -n "$TOP" | awk '{printf "%6d  %s\n", $1, $2}'
  fi

  exit 0
fi

echo "WARNING: tshark not found. Install Wireshark (include tshark) or add it to PATH." >&2
echo "Fallback: scanning binary for hostname-like strings (best-effort)."
echo ""

command -v rg >/dev/null 2>&1 || { echo "ERROR: Neither tshark nor rg available for fallback." >&2; exit 1; }

patterns=(
  "[a-z0-9][a-z0-9.-]{1,253}\\.googleapis\\.com"
  "[a-z0-9][a-z0-9.-]{1,253}\\.google\\.com"
  "[a-z0-9][a-z0-9.-]{1,253}\\.gstatic\\.com"
  "[a-z0-9][a-z0-9.-]{1,253}\\.goog"
  "[a-z0-9][a-z0-9.-]{1,253}\\.openai\\.com"
  "[a-z0-9][a-z0-9.-]{1,253}\\.chatgpt\\.com"
  "[a-z0-9][a-z0-9.-]{1,253}\\.anthropic\\.com"
)

hits=""
for pcap in "${pcaps[@]}"; do
  for pat in "${patterns[@]}"; do
    result="$(rg -a -o -i "$pat" "$pcap" -S 2>/dev/null || true)"
    [[ -n "$result" ]] && hits+="$result"$'\n'
  done
done

if [[ -z "$hits" ]]; then
  echo "WARNING: No hostname-like strings found in fallback scan." >&2
  exit 0
fi

echo "Top host-like strings:"
printf '%s' "$hits" | grep -v '^$' | sort | uniq -c | sort -rn | head -n "$TOP" | awk '{printf "%6d  %s\n", $1, $2}'
