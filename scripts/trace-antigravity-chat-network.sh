#!/usr/bin/env bash
# Traces Antigravity Agent chat network traffic at the OS level.
# Linux equivalent of trace-antigravity-chat-network.ps1.
# Uses tcpdump (instead of pktmon) and ss (instead of Get-NetTCPConnection).
# Requires root/sudo for tcpdump.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PORT=8879
OUT_BASE=""
PROCESS_NAME="language_server_linux_x64"
POLL_INTERVAL_MS=500
PKT_SIZE=0
MAX_FILE_SIZE_MB=512
NO_TCPDUMP=false
NO_CONNECTION_POLL=false

show_usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/trace-antigravity-chat-network.sh [options]

Options:
  --port <n>                Proxy port. Default: 8879
  --out-base <path>         Output base name. Default: output/antigravity_chat_nettrace_<timestamp>
  --process-name <name>     Process to correlate. Default: language_server_linux_x64
  --poll-interval-ms <ms>   Connection poll interval. Default: 500
  --pkt-size <n>            Snap length (0=full). Default: 0
  --max-file-size-mb <n>    Max pcap file size. Default: 512
  --no-tcpdump              Skip tcpdump capture
  --no-connection-poll      Skip connection polling
  -h, --help                Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --out-base) OUT_BASE="$2"; shift 2 ;;
    --process-name) PROCESS_NAME="$2"; shift 2 ;;
    --poll-interval-ms) POLL_INTERVAL_MS="$2"; shift 2 ;;
    --pkt-size) PKT_SIZE="$2"; shift 2 ;;
    --max-file-size-mb) MAX_FILE_SIZE_MB="$2"; shift 2 ;;
    --no-tcpdump) NO_TCPDUMP=true; shift ;;
    --no-connection-poll) NO_CONNECTION_POLL=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

# Check root for tcpdump
if [[ "$NO_TCPDUMP" != "true" ]] && [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: This script must be run with sudo for tcpdump. Use --no-tcpdump to skip packet capture." >&2
  exit 1
fi

output_dir="$REPO_ROOT/output"
mkdir -p "$output_dir"

timestamp_tag="$(date -u +%Y%m%d-%H%M%S)"

if [[ -z "$OUT_BASE" ]]; then
  OUT_BASE="$output_dir/antigravity_chat_nettrace_${timestamp_tag}"
elif [[ "$OUT_BASE" != /* ]]; then
  OUT_BASE="$REPO_ROOT/$OUT_BASE"
fi

pcap_file="$OUT_BASE.tcpdump.pcap"
conn_csv="$OUT_BASE.$PROCESS_NAME.connections.csv"

# Find process PID
ls_pid=""
if pgrep -x "$PROCESS_NAME" >/dev/null 2>&1; then
  ls_pid="$(pgrep -x "$PROCESS_NAME" | head -n 1)"
fi

echo "Tracing Antigravity Agent chat network traffic (OS-level)."
if [[ -n "$ls_pid" ]]; then
  echo "Process to correlate: $PROCESS_NAME (pid=$ls_pid)"
else
  echo "Process to correlate: $PROCESS_NAME (not running yet)"
fi
echo "Outputs:"
echo "  $pcap_file"
echo "  $conn_csv"
echo ""
echo "Steps:"
echo "1) Script will start tcpdump capture (port 443, TCP+UDP)."
echo "2) Trigger Antigravity Agent chat activity (send a message, wait for response)."
echo "3) Press Enter here to stop capture and write outputs."
echo ""

tcpdump_pid=""
poll_pid=""

cleanup() {
  if [[ -n "$poll_pid" ]]; then
    kill "$poll_pid" 2>/dev/null || true
    wait "$poll_pid" 2>/dev/null || true
    echo "Connection poller stopped."
  fi
  if [[ -n "$tcpdump_pid" ]]; then
    kill "$tcpdump_pid" 2>/dev/null || true
    wait "$tcpdump_pid" 2>/dev/null || true
    echo "tcpdump stopped."
  fi
}
trap cleanup EXIT

# Start tcpdump
if [[ "$NO_TCPDUMP" != "true" ]]; then
  command -v tcpdump >/dev/null 2>&1 || { echo "ERROR: tcpdump not found. Install it or use --no-tcpdump." >&2; exit 1; }
  snap_arg=""
  if [[ "$PKT_SIZE" -gt 0 ]]; then
    snap_arg="-s $PKT_SIZE"
  fi
  # Capture port 443 (TLS + QUIC)
  # shellcheck disable=SC2086
  tcpdump -i any -w "$pcap_file" -C "$MAX_FILE_SIZE_MB" $snap_arg "port 443" &
  tcpdump_pid=$!
  echo "tcpdump capture started (PID: $tcpdump_pid)."
else
  echo "WARNING: Skipping tcpdump capture (--no-tcpdump)." >&2
fi

# Start connection poller
if [[ "$NO_CONNECTION_POLL" != "true" ]]; then
  if [[ -z "$ls_pid" ]]; then
    echo "Waiting for $PROCESS_NAME to start..."
    deadline=$((SECONDS + 30))
    while [[ -z "$ls_pid" ]] && [[ $SECONDS -lt $deadline ]]; do
      if pgrep -x "$PROCESS_NAME" >/dev/null 2>&1; then
        ls_pid="$(pgrep -x "$PROCESS_NAME" | head -n 1)"
        break
      fi
      sleep 0.5
    done
  fi

  if [[ -n "$ls_pid" ]]; then
    poll_interval_sec="$(echo "scale=3; $POLL_INTERVAL_MS / 1000" | bc 2>/dev/null || echo "0.5")"
    (
      echo "timestamp_utc,owning_process,local_address,local_port,remote_address,remote_port,state" > "$conn_csv"
      while true; do
        ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
        # Use ss to get ESTAB connections for the process
        ss -tnpH state established 2>/dev/null | grep "pid=$ls_pid," 2>/dev/null | awk -v ts="$ts" -v pid="$ls_pid" '{
          split($4, local, ":")
          split($5, remote, ":")
          printf "%s,%s,%s,%s,%s,%s,Established\n", ts, pid, local[1], local[2], remote[1], remote[2]
        }' >> "$conn_csv" 2>/dev/null || true
        sleep "$poll_interval_sec"
      done
    ) &
    poll_pid=$!
    echo "Connection poller started for pid=$ls_pid."
  else
    echo "WARNING: Could not find $PROCESS_NAME to poll connections. (Start Antigravity, then re-run.)" >&2
  fi
else
  echo "WARNING: Skipping connection poll (--no-connection-poll)." >&2
fi

read -r -p "Press Enter when done "

# Cleanup handled by trap
echo ""
echo "Next:"
echo "- Open the .pcap in Wireshark and filter for TLS ClientHello to extract SNI (server names)."
echo "  Example Wireshark display filter: tls.handshake.type == 1"
echo "- Use the connections CSV to correlate which remote IPs belong to $PROCESS_NAME."
