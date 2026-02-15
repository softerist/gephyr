#!/usr/bin/env bash
# Splits a known-good JSONL capture into per-User-Agent files.
set -euo pipefail

IN_PATH="output/known_good.jsonl"
OUT_DIR="output/known_good_by_ua"
ONLY_GOOGLE=false
PRINT_SUMMARY_ONLY=false
MAX_FILES=50

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/split-known-good-by-ua.sh [options]

Options:
  --in <path>              Input JSONL. Default: output/known_good.jsonl
  --out-dir <dir>          Output directory. Default: output/known_good_by_ua
  --only-google            Only include Google endpoints
  --summary-only           Print summary table only
  --max-files <n>          Max output files. Default: 50
  -h, --help               Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --in) IN_PATH="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --only-google) ONLY_GOOGLE=true; shift ;;
    --summary-only) PRINT_SUMMARY_ONLY=true; shift ;;
    --max-files) MAX_FILES="$2"; shift 2 ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

[[ -f "$IN_PATH" ]] || { echo "ERROR: Input JSONL not found: $IN_PATH" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required." >&2; exit 1; }

mkdir -p "$OUT_DIR"

python3 - <<PY "$IN_PATH" "$OUT_DIR" "$ONLY_GOOGLE" "$PRINT_SUMMARY_ONLY" "$MAX_FILES"
import json, sys, re, os

in_path = sys.argv[1]
out_dir = sys.argv[2]
only_google = sys.argv[3] == "true"
summary_only = sys.argv[4] == "true"
max_files = int(sys.argv[5])

def is_google(ep):
    if not ep:
        return False
    return bool(re.match(r'(?i)^https?://[^/]*(googleapis\.com|google\.com)(?::\d+)?/', ep))

def sanitize(name):
    if not name:
        return "unknown"
    s = name.strip()[:120]
    s = re.sub(r'[\\/:*?"<>|]', '_', s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s or "unknown"

counts = {}
lines_by_ua = {}

with open(in_path) as f:
    for raw in f:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        ep = obj.get("endpoint", "")
        if only_google and not is_google(ep):
            continue

        ua = ""
        headers = obj.get("headers")
        if isinstance(headers, dict):
            ua = headers.get("user-agent", headers.get("User-Agent", ""))
        if not ua:
            ua = "<missing-user-agent>"

        counts[ua] = counts.get(ua, 0) + 1
        lines_by_ua.setdefault(ua, []).append(raw)

top = sorted(counts.items(), key=lambda x: -x[1])[:max_files]

if summary_only:
    print(f"{'Count':>8}  User-Agent")
    print(f"{'-----':>8}  ----------")
    for ua, c in top:
        print(f"{c:>8}  {ua}")
    sys.exit(0)

written = 0
for ua, c in top:
    safe = sanitize(ua)
    out_path = os.path.join(out_dir, f"known_good.ua.{safe}.jsonl")
    with open(out_path, "w") as f:
        for line in lines_by_ua[ua]:
            f.write(line + "\n")
    written += 1

print(f"Wrote {written} file(s) under: {out_dir}")
print("Top user-agents:")
print(f"{'Count':>8}  User-Agent")
print(f"{'-----':>8}  ----------")
for ua, c in top:
    print(f"{c:>8}  {ua}")
PY
