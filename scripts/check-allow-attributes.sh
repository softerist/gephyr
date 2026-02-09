#!/usr/bin/env bash
set -euo pipefail

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/check-allow-attributes.sh [--root <path>] [--help]

Description:
  Scans src/ for forbidden Rust allow attributes:
  - #[allow(dead_code)] in runtime code
  - non-test #[allow(clippy::...)] attributes

Examples:
  ./scripts/check-allow-attributes.sh
  ./scripts/check-allow-attributes.sh --root /path/to/repo
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_usage
      exit 0
      ;;
    --root)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --root requires a path argument." >&2
        exit 2
      fi
      ROOT_DIR="$2"
      shift 2
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      show_usage
      exit 2
      ;;
  esac
done

cd "$ROOT_DIR"

fail=0

echo "[allow-guard] scanning src/ for forbidden allow attributes..."

dead_hits="$(rg -n '#\[allow\(dead_code\)\]' src || true)"
if [[ -n "$dead_hits" ]]; then
  echo ""
  echo "[allow-guard] ERROR: runtime dead_code allow(s) detected in src/."
  echo "$dead_hits"
  fail=1
fi

clippy_hits="$(rg -n '#\[allow\([^)]*clippy::[^)]*\)\]' src || true)"
if [[ -n "$clippy_hits" ]]; then
  disallowed_clippy="$(printf '%s\n' "$clippy_hits" | awk -F: '
    {
      path=$1;
      gsub(/\\/, "/", path);
      if (path ~ /\/tests\// || path ~ /_test\\.rs$/ || path ~ /_tests\\.rs$/) {
        next;
      }
      print $0;
    }
  ')"

  if [[ -n "$disallowed_clippy" ]]; then
    echo ""
    echo "[allow-guard] ERROR: non-test clippy allow(s) detected in src/."
    echo "$disallowed_clippy"
    fail=1
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo ""
  echo "[allow-guard] failed. Remove allow attributes or move clippy allows to test-only files."
  exit 1
fi

echo "[allow-guard] ok"
