#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
