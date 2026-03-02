#!/usr/bin/env bash
set -euo pipefail

tracked="$(git ls-files)"

violations=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if [[ "$line" == output/parity/raw/* ]]; then
    violations+=("$line")
    continue
  fi
  if [[ "$line" == *".raw.jsonl" ]]; then
    violations+=("$line")
    continue
  fi
  if [[ "$line" == parity/baselines/raw/* ]]; then
    violations+=("$line")
    continue
  fi
done <<< "$tracked"

if (( ${#violations[@]} > 0 )); then
  echo "ERROR: raw parity artifacts must not be committed:" >&2
  for v in "${violations[@]}"; do
    echo "  - $v" >&2
  done
  exit 1
fi

echo "OK: no raw parity artifacts tracked in git"
