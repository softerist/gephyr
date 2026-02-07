#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="start-auth.sh"

if [[ ! -f "$SCRIPT_DIR/$TARGET" ]]; then
  echo "Missing script: $SCRIPT_DIR/$TARGET" >&2
  exit 1
fi

cd "$SCRIPT_DIR"

# Wrapper for naming parity with Windows script.
# Delegates to start-auth.sh (full CLI implementation).
if [[ $# -eq 0 ]]; then
  exec bash "./$TARGET" start
fi

case "${1:-}" in
  --help|-h|-?|\?|/help)
    exec bash "./$TARGET" help
    ;;
esac

if [[ "${1:0:1}" == "-" ]]; then
  exec bash "./$TARGET" start "$@"
fi

exec bash "./$TARGET" "$@"
