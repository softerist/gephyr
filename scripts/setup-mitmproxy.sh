#!/usr/bin/env bash
# Sets up mitmproxy using pip3.
# Linux equivalent of setup-mitmproxy.ps1 (which uses the Windows 'py' launcher).
set -euo pipefail

PYTHON_BIN="python3"
SKIP_INSTALL=false
NO_PATH_PERSIST=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/setup-mitmproxy.sh [options]

Options:
  --python <bin>      Python binary. Default: python3
  --skip-install      Skip pip install
  --no-path-persist   Don't update shell profile PATH
  -h, --help          Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python) PYTHON_BIN="$2"; shift 2 ;;
    --skip-install) SKIP_INSTALL=true; shift ;;
    --no-path-persist) NO_PATH_PERSIST=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

command -v "$PYTHON_BIN" >/dev/null 2>&1 || { echo "ERROR: $PYTHON_BIN not found. Install Python 3 first." >&2; exit 1; }

py_version="$("$PYTHON_BIN" -c "import sys; print(sys.version)" 2>&1 | tail -n 1)"
echo "Using Python: $PYTHON_BIN => $py_version"

if [[ "$SKIP_INSTALL" != "true" ]]; then
  echo "Installing/upgrading mitmproxy ..."
  "$PYTHON_BIN" -m pip install --user --upgrade mitmproxy
fi

# Resolve user scripts path
scripts_path="$("$PYTHON_BIN" -c "import sysconfig; print(sysconfig.get_path('scripts', scheme='posix_user'))" 2>/dev/null || true)"
if [[ -z "$scripts_path" ]]; then
  scripts_path="$HOME/.local/bin"
fi

mitmdump_path="$scripts_path/mitmdump"
if [[ ! -f "$mitmdump_path" ]]; then
  # Try common fallback
  if command -v mitmdump >/dev/null 2>&1; then
    mitmdump_path="$(command -v mitmdump)"
  else
    echo "ERROR: mitmdump not found at '$scripts_path/mitmdump'. Re-run without --skip-install or verify pip install output." >&2
    exit 1
  fi
fi

if [[ "$NO_PATH_PERSIST" != "true" ]]; then
  # Add to PATH in current shell profile
  shell_profile=""
  if [[ -n "${ZSH_VERSION:-}" ]]; then
    shell_profile="$HOME/.zshrc"
  elif [[ -f "$HOME/.bashrc" ]]; then
    shell_profile="$HOME/.bashrc"
  elif [[ -f "$HOME/.bash_profile" ]]; then
    shell_profile="$HOME/.bash_profile"
  fi

  if [[ -n "$shell_profile" ]]; then
    path_line="export PATH=\"$scripts_path:\$PATH\""
    if ! grep -qF "$scripts_path" "$shell_profile" 2>/dev/null; then
      echo "" >> "$shell_profile"
      echo "# Added by setup-mitmproxy.sh" >> "$shell_profile"
      echo "$path_line" >> "$shell_profile"
      echo "Updated $shell_profile with: $scripts_path"
    else
      echo "PATH already contains $scripts_path in $shell_profile"
    fi
  else
    echo "WARNING: Could not identify shell profile to update PATH." >&2
  fi
else
  echo "Skipped persistent PATH update (--no-path-persist)."
fi

# Update current session
export PATH="$scripts_path:$PATH"
echo "Updated current session PATH."

"$mitmdump_path" --version

echo ""
echo "Setup complete."
echo "You can now run:"
echo "  bash scripts/capture-known-good-mitmproxy.sh --trust-cert"
