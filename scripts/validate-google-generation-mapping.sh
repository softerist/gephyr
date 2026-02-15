#!/usr/bin/env bash
# Validates static guardrails for Google generation route/caller mapping.
#
# Enforces two code-level invariants:
# 1) Only allowlisted non-test files may call UpstreamClient `call_v1_internal*`.
# 2) Expected generation ingress route paths and handler symbols are present in
#    src/proxy/routes/mod.rs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CALLER_ALLOWLIST_PATH="scripts/allowlists/google_generation_upstream_callers.txt"
ROUTE_ALLOWLIST_PATH="scripts/allowlists/google_generation_ingress_routes.txt"
ROUTES_FILE_PATH="src/proxy/routes/mod.rs"
OUT_JSON="output/google_generation_mapping_validation.json"
OUT_TEXT="output/google_generation_mapping_validation.txt"
NO_THROW=false

show_usage() {
  cat <<'EOF'
Usage:
  ./scripts/validate-google-generation-mapping.sh [options]

Options:
  --caller-allowlist <path>   Default: scripts/allowlists/google_generation_upstream_callers.txt
  --route-allowlist <path>    Default: scripts/allowlists/google_generation_ingress_routes.txt
  --routes-file <path>        Default: src/proxy/routes/mod.rs
  --out-json <path>           Default: output/google_generation_mapping_validation.json
  --out-text <path>           Default: output/google_generation_mapping_validation.txt
  --no-throw                  Do not exit with error on validation failure
  -h, --help                  Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --caller-allowlist) CALLER_ALLOWLIST_PATH="$2"; shift 2 ;;
    --route-allowlist) ROUTE_ALLOWLIST_PATH="$2"; shift 2 ;;
    --routes-file) ROUTES_FILE_PATH="$2"; shift 2 ;;
    --out-json) OUT_JSON="$2"; shift 2 ;;
    --out-text) OUT_TEXT="$2"; shift 2 ;;
    --no-throw) NO_THROW=true; shift ;;
    -h|--help) show_usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; show_usage; exit 2 ;;
  esac
done

cd "$REPO_ROOT"

command -v rg >/dev/null 2>&1 || { echo "ERROR: ripgrep (rg) is required for this validator." >&2; exit 1; }

[[ -f "$ROUTES_FILE_PATH" ]] || { echo "ERROR: Routes file not found: $ROUTES_FILE_PATH" >&2; exit 1; }
[[ -f "$CALLER_ALLOWLIST_PATH" ]] || { echo "ERROR: Caller allowlist not found: $CALLER_ALLOWLIST_PATH" >&2; exit 1; }
[[ -f "$ROUTE_ALLOWLIST_PATH" ]] || { echo "ERROR: Route allowlist not found: $ROUTE_ALLOWLIST_PATH" >&2; exit 1; }

normalize_path() {
  printf '%s' "$1" | tr '\\' '/'
}

# Load allowlists (skip blanks and comments)
mapfile -t caller_allow < <(grep -v '^\s*#' "$CALLER_ALLOWLIST_PATH" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$')
mapfile -t route_allow < <(grep -v '^\s*#' "$ROUTE_ALLOWLIST_PATH" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$')

# Build a set of normalized allowed caller paths
declare -A caller_allow_set
for p in "${caller_allow[@]}"; do
  caller_allow_set["$(normalize_path "$p")"]=1
done

# Find all files calling call_v1_internal
caller_matches="$(rg -n 'call_v1_internal_with_headers\(|call_v1_internal\(' src/proxy src/modules -S 2>/dev/null || true)"

declare -A observed_callers
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  path="$(printf '%s' "$line" | cut -d: -f1)"
  path="$(normalize_path "$path")"
  # Exclude upstream client implementation and tests
  [[ "$path" == "src/proxy/upstream/client.rs" ]] && continue
  [[ "$path" =~ /tests/ ]] && continue
  observed_callers["$path"]=1
done <<< "$caller_matches"

# Compute unknown callers and missing allowed callers
unknown_callers=()
for k in "${!observed_callers[@]}"; do
  [[ -z "${caller_allow_set[$k]:-}" ]] && unknown_callers+=("$k")
done
IFS=$'\n' unknown_callers=($(printf '%s\n' "${unknown_callers[@]}" | sort)); unset IFS

missing_allowed_callers=()
for p in "${caller_allow[@]}"; do
  np="$(normalize_path "$p")"
  [[ -z "${observed_callers[$np]:-}" ]] && missing_allowed_callers+=("$np")
done
IFS=$'\n' missing_allowed_callers=($(printf '%s\n' "${missing_allowed_callers[@]}" | sort)); unset IFS

observed_allowed_callers=()
for k in "${!observed_callers[@]}"; do
  [[ -n "${caller_allow_set[$k]:-}" ]] && observed_allowed_callers+=("$k")
done
IFS=$'\n' observed_allowed_callers=($(printf '%s\n' "${observed_allowed_callers[@]}" | sort)); unset IFS

# Check routes and handler symbols
routes_text="$(cat "$ROUTES_FILE_PATH")"
missing_routes=()
for route in "${route_allow[@]}"; do
  if ! printf '%s' "$routes_text" | grep -qF "$route"; then
    missing_routes+=("$route")
  fi
done

required_symbols=(
  "handlers::openai::handle_chat_completions"
  "handlers::openai::handle_completions"
  "handlers::claude::handle_messages"
  "handlers::gemini::handle_generate"
)
missing_symbols=()
for sym in "${required_symbols[@]}"; do
  if ! printf '%s' "$routes_text" | grep -qF "$sym"; then
    missing_symbols+=("$sym")
  fi
done

pass=true
if [[ ${#unknown_callers[@]} -gt 0 || ${#missing_routes[@]} -gt 0 || ${#missing_symbols[@]} -gt 0 ]]; then
  pass=false
fi

# Ensure output directory exists
mkdir -p "$(dirname "$OUT_JSON")" "$(dirname "$OUT_TEXT")"

# Write JSON report
if command -v python3 >/dev/null 2>&1; then
  python3 - <<PY "$pass" "${#caller_allow[@]}" "${#observed_callers[@]}" "${#observed_allowed_callers[@]}"
import json, sys, datetime

pass_val = sys.argv[1] == "true"
result = {
    "generated_at": datetime.datetime.now().isoformat(),
    "caller_allowlist_path": "$CALLER_ALLOWLIST_PATH",
    "route_allowlist_path": "$ROUTE_ALLOWLIST_PATH",
    "routes_file_path": "$ROUTES_FILE_PATH",
    "caller_allow_count": int(sys.argv[2]),
    "observed_non_test_callers_count": int(sys.argv[3]),
    "observed_allowed_callers": $(printf '%s\n' "${observed_allowed_callers[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
    "unknown_callers": $(printf '%s\n' "${unknown_callers[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
    "missing_allowed_callers": $(printf '%s\n' "${missing_allowed_callers[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
    "required_route_paths_missing": $(printf '%s\n' "${missing_routes[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
    "required_handler_symbols_missing": $(printf '%s\n' "${missing_symbols[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
    "pass": pass_val
}
with open("$OUT_JSON", "w") as f:
    json.dump(result, f, indent=2)
PY
else
  echo "{\"pass\": $pass}" > "$OUT_JSON"
fi

# Write text report
{
  echo "Google Generation Mapping Validation"
  echo "Generated: $(date -Iseconds)"
  echo "Routes file: $ROUTES_FILE_PATH"
  echo "Caller allowlist: $CALLER_ALLOWLIST_PATH"
  echo "Route allowlist: $ROUTE_ALLOWLIST_PATH"
  echo "Pass: $pass"
  echo ""
  echo "Unknown non-test call_v1_internal* callers:"
  if [[ ${#unknown_callers[@]} -eq 0 ]]; then
    echo "  (none)"
  else
    for c in "${unknown_callers[@]}"; do echo "  $c"; done
  fi
  echo ""
  echo "Missing allowlisted callers (informational):"
  if [[ ${#missing_allowed_callers[@]} -eq 0 ]]; then
    echo "  (none)"
  else
    for c in "${missing_allowed_callers[@]}"; do echo "  $c"; done
  fi
  echo ""
  echo "Missing required route paths:"
  if [[ ${#missing_routes[@]} -eq 0 ]]; then
    echo "  (none)"
  else
    for r in "${missing_routes[@]}"; do echo "  $r"; done
  fi
  echo ""
  echo "Missing required route handler symbols:"
  if [[ ${#missing_symbols[@]} -eq 0 ]]; then
    echo "  (none)"
  else
    for s in "${missing_symbols[@]}"; do echo "  $s"; done
  fi
} > "$OUT_TEXT"

echo "Validation report written:"
echo "  $OUT_TEXT"
echo "  $OUT_JSON"
echo "Pass: $pass"

if [[ "$NO_THROW" != "true" && "$pass" != "true" ]]; then
  echo "ERROR: Google generation mapping validation failed. See: $OUT_TEXT" >&2
  exit 1
fi
