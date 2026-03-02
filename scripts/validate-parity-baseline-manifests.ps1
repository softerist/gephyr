<#
.SYNOPSIS
    Validates parity baseline manifest files.
.DESCRIPTION
    Checks that all .manifest.json files under parity/baselines/redacted
    have the correct schema, required keys, valid checksums, and matching
    record counts.
#>
$ErrorActionPreference = 'Stop'

# --- locate python ---
$pythonBin = if ($env:PYTHON_BIN) { $env:PYTHON_BIN } else { $null }

if (-not $pythonBin) {
    foreach ($candidate in @('python3', 'python', 'py')) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) {
            $pythonBin = $candidate
            break
        }
    }
}

if (-not $pythonBin) {
    Write-Error "ERROR: python3/python is required for baseline manifest validation"
    exit 1
}

# --- inline python validator (identical logic to the .sh version) ---
$pyScript = @'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(".").resolve()
manifest_paths = sorted(pathlib.Path("parity/baselines/redacted").glob("**/*.manifest.json"))
if not manifest_paths:
    print("ERROR: no baseline manifests found under parity/baselines/redacted", file=sys.stderr)
    sys.exit(1)

required = {
    "schema_version": str,
    "generated_at": str,
    "capture_mode": str,
    "platform": str,
    "input_path": str,
    "redacted_baseline_path": str,
    "record_count": int,
    "checksum_sha256": str,
    "ruleset_version": str,
}

errors = []
for path in manifest_paths:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: invalid JSON ({exc})")
        continue

    for key, expected_type in required.items():
        if key not in data:
            errors.append(f"{path}: missing key '{key}'")
            continue
        if not isinstance(data[key], expected_type):
            errors.append(
                f"{path}: key '{key}' has wrong type {type(data[key]).__name__}, expected {expected_type.__name__}"
            )

    if data.get("schema_version") != "v1":
        errors.append(f"{path}: schema_version must be 'v1'")
        continue

    checksum = str(data.get("checksum_sha256", "")).lower()
    if len(checksum) != 64 or any(ch not in "0123456789abcdef" for ch in checksum):
        errors.append(f"{path}: checksum_sha256 must be 64-char lowercase hex")
        continue

    baseline_rel = str(data.get("redacted_baseline_path", "")).strip()
    if not baseline_rel:
        errors.append(f"{path}: redacted_baseline_path must be non-empty")
        continue

    baseline_path = root / baseline_rel
    if not baseline_path.exists():
        errors.append(f"{path}: referenced baseline file missing: {baseline_rel}")
        continue

    actual_checksum = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
    if actual_checksum != checksum:
        errors.append(
            f"{path}: checksum mismatch for {baseline_rel} (manifest={checksum}, actual={actual_checksum})"
        )

    expected_count = data.get("record_count")
    if isinstance(expected_count, int):
        actual_count = sum(1 for line in baseline_path.read_text(encoding="utf-8").splitlines() if line.strip())
        if actual_count != expected_count:
            errors.append(
                f"{path}: record_count mismatch for {baseline_rel} (manifest={expected_count}, actual={actual_count})"
            )

if errors:
    print("ERROR: baseline manifest validation failed:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)

print(f"OK: validated {len(manifest_paths)} baseline manifest(s)")
'@

$pyScript | & $pythonBin -
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
