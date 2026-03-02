<#
.SYNOPSIS
    Ensures no raw parity artifacts are tracked in git.
.DESCRIPTION
    Fails CI if raw/unredacted parity capture files have been committed.
#>
$ErrorActionPreference = 'Stop'

$tracked = git ls-files
$violations = @()

foreach ($line in $tracked) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    if ($line -like 'output/parity/raw/*') {
        $violations += $line
        continue
    }
    if ($line -like '*.raw.jsonl') {
        $violations += $line
        continue
    }
    if ($line -like 'parity/baselines/raw/*') {
        $violations += $line
        continue
    }
}

if ($violations.Count -gt 0) {
    Write-Error "ERROR: raw parity artifacts must not be committed:"
    foreach ($v in $violations) {
        Write-Error "  - $v"
    }
    exit 1
}

Write-Host "OK: no raw parity artifacts tracked in git"
