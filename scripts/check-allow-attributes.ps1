param(
  [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot ".."))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Set-Location $Root

$fail = $false
Write-Host "[allow-guard] scanning src/ for forbidden allow attributes..."

$deadHits = rg -n "#\[allow\(dead_code\)\]" src 2>$null
if ($LASTEXITCODE -eq 0 -and $deadHits) {
  Write-Host ""
  Write-Host "[allow-guard] ERROR: runtime dead_code allow(s) detected in src/."
  $deadHits | ForEach-Object { Write-Host $_ }
  $fail = $true
}

$clippyHits = rg -n "#\[allow\([^)]*clippy::[^)]*\)\]" src 2>$null
if ($LASTEXITCODE -eq 0 -and $clippyHits) {
  $disallowed = @()
  foreach ($line in $clippyHits) {
    $path = ($line -split ":", 2)[0]
    $normalized = $path -replace "\\", "/"
    if ($normalized -match "/tests/" -or $normalized -match "_test\.rs$" -or $normalized -match "_tests\.rs$") {
      continue
    }
    $disallowed += $line
  }

  if ($disallowed.Count -gt 0) {
    Write-Host ""
    Write-Host "[allow-guard] ERROR: non-test clippy allow(s) detected in src/."
    $disallowed | ForEach-Object { Write-Host $_ }
    $fail = $true
  }
}

if ($fail) {
  Write-Host ""
  Write-Host "[allow-guard] failed. Remove allow attributes or move clippy allows to test-only files."
  exit 1
}

Write-Host "[allow-guard] ok"
