<#
.SYNOPSIS
Guard script to block forbidden Rust allow attributes in src/.

.DESCRIPTION
Scans src/ for:
- #[allow(dead_code)] (forbidden in runtime code)
- non-test #[allow(clippy::...)] attributes

Returns non-zero when violations are found.

.PARAMETER Root
Repository root path to scan. Defaults to parent of this script.

.PARAMETER Help
Print usage/examples and exit.

.EXAMPLE
.\scripts\check-allow-attributes.ps1

.EXAMPLE
.\scripts\check-allow-attributes.ps1 -Root F:\Git\gephyr

.EXAMPLE
Get-Help .\scripts\check-allow-attributes.ps1 -Detailed
#>
param(
  [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")),
  [Alias("h", "?")]
  [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
  Write-Host ""
  Write-Host "Usage:" -ForegroundColor Cyan
  Write-Host "  .\scripts\check-allow-attributes.ps1 [-Root <path>] [-Help]"
  Write-Host ""
  Write-Host "Examples:" -ForegroundColor Cyan
  Write-Host "  .\scripts\check-allow-attributes.ps1"
  Write-Host "  .\scripts\check-allow-attributes.ps1 -Root F:\Git\gephyr"
  Write-Host ""
  Write-Host "PowerShell native help:" -ForegroundColor Cyan
  Write-Host "  Get-Help .\scripts\check-allow-attributes.ps1 -Detailed"
}

if ($Help.IsPresent) {
  Show-Usage
  return
}

Set-Location $Root

# Check if ripgrep is available, fallback to Select-String
$useRipgrep = $null -ne (Get-Command rg -ErrorAction SilentlyContinue)

function Search-Pattern {
  param(
    [string]$Pattern,
    [string]$Path
  )
  
  if ($useRipgrep) {
    $result = rg -n $Pattern $Path 2>$null
    if ($LASTEXITCODE -eq 0 -and $result) {
      return $result
    }
    return @()
  } else {
    # PowerShell fallback using Select-String
    $files = Get-ChildItem -Path $Path -Recurse -Filter "*.rs" -File
    $matches = $files | Select-String -Pattern $Pattern
    if ($matches) {
      return $matches | ForEach-Object { "$($_.Path):$($_.LineNumber):$($_.Line)" }
    }
    return @()
  }
}

$fail = $false
Write-Host "[allow-guard] scanning src/ for forbidden allow attributes..."

$deadHits = Search-Pattern -Pattern '#\[allow\(dead_code\)\]' -Path "src"
if ($deadHits -and $deadHits.Count -gt 0) {
  Write-Host ""
  Write-Host "[allow-guard] ERROR: runtime dead_code allow(s) detected in src/."
  $deadHits | ForEach-Object { Write-Host $_ }
  $fail = $true
}

$clippyHits = Search-Pattern -Pattern '#\[allow\([^)]*clippy::[^)]*\)\]' -Path "src"
if ($clippyHits -and $clippyHits.Count -gt 0) {
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
