param(
  [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot ".."))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

