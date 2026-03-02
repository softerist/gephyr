param(
    [Parameter(Mandatory = $true)][string]$GephyrPath,
    [Parameter(Mandatory = $true)][string]$OfficialPath,
    [string]$BaselineDir = "parity/baselines/redacted/windows/default",
    [string]$RulesPath = "",
    [string]$RequireSources = "antigravity_exe,language_server_windows_x64",
    [double]$MaxUnknownRatio = 0.15,
    [string]$AntigravityExePath = "",
    [string]$LanguageServerExePath = "",
    [switch]$Gate
)

$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $projectRoot

$argsAudit = @(
    "run", "--quiet", "--bin", "gephyr-parity", "--",
    "source-audit",
    "--input", $OfficialPath,
    "--out", "output/parity/official/source_audit.json",
    "--require-sources", $RequireSources,
    "--max-unknown-ratio", "$MaxUnknownRatio"
)
if ($RulesPath) {
    # source-audit does not consume rules today; kept for future parity in wrapper
}

Write-Host "Running source audit on official capture..."
& cargo @argsAudit
if ($LASTEXITCODE -ne 0) {
    throw "source-audit failed"
}

$argsRefresh = @(
    "run", "--quiet", "--bin", "gephyr-parity", "--",
    "refresh-baseline",
    "--gephyr", $GephyrPath,
    "--official", $OfficialPath,
    "--baseline-dir", $BaselineDir
)

if ($Gate) {
    $argsRefresh += "--gate"
}
if ($RulesPath) {
    $argsRefresh += @("--rules", $RulesPath)
}
if ($AntigravityExePath) {
    $argsRefresh += @("--antigravity-exe-path", $AntigravityExePath)
}
if ($LanguageServerExePath) {
    $argsRefresh += @("--language-server-exe-path", $LanguageServerExePath)
}

Write-Host "Refreshing baseline artifacts/manifests..."
& cargo @argsRefresh
if ($LASTEXITCODE -ne 0) {
    throw "refresh-baseline failed"
}

Write-Host "Done. Baseline refreshed at: $BaselineDir"
Write-Host "Source audit report: output/parity/official/source_audit.json"
