param(
    [string]$ParityScriptPath = (Join-Path $PSScriptRoot "live-google-parity-verify.ps1")
)

$ErrorActionPreference = "Stop"

function Read-DefaultString {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [Parameter(Mandatory = $true)][string]$Default
    )
    $value = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value.Trim()
}

function Read-DefaultInt {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [Parameter(Mandatory = $true)][int]$Default
    )
    while ($true) {
        $value = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
        $parsed = 0
        if ([int]::TryParse($value, [ref]$parsed) -and $parsed -gt 0) {
            return $parsed
        }
        Write-Host "Please enter a positive integer." -ForegroundColor Yellow
    }
}

function Read-YesNo {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [bool]$Default = $true
    )
    $hint = if ($Default) { "Y/n" } else { "y/N" }
    while ($true) {
        $value = Read-Host "$Prompt ($hint)"
        if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
        switch ($value.Trim().ToLowerInvariant()) {
            "y" { return $true }
            "yes" { return $true }
            "1" { return $true }
            "n" { return $false }
            "no" { return $false }
            "0" { return $false }
            default { Write-Host "Please answer y or n." -ForegroundColor Yellow }
        }
    }
}

function Read-Mode {
    Write-Host ""
    Write-Host "Select run mode:"
    Write-Host "  1) Gephyr scope (recommended default)"
    Write-Host "  2) Antigravity scope (allowlist + UA scoped)"
    Write-Host "  3) Raw baseline (no scope transform)"
    while ($true) {
        $choice = Read-Host "Mode [1]"
        if ([string]::IsNullOrWhiteSpace($choice)) { return "1" }
        if ($choice -in @("1", "2", "3")) { return $choice }
        Write-Host "Please choose 1, 2, or 3." -ForegroundColor Yellow
    }
}

if (-not (Test-Path $ParityScriptPath)) {
    throw "Parity script not found: $ParityScriptPath"
}

Write-Host "Live Google Parity Verify - Interactive Launcher"
Write-Host "Script: $ParityScriptPath"

$modeChoice = Read-Mode
$scope = "Gephyr"
$knownGoodPath = "output/known_good.gephyr_scope.jsonl"
$knownGoodSourcePath = "output/known_good.jsonl"
$allowlistPath = "scripts/allowlists/antigravity_google_endpoints_default_chat.txt"

switch ($modeChoice) {
    "1" {
        $scope = "Gephyr"
        $knownGoodPath = "output/known_good.gephyr_scope.jsonl"
        $knownGoodSourcePath = "output/known_good.jsonl"
    }
    "2" {
        $scope = "Antigravity"
        $knownGoodPath = "output/known_good.antigravity_scope.jsonl"
        $knownGoodSourcePath = "output/known_good.jsonl"
    }
    "3" {
        $scope = "Raw"
        $knownGoodPath = "output/known_good.jsonl"
    }
}

$configPath = Read-DefaultString -Prompt "Config path" -Default "$env:USERPROFILE\.gephyr\config.json"
$outGephyrPath = Read-DefaultString -Prompt "Gephyr outbound trace output path" -Default "output/gephyr_google_outbound_headers.jsonl"
$startupTimeout = Read-DefaultInt -Prompt "Startup timeout (seconds)" -Default 60
$requireOAuthRelink = Read-YesNo -Prompt "Require OAuth relink flow" -Default $true
$skipExtendedFlow = Read-YesNo -Prompt "Skip extended probes" -Default $false
$skipBulkQuotaRefresh = $false
if (-not $skipExtendedFlow) {
    $skipBulkQuotaRefresh = Read-YesNo -Prompt "Skip bulk quota refresh inside extended probes" -Default $false
}
$noClaudeProbes = Read-YesNo -Prompt "Disable Claude probes (/v1/messages) to avoid anthropic-beta drift" -Default $true

if ($scope -eq "Raw") {
    $knownGoodPath = Read-DefaultString -Prompt "Known-good path (raw)" -Default $knownGoodPath
} else {
    $knownGoodSourcePath = Read-DefaultString -Prompt "Known-good source path" -Default $knownGoodSourcePath
    $knownGoodPath = Read-DefaultString -Prompt "Scoped known-good output path" -Default $knownGoodPath
}

if ($scope -eq "Antigravity") {
    $allowlistPath = Read-DefaultString -Prompt "Antigravity allowlist path" -Default $allowlistPath
}

$args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $ParityScriptPath,
    "-ConfigPath", $configPath,
    "-Scope", $scope,
    "-KnownGoodPath", $knownGoodPath,
    "-OutGephyrPath", $outGephyrPath,
    "-StartupTimeoutSeconds", "$startupTimeout"
)

if ($scope -ne "Raw") {
    $args += @("-KnownGoodSourcePath", $knownGoodSourcePath)
}
if ($scope -eq "Antigravity") {
    $args += @("-AntigravityAllowlistPath", $allowlistPath)
}
if ($requireOAuthRelink) { $args += "-RequireOAuthRelink" }
if ($skipExtendedFlow) { $args += "-SkipExtendedFlow" }
if ($skipBulkQuotaRefresh) { $args += "-SkipBulkQuotaRefresh" }
if ($noClaudeProbes) { $args += "-NoClaudeProbes" }

$previewArgs = $args | ForEach-Object {
    if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
}
Write-Host ""
Write-Host "Command preview:"
Write-Host ("powershell {0}" -f ($previewArgs -join " "))

$confirm = Read-YesNo -Prompt "Run now" -Default $true
if (-not $confirm) {
    Write-Host "Cancelled."
    exit 0
}

& powershell @args
if ($LASTEXITCODE -ne 0) {
    throw "Parity script failed with exit code $LASTEXITCODE"
}

Write-Host "Completed."
