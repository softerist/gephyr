param(
    [string]$ConfigPath = "$env:USERPROFILE\\.gephyr\\config.json",
    [string]$KnownGoodPath = "output/known_good.jsonl",
    [string]$OutGephyrPath = "output/gephyr_google_outbound_headers.jsonl",
    [int]$StartupTimeoutSeconds = 60,
    [switch]$RequireOAuthRelink,
    [string]$AllowlistPath = "scripts/allowlists/antigravity_google_endpoints_default_chat.txt",
    [switch]$SkipParityMimicTrigger,
    [switch]$AllowMimicTokenRefresh,
    [switch]$RefreshInclusive,
    [switch]$IncludeChatProbe,
    [switch]$IncludeAuthEventProbes,
    [switch]$IncludeExtendedFlow,
    [switch]$AllowMissingAllowlistEndpoints,
    [switch]$SkipAllowlistValidation
)

$ErrorActionPreference = "Stop"

$parityScript = Join-Path $PSScriptRoot "live-google-parity-verify.ps1"
$knownGoodDir = Split-Path -Parent $KnownGoodPath
if (-not $knownGoodDir) { $knownGoodDir = "." }
$knownGoodBase = [System.IO.Path]::GetFileNameWithoutExtension($KnownGoodPath)
$scopedKnownGoodPath = Join-Path $knownGoodDir ("{0}.scoped.jsonl" -f $knownGoodBase)
$args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $parityScript,
    "-ConfigPath", $ConfigPath,
    "-KnownGoodPath", $scopedKnownGoodPath,
    "-KnownGoodSourcePath", $KnownGoodPath,
    "-Scope", "Antigravity",
    "-AntigravityAllowlistPath", $AllowlistPath,
    "-OutGephyrPath", $OutGephyrPath,
    "-StartupTimeoutSeconds", $StartupTimeoutSeconds
)
if ($RequireOAuthRelink) {
    $args += "-RequireOAuthRelink"
}
$effectiveAllowMimicTokenRefresh = [bool]$AllowMimicTokenRefresh
if ($RefreshInclusive) {
    $effectiveAllowMimicTokenRefresh = $true
    $args += "-DisableStrictAntigravityStabilization"
}
if (-not $SkipParityMimicTrigger) {
    $args += "-UseParityMimicTrigger"
    if (-not $effectiveAllowMimicTokenRefresh) {
        $args += "-ParityMimicSkipTokenRefresh"
    }
}
if (-not $IncludeChatProbe) {
    $args += "-SkipChatProbe"
}
if (-not $IncludeAuthEventProbes) {
    $args += "-SkipAuthEventProbes"
}
if (-not $IncludeExtendedFlow) {
    $args += "-SkipExtendedFlow"
}

& powershell @args
if ($LASTEXITCODE -ne 0) {
    throw "live-google-parity-verify.ps1 failed with exit code $LASTEXITCODE"
}

if (-not $SkipAllowlistValidation) {
    if (-not (Test-Path $OutGephyrPath)) {
        throw "Expected Gephyr outbound trace not found for allowlist validation: $OutGephyrPath"
    }
    Write-Host "Running Antigravity Google endpoint allowlist validation ..."
    $validateArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $PSScriptRoot "validate-antigravity-allowed-google-endpoints.ps1"),
        "-TracePath", $OutGephyrPath,
        "-AllowlistPath", $AllowlistPath
    )
    if ($RefreshInclusive) {
        $validateArgs += "-AllowedExtraGoogleEndpoints"
        $validateArgs += "https://oauth2.googleapis.com/token"
    }
    if (-not $AllowMissingAllowlistEndpoints) {
        $validateArgs += "-RequireAllAllowedObserved"
    }
    & powershell @validateArgs
}
