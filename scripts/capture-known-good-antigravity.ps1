param(
    [int]$Port = 8879,
    [string]$KnownGoodPath = "output/known_good_antigravity.jsonl",
    [string[]]$TargetHosts = @(),
    [string[]]$TargetSuffixes = @(),
    [switch]$CaptureAll,
    [switch]$CaptureNoise,
    [switch]$TrustCert,
    [switch]$SelfTestProxy,
    [switch]$RequireStream,
    [switch]$RequireStrictStream,
    [switch]$AllowMissingStream,
    [switch]$StopExistingAntigravity,
    # Default behavior: manage + restore Windows proxy settings to maximize capture fidelity.
    # Use -NoManage* to opt out.
    [switch]$ManageSystemProxy,
    [switch]$NoManageSystemProxy,
    [switch]$ManageWinHttpProxy,
    [switch]$NoManageWinHttpProxy
)

$ErrorActionPreference = "Stop"

$args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $PSScriptRoot "capture-known-good-mitmproxy.ps1"),
    "-Port", $Port,
    "-KnownGoodPath", $KnownGoodPath,
    "-SkipDiff",
    "-ManageAntigravityIdeProxy",
    "-LaunchAntigravityProxied"
)

foreach ($h in $TargetHosts) {
    $args += "-TargetHosts"
    $args += $h
}
foreach ($s in $TargetSuffixes) {
    $args += "-TargetSuffixes"
    $args += $s
}

if ($CaptureAll) { $args += "-CaptureAll" }
if ($CaptureNoise) { $args += "-CaptureNoise" }
if ($TrustCert) { $args += "-TrustCert" }
if ($SelfTestProxy) { $args += "-SelfTestProxy" }
if ($RequireStream) { $args += "-RequireStream" }
if ($RequireStrictStream) { $args += "-RequireStrictStream" }
if ($AllowMissingStream) { $args += "-AllowMissingStream" }
if ($StopExistingAntigravity) { $args += "-StopExistingAntigravity" }

if ($ManageSystemProxy -and $NoManageSystemProxy) { throw "Conflicting switches: -ManageSystemProxy and -NoManageSystemProxy" }
if ($ManageWinHttpProxy -and $NoManageWinHttpProxy) { throw "Conflicting switches: -ManageWinHttpProxy and -NoManageWinHttpProxy" }

$shouldManageSystemProxy = $ManageSystemProxy -or (-not $NoManageSystemProxy)
$shouldManageWinHttpProxy = $ManageWinHttpProxy -or (-not $NoManageWinHttpProxy)

if ($shouldManageSystemProxy) { $args += "-ManageSystemProxy" }
if ($shouldManageWinHttpProxy) { $args += "-ManageWinHttpProxy" }

if (-not $CaptureAll) {
    Write-Host "Capture mode: strict Google targets (default). Use -CaptureAll to inspect all hosts."
} else {
    Write-Warning "Capture mode is ALL HOSTS (-CaptureAll). 'target' counts in diagnostics will include non-Google hosts."
}
Write-Host ("Proxy management: system={0}, winhttp={1}, ide={2}" -f $shouldManageSystemProxy, $shouldManageWinHttpProxy, $true)

& powershell @args
