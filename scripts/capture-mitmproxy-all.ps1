param(
    [int]$Port = 8879,
    [string]$OutPath = "output/mitm_all_traffic.jsonl",
    [switch]$TrustCert,
    [switch]$SelfTestProxy,
    # Default behavior: manage + restore Windows proxy settings for a true "all traffic" capture.
    # Use -NoManage* to opt out.
    [switch]$ManageSystemProxy,
    [switch]$NoManageSystemProxy,
    [switch]$ManageWinHttpProxy,
    [switch]$NoManageWinHttpProxy,
    [switch]$ManageAntigravityIdeProxy,
    [switch]$LaunchAntigravityProxied,
    [switch]$StopExistingAntigravity
)

$ErrorActionPreference = "Stop"

$args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $PSScriptRoot "capture-known-good-mitmproxy.ps1"),
    "-Port", $Port,
    "-KnownGoodPath", $OutPath,
    "-SkipDiff",
    "-CaptureAll",
    "-CaptureNoise"
)

if ($TrustCert) { $args += "-TrustCert" }
if ($SelfTestProxy) { $args += "-SelfTestProxy" }
if ($ManageSystemProxy -and $NoManageSystemProxy) { throw "Conflicting switches: -ManageSystemProxy and -NoManageSystemProxy" }
if ($ManageWinHttpProxy -and $NoManageWinHttpProxy) { throw "Conflicting switches: -ManageWinHttpProxy and -NoManageWinHttpProxy" }

$shouldManageSystemProxy = $ManageSystemProxy -or (-not $NoManageSystemProxy)
$shouldManageWinHttpProxy = $ManageWinHttpProxy -or (-not $NoManageWinHttpProxy)

if ($shouldManageSystemProxy) { $args += "-ManageSystemProxy" }
if ($shouldManageWinHttpProxy) { $args += "-ManageWinHttpProxy" }
if ($ManageAntigravityIdeProxy) { $args += "-ManageAntigravityIdeProxy" }
if ($LaunchAntigravityProxied) { $args += "-LaunchAntigravityProxied" }
if ($StopExistingAntigravity) { $args += "-StopExistingAntigravity" }

& powershell @args
