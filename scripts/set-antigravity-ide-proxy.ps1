param(
    [string]$ProxyUrl = "",
    [int]$Port = 8879,
    [string]$SettingsPath = "",
    [ValidateSet("override","on","off")]
    [string]$ProxySupport = "override",
    [switch]$Clear,
    [switch]$PrintOnly
)

$ErrorActionPreference = "Stop"

function Resolve-SettingsPath {
    param([string]$Explicit)
    if ($Explicit) { return $Explicit }
    if (-not $env:APPDATA) {
        throw "APPDATA is not set; can't locate Antigravity settings.json."
    }
    return (Join-Path $env:APPDATA "Antigravity\User\settings.json")
}

if (-not $ProxyUrl) {
    $ProxyUrl = "http://127.0.0.1:$Port"
}

$settingsAbs = Resolve-SettingsPath -Explicit $SettingsPath
$settingsDir = Split-Path -Parent $settingsAbs
if (-not (Test-Path $settingsDir)) {
    New-Item -ItemType Directory -Path $settingsDir | Out-Null
}

$raw = "{}"
if (Test-Path $settingsAbs) {
    $raw = Get-Content -Path $settingsAbs -Raw
}

try {
    $obj = $raw | ConvertFrom-Json
} catch {
    throw "Failed to parse Antigravity settings JSON at '$settingsAbs': $($_.Exception.Message)"
}

if ($PrintOnly) {
    $currentProxy = $obj."http.proxy"
    $currentSupport = $obj."http.proxySupport"
    Write-Host "Settings: $settingsAbs"
    Write-Host "http.proxy: $currentProxy"
    Write-Host "http.proxySupport: $currentSupport"
    return
}

if ($Clear) {
    if ($null -ne $obj.PSObject.Properties["http.proxy"]) { $obj.PSObject.Properties.Remove("http.proxy") }
    if ($null -ne $obj.PSObject.Properties["http.proxySupport"]) { $obj.PSObject.Properties.Remove("http.proxySupport") }
} else {
    $obj | Add-Member -NotePropertyName "http.proxy" -NotePropertyValue $ProxyUrl -Force
    $obj | Add-Member -NotePropertyName "http.proxySupport" -NotePropertyValue $ProxySupport -Force
}

$backup = ""
if (Test-Path $settingsAbs) {
    $backup = "{0}.bak-{1}" -f $settingsAbs, (Get-Date -Format "yyyyMMdd-HHmmss")
    Copy-Item -Path $settingsAbs -Destination $backup -Force
}

$obj | ConvertTo-Json -Depth 20 | Set-Content -Path $settingsAbs -Encoding UTF8

if ($Clear) {
    Write-Host "Cleared Antigravity IDE proxy settings in: $settingsAbs"
} else {
    Write-Host "Set Antigravity IDE proxy settings in: $settingsAbs"
    Write-Host "  http.proxy=$ProxyUrl"
    Write-Host "  http.proxySupport=$ProxySupport"
}
if ($backup) {
    Write-Host "Backup: $backup"
}
