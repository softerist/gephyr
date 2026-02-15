param(
    [int]$Port = 8877,
    [string]$AntigravityExe = "$env:LOCALAPPDATA\Programs\Antigravity\Antigravity.exe",
    [string]$NoProxy = "localhost,127.0.0.1,lh3.googleusercontent.com,.googleusercontent.com",
    [switch]$StopExisting,
    [switch]$SetIdeProxy,
    [ValidateSet("override","on","off")]
    [string]$IdeProxySupport = "override",
    [string]$SettingsPath = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $AntigravityExe)) {
    throw "Antigravity executable not found: $AntigravityExe"
}

if ($StopExisting) {
    Get-Process Antigravity -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
}

$caCer = Join-Path $env:USERPROFILE ".mitmproxy\mitmproxy-ca-cert.cer"
if (-not (Test-Path $caCer)) {
    throw "mitmproxy CA certificate not found: $caCer"
}

$proxy = "http://127.0.0.1:$Port"

if ($SetIdeProxy) {
    try {
        $setter = Join-Path $PSScriptRoot "set-antigravity-ide-proxy.ps1"
        if (Test-Path $setter) {
            $setParams = @{
                ProxyUrl = $proxy
                ProxySupport = $IdeProxySupport
            }
            if ($SettingsPath) { $setParams.SettingsPath = $SettingsPath }
            & $setter @setParams | Out-Null
        } else {
            Write-Warning "Missing IDE proxy setter script: $setter"
        }
    } catch {
        Write-Warning "Failed to set Antigravity IDE proxy: $($_.Exception.Message)"
    }
}

Write-Host "Launching Antigravity with proxy env:"
Write-Host "  HTTP_PROXY=$proxy"
Write-Host "  HTTPS_PROXY=$proxy"
Write-Host "  http_proxy=$proxy"
Write-Host "  https_proxy=$proxy"
Write-Host "  ALL_PROXY=$proxy"
Write-Host "  NO_PROXY=$NoProxy"
Write-Host "  NODE_EXTRA_CA_CERTS=$caCer"
Write-Host "  GOOGLE_CLOUD_DISABLE_DIRECT_PATH=1"

# Always inherit the normal parent environment and overlay proxy vars only.
# Using Start-Process -Environment may produce a reduced environment for this app.
# --proxy-server forces Chromium's network stack (used by Electron) to route ALL
# traffic through the proxy.  Without this flag, extension-initiated requests
# (e.g. Gemini Code Assist streamGenerateContent) bypass HTTP_PROXY env vars.
$envPrefix = "set HTTP_PROXY=$proxy && set HTTPS_PROXY=$proxy && set http_proxy=$proxy && set https_proxy=$proxy && set ALL_PROXY=$proxy && set NO_PROXY=$NoProxy && set NODE_EXTRA_CA_CERTS=$caCer && "
$envPrefix += "set GOOGLE_CLOUD_DISABLE_DIRECT_PATH=1 && "
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "$envPrefix`"$AntigravityExe`" --proxy-server=$proxy" | Out-Null

Write-Host "Antigravity started."
