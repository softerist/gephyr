param(
    [int]$Port = 8879,
    [string]$AntigravityExe = "$env:LOCALAPPDATA\Programs\Antigravity\Antigravity.exe",
    [string]$NoProxy = "localhost,127.0.0.1,lh3.googleusercontent.com,.googleusercontent.com",
    [switch]$StopExisting,
    [switch]$SetIdeProxy,
    [switch]$SkipProxyCheck,
    [ValidateSet("override","on","off")]
    [string]$IdeProxySupport = "override",
    [string]$SettingsPath = "",
    [int]$SidecarWaitSeconds = 20
)

$ErrorActionPreference = "Stop"

function Test-TcpPort {
    param(
        [string]$TargetHost,
        [int]$Port,
        [int]$TimeoutMs = 1500
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $null
    try {
        $asyncResult = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            return $false
        }
        $client.EndConnect($asyncResult)
        return $true
    } catch {
        return $false
    } finally {
        if ($asyncResult -and $asyncResult.AsyncWaitHandle) {
            $asyncResult.AsyncWaitHandle.Close()
        }
        $client.Close()
    }
}

function Get-LatestSidecar {
    Get-CimInstance Win32_Process -Filter "Name='language_server_windows_x64.exe'" |
        Sort-Object CreationDate -Descending |
        Select-Object -First 1
}

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

if (-not $SkipProxyCheck) {
    if (-not (Test-TcpPort -TargetHost "127.0.0.1" -Port $Port)) {
        throw "Proxy endpoint is not reachable at 127.0.0.1:$Port. Start mitmproxy first, then retry."
    }
    Write-Host "Proxy reachability check passed: 127.0.0.1:$Port"
} else {
    Write-Warning "Skipping proxy reachability check."
}

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
Write-Host "  GRPC_PROXY=$proxy"
Write-Host "  grpc_proxy=$proxy"
Write-Host "  NO_PROXY=$NoProxy"
Write-Host "  NODE_EXTRA_CA_CERTS=$caCer"
Write-Host "  GOOGLE_CLOUD_DISABLE_DIRECT_PATH=true"

$existingSidecarPids = @(
    Get-Process language_server_windows_x64 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Id
)

# Always inherit the normal parent environment and overlay proxy vars only.
# Using Start-Process -Environment may produce a reduced environment for this app.
# --proxy-server forces Chromium's network stack (used by Electron) to route ALL
# traffic through the proxy.  Without this flag, extension-initiated requests
# (e.g. Gemini Code Assist streamGenerateContent) bypass HTTP_PROXY env vars.
$cmdSet = @(
    "set `"HTTP_PROXY=$proxy`"",
    "set `"HTTPS_PROXY=$proxy`"",
    "set `"http_proxy=$proxy`"",
    "set `"https_proxy=$proxy`"",
    "set `"ALL_PROXY=$proxy`"",
    "set `"GRPC_PROXY=$proxy`"",
    "set `"grpc_proxy=$proxy`"",
    "set `"NO_PROXY=$NoProxy`"",
    "set `"NODE_EXTRA_CA_CERTS=$caCer`"",
    "set `"GOOGLE_CLOUD_DISABLE_DIRECT_PATH=true`""
)

$envPrefix = ($cmdSet -join " && ") + " && "
$launchCmd = "$envPrefix`"$AntigravityExe`" --proxy-server=$proxy"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $launchCmd | Out-Null

Write-Host "Antigravity started."

$deadline = (Get-Date).AddSeconds($SidecarWaitSeconds)
$sidecar = $null
while ((Get-Date) -lt $deadline) {
    $candidate = Get-LatestSidecar
    if ($candidate) {
        if (($existingSidecarPids -notcontains [int]$candidate.ProcessId) -or $StopExisting) {
            $sidecar = $candidate
            break
        }
    }
    Start-Sleep -Milliseconds 500
}

if (-not $sidecar) {
    $sidecar = Get-LatestSidecar
}

if (-not $sidecar) {
    Write-Warning "No language_server_windows_x64.exe process found yet. Start Agent Chat once the IDE is ready, then re-run diagnostics."
    return
}

Write-Host ""
Write-Host "Detected sidecar:"
Write-Host "  PID: $($sidecar.ProcessId)"
Write-Host "  Path: $($sidecar.ExecutablePath)"
Write-Host "  Created: $($sidecar.CreationDate)"

$tcp = Get-NetTCPConnection -OwningProcess $sidecar.ProcessId -ErrorAction SilentlyContinue
if (-not $tcp) {
    Write-Warning "No TCP sockets found yet for sidecar PID $($sidecar.ProcessId). Trigger a native chat request and check again."
    return
}

$establishedPublic = $tcp |
    Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -ne "127.0.0.1" }

Write-Host ""
if ($establishedPublic) {
    Write-Host "Established non-loopback connections for sidecar:"
    $establishedPublic |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort |
        Sort-Object RemoteAddress, RemotePort, LocalPort |
        Format-Table -AutoSize
    Write-Warning "If these show direct public :443 destinations instead of proxy routing, sidecar proxy interception is still bypassed."
} else {
    Write-Host "No established non-loopback sidecar connections yet."
}
