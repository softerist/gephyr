<#
.SYNOPSIS
Smoke-test the dedicated proxy-pool runtime endpoint.

.DESCRIPTION
Validates that `POST /api/proxy/pool/runtime` can update proxy-pool runtime
knobs (`enabled`, `auto_failover`, `health_check_interval`) without full
`/api/config` writes, and that changes are visible via
`GET /api/proxy/pool/runtime`.

.PARAMETER Port
Proxy port. Default: 8045.

.PARAMETER ContainerName
Docker container name used by console.ps1. Default: gephyr.

.PARAMETER Image
Docker image tag used by console.ps1. Default: gephyr:latest.

.PARAMETER DataDir
Gephyr data directory passed to console.ps1.

.PARAMETER TargetEnabled
Optional explicit target for pool enabled flag (true/false).

.PARAMETER TargetAutoFailover
Optional explicit target for auto_failover flag (true/false).

.PARAMETER TargetHealthCheckInterval
Optional explicit target health check interval (seconds).
If omitted, script uses a derived alternate value.

.PARAMETER SkipStart
Use currently running server instead of starting via console.ps1.

.PARAMETER KeepChange
Do not restore original values after test.

.PARAMETER Help
Print usage/examples and exit.

.EXAMPLE
.\scripts\test-proxy-pool-runtime.ps1

.EXAMPLE
.\scripts\test-proxy-pool-runtime.ps1 -TargetEnabled $true -TargetAutoFailover $false -TargetHealthCheckInterval 120

.EXAMPLE
.\scripts\test-proxy-pool-runtime.ps1 -SkipStart -KeepChange

.EXAMPLE
Get-Help .\scripts\test-proxy-pool-runtime.ps1 -Detailed
#>
param(
    [int]$Port = 8045,
    [string]$ContainerName = "gephyr",
    [string]$Image = "gephyr:latest",
    [string]$DataDir = "$env:USERPROFILE\.gephyr",
    [Nullable[bool]]$TargetEnabled = $null,
    [Nullable[bool]]$TargetAutoFailover = $null,
    [Nullable[int]]$TargetHealthCheckInterval = $null,
    [switch]$SkipStart,
    [switch]$KeepChange,
    [Alias("h", "?")]
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ConsoleScript = Join-Path $RepoRoot "console.ps1"
$EnvFile = Join-Path $RepoRoot ".env.local"
$BaseUrl = "http://127.0.0.1:$Port"

function Show-Usage {
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  .\scripts\test-proxy-pool-runtime.ps1 [options]"
    Write-Host ""
    Write-Host "Common examples:" -ForegroundColor Cyan
    Write-Host "  .\scripts\test-proxy-pool-runtime.ps1"
    Write-Host "  .\scripts\test-proxy-pool-runtime.ps1 -TargetEnabled `$true -TargetAutoFailover `$false -TargetHealthCheckInterval 120"
    Write-Host "  .\scripts\test-proxy-pool-runtime.ps1 -SkipStart -KeepChange"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  -Port <int>                        Default: 8045"
    Write-Host "  -TargetEnabled <bool?>             Optional explicit target"
    Write-Host "  -TargetAutoFailover <bool?>        Optional explicit target"
    Write-Host "  -TargetHealthCheckInterval <int?>  Optional explicit target (seconds)"
    Write-Host "  -SkipStart                         Uses currently running server"
    Write-Host "  -KeepChange                        Do not restore original values"
    Write-Host "  -Help                              Print this usage"
    Write-Host ""
    Write-Host "PowerShell native help:" -ForegroundColor Cyan
    Write-Host "  Get-Help .\scripts\test-proxy-pool-runtime.ps1 -Detailed"
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 76) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("=" * 76) -ForegroundColor Cyan
}

function Write-Step {
    param(
        [int]$Number,
        [string]$Title
    )
    Write-Host ""
    Write-Host ("[{0}] {1}" -f $Number, $Title) -ForegroundColor Yellow
}

function Load-EnvLocal {
    if (-not (Test-Path $EnvFile)) {
        return
    }

    foreach ($raw in Get-Content $EnvFile) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) {
            continue
        }
        $parts = $line.Split("=", 2)
        $name = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"').Trim("'")
        if ($name -and $value -and -not (Get-Item "Env:$name" -ErrorAction SilentlyContinue)) {
            Set-Item -Path "Env:$name" -Value $value
        }
    }
}

function Get-AuthHeaders {
    if (-not $env:GEPHYR_API_KEY) {
        throw "Missing GEPHYR_API_KEY. Set env var or add it to .env.local."
    }
    return @{ Authorization = "Bearer $($env:GEPHYR_API_KEY)" }
}

function Assert-DockerReady {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host ""
        Write-Host "Docker CLI not found in PATH." -ForegroundColor Red
        Write-Host ""
        Write-Host "Install Docker:" -ForegroundColor Yellow
        Write-Host "  Docker Desktop : https://docs.docker.com/desktop/install/windows-install/"
        Write-Host "  winget         : winget install Docker.DockerDesktop"
        Write-Host "  choco          : choco install docker-desktop"
        throw "Missing prerequisite: docker"
    }
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon is not reachable. Start Docker Desktop first."
    }
}

function Wait-ServiceReady {
    param(
        [int]$Attempts = 50,
        [int]$DelayMs = 500
    )

    $headers = Get-AuthHeaders
    for ($i = 0; $i -lt $Attempts; $i++) {
        try {
            $resp = Invoke-WebRequest -Uri "$BaseUrl/healthz" -Headers $headers -UseBasicParsing -TimeoutSec 3
            if ($resp.StatusCode -eq 200) {
                return $true
            }
        } catch {
            Start-Sleep -Milliseconds $DelayMs
        }
    }
    return $false
}

function Start-Server {
    & $ConsoleScript -Command start -EnableAdminApi -Port $Port -ContainerName $ContainerName -Image $Image -DataDir $DataDir
}

function Api-Get {
    param([string]$Path)
    $headers = Get-AuthHeaders
    Invoke-RestMethod -Uri "$BaseUrl$Path" -Headers $headers -Method Get -TimeoutSec 30
}

function Api-PostJson {
    param(
        [string]$Path,
        [object]$Payload
    )
    $headers = Get-AuthHeaders
    $headers["Content-Type"] = "application/json"
    $json = $Payload | ConvertTo-Json -Depth 20
    Invoke-RestMethod -Uri "$BaseUrl$Path" -Headers $headers -Method Post -Body $json -TimeoutSec 30
}

if ($Help.IsPresent) {
    Show-Usage
    return
}

Write-Section "Gephyr Proxy-Pool Runtime Endpoint Smoke Test"
Write-Host "This script validates GET/POST /api/proxy/pool/runtime behavior." -ForegroundColor Gray

if (-not (Test-Path $ConsoleScript)) {
    throw "console.ps1 not found at $ConsoleScript"
}

Load-EnvLocal
Assert-DockerReady
[void](Get-AuthHeaders)

if ($TargetHealthCheckInterval.HasValue -and $TargetHealthCheckInterval.Value -lt 1) {
    throw "TargetHealthCheckInterval must be >= 1."
}

$before = $null
$after = $null
$restoreNeeded = $false

try {
    if (-not $SkipStart.IsPresent) {
        Write-Step 1 "Start server with admin API enabled"
        Start-Server
        if (-not (Wait-ServiceReady)) {
            throw "Service did not become ready on $BaseUrl"
        }
        Write-Host "Service is ready." -ForegroundColor Green
    } else {
        Write-Step 1 "Using running server (SkipStart)"
        if (-not (Wait-ServiceReady -Attempts 5 -DelayMs 300)) {
            throw "Server is not reachable on $BaseUrl."
        }
        Write-Host "Service is reachable." -ForegroundColor Green
    }

    Write-Step 2 "Verify route capability"
    $caps = Api-Get "/api/version/routes"
    if (-not $caps.routes.'GET /api/proxy/pool/runtime' -or -not $caps.routes.'POST /api/proxy/pool/runtime') {
        throw "Running image does not expose GET/POST /api/proxy/pool/runtime."
    }
    Write-Host ("Running version: {0}" -f $caps.version) -ForegroundColor Green

    Write-Step 3 "Read current runtime snapshot"
    $before = Api-Get "/api/proxy/pool/runtime"
    Write-Host ("Before: enabled={0}, auto_failover={1}, health_check_interval={2}, strategy={3}" -f `
        $before.enabled, $before.auto_failover, $before.health_check_interval, $before.strategy) -ForegroundColor Gray

    $nextEnabled = if ($TargetEnabled.HasValue) { $TargetEnabled.Value } else { -not [bool]$before.enabled }
    $nextAutoFailover = if ($TargetAutoFailover.HasValue) { $TargetAutoFailover.Value } else { -not [bool]$before.auto_failover }
    $nextInterval = if ($TargetHealthCheckInterval.HasValue) { $TargetHealthCheckInterval.Value } else { [Math]::Max(30, [int]$before.health_check_interval + 30) }

    if (($nextEnabled -eq [bool]$before.enabled) -and ($nextAutoFailover -eq [bool]$before.auto_failover) -and ($nextInterval -eq [int]$before.health_check_interval)) {
        $nextInterval = [Math]::Max(30, [int]$before.health_check_interval + 60)
        Write-Host ("Derived payload matched current state; bumping health_check_interval to {0}." -f $nextInterval) -ForegroundColor Yellow
    }

    Write-Step 4 "Update runtime knobs via dedicated endpoint"
    $post = Api-PostJson -Path "/api/proxy/pool/runtime" -Payload @{
        enabled = $nextEnabled
        auto_failover = $nextAutoFailover
        health_check_interval = $nextInterval
    }
    if (-not $post.ok -or -not $post.saved) {
        throw "Runtime update endpoint did not return success payload."
    }
    Write-Host ("Updated: enabled={0}, auto_failover={1}, health_check_interval={2}" -f `
        $post.proxy_pool.enabled, $post.proxy_pool.auto_failover, $post.proxy_pool.health_check_interval) -ForegroundColor Green

    Write-Step 5 "Verify persisted runtime snapshot"
    $after = Api-Get "/api/proxy/pool/runtime"
    if ([bool]$after.enabled -ne $nextEnabled) {
        throw "Expected enabled=$nextEnabled, got $($after.enabled)."
    }
    if ([bool]$after.auto_failover -ne $nextAutoFailover) {
        throw "Expected auto_failover=$nextAutoFailover, got $($after.auto_failover)."
    }
    if ([int]$after.health_check_interval -ne $nextInterval) {
        throw "Expected health_check_interval=$nextInterval, got $($after.health_check_interval)."
    }

    $restoreNeeded = -not $KeepChange.IsPresent

    Write-Step 6 "Result summary"
    Write-Host ("Before: enabled={0}, auto_failover={1}, health_check_interval={2}" -f `
        $before.enabled, $before.auto_failover, $before.health_check_interval)
    Write-Host ("After:  enabled={0}, auto_failover={1}, health_check_interval={2}" -f `
        $after.enabled, $after.auto_failover, $after.health_check_interval)
    Write-Host ""
    Write-Host "PASS: Dedicated pool-runtime endpoint is working." -ForegroundColor Green
}
finally {
    if ($restoreNeeded -and $before) {
        try {
            Api-PostJson -Path "/api/proxy/pool/runtime" -Payload @{
                enabled = [bool]$before.enabled
                auto_failover = [bool]$before.auto_failover
                health_check_interval = [int]$before.health_check_interval
            } | Out-Null
            Write-Host ("Restored original runtime knobs: enabled={0}, auto_failover={1}, health_check_interval={2}" -f `
                $before.enabled, $before.auto_failover, $before.health_check_interval) -ForegroundColor Gray
        } catch {
            Write-Host "Warning: failed to restore original runtime knobs automatically." -ForegroundColor Yellow
        }
    } elseif ($KeepChange.IsPresent) {
        Write-Host "KeepChange set: runtime knob changes were kept." -ForegroundColor Gray
    }
}

