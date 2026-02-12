<#
.SYNOPSIS
Smoke-test the dedicated proxy-pool strategy endpoint.

.DESCRIPTION
Validates that `POST /api/proxy/pool/strategy` can update only proxy-pool
strategy without full `/api/config` writes, and that the change is visible via
`GET /api/proxy/pool/strategy`.

.PARAMETER Port
Proxy port. Default: 8045.

.PARAMETER ContainerName
Docker container name used by console.ps1. Default: gephyr.

.PARAMETER Image
Docker image tag used by console.ps1. Default: gephyr:latest.

.PARAMETER DataDir
Gephyr data directory passed to console.ps1.

.PARAMETER TargetStrategy
Desired strategy to test. Default: round_robin.
Allowed: round_robin, random, priority, least_connections, weighted_round_robin.

.PARAMETER SkipStart
Use currently running server instead of starting via console.ps1.

.PARAMETER KeepChange
Do not restore original strategy after the test.

.PARAMETER Help
Print usage/examples and exit.

.EXAMPLE
.\scripts\test-proxy-pool-strategy.ps1

.EXAMPLE
.\scripts\test-proxy-pool-strategy.ps1 -TargetStrategy weighted_round_robin

.EXAMPLE
.\scripts\test-proxy-pool-strategy.ps1 -SkipStart -KeepChange

.EXAMPLE
Get-Help .\scripts\test-proxy-pool-strategy.ps1 -Detailed
#>
param(
    [int]$Port = 8045,
    [string]$ContainerName = "gephyr",
    [string]$Image = "gephyr:latest",
    [string]$DataDir = "$env:USERPROFILE\.gephyr",
    [string]$TargetStrategy = "round_robin",
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
$AllowedStrategies = @(
    "round_robin",
    "random",
    "priority",
    "least_connections",
    "weighted_round_robin"
)

function Show-Usage {
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  .\scripts\test-proxy-pool-strategy.ps1 [options]"
    Write-Host ""
    Write-Host "Common examples:" -ForegroundColor Cyan
    Write-Host "  .\scripts\test-proxy-pool-strategy.ps1"
    Write-Host "  .\scripts\test-proxy-pool-strategy.ps1 -TargetStrategy weighted_round_robin"
    Write-Host "  .\scripts\test-proxy-pool-strategy.ps1 -SkipStart -KeepChange"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  -Port <int>                     Default: 8045"
    Write-Host "  -TargetStrategy <string>        Default: round_robin"
    Write-Host "  -SkipStart                      Uses currently running server"
    Write-Host "  -KeepChange                     Do not restore original strategy"
    Write-Host "  -Help                           Print this usage"
    Write-Host ""
    Write-Host "PowerShell native help:" -ForegroundColor Cyan
    Write-Host "  Get-Help .\scripts\test-proxy-pool-strategy.ps1 -Detailed"
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
    if (-not $env:API_KEY) {
        throw "Missing API_KEY. Set env var or add it to .env.local."
    }
    return @{ Authorization = "Bearer $($env:API_KEY)" }
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

function Select-AlternateStrategy {
    param([string]$Current)
    foreach ($candidate in $AllowedStrategies) {
        if ($candidate -ne $Current) {
            return $candidate
        }
    }
    return $Current
}

if ($Help.IsPresent) {
    Show-Usage
    return
}

Write-Section "Gephyr Proxy-Pool Strategy Endpoint Smoke Test"
Write-Host "This script validates GET/POST /api/proxy/pool/strategy behavior." -ForegroundColor Gray

if (-not (Test-Path $ConsoleScript)) {
    throw "console.ps1 not found at $ConsoleScript"
}

Load-EnvLocal
Assert-DockerReady
[void](Get-AuthHeaders)

$normalizedTarget = $TargetStrategy.Trim().ToLowerInvariant()
if ($AllowedStrategies -notcontains $normalizedTarget) {
    throw "Invalid TargetStrategy '$TargetStrategy'. Allowed: $($AllowedStrategies -join ', ')"
}

$originalStrategy = $null
$updatedStrategy = $null
$restoreAttempted = $false

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
    if (-not $caps.routes.'GET /api/proxy/pool/strategy' -or -not $caps.routes.'POST /api/proxy/pool/strategy') {
        throw "Running image does not expose GET/POST /api/proxy/pool/strategy."
    }
    Write-Host ("Running version: {0}" -f $caps.version) -ForegroundColor Green

    Write-Step 3 "Read current strategy snapshot"
    $before = Api-Get "/api/proxy/pool/strategy"
    $originalStrategy = [string]$before.strategy
    if ([string]::IsNullOrWhiteSpace($originalStrategy)) {
        throw "Current strategy is missing from response."
    }
    Write-Host ("Current strategy: {0}" -f $originalStrategy) -ForegroundColor Gray
    Write-Host ("Pool enabled: {0}, auto_failover: {1}, health_check_interval: {2}" -f $before.enabled, $before.auto_failover, $before.health_check_interval) -ForegroundColor Gray

    if ($normalizedTarget -eq $originalStrategy) {
        $normalizedTarget = Select-AlternateStrategy -Current $originalStrategy
        Write-Host ("Target matched current; using alternate strategy: {0}" -f $normalizedTarget) -ForegroundColor Yellow
    }

    Write-Step 4 "Update strategy via dedicated endpoint"
    $post = Api-PostJson -Path "/api/proxy/pool/strategy" -Payload @{
        strategy = $normalizedTarget
    }
    if (-not $post.ok -or -not $post.saved) {
        throw "Strategy update endpoint did not return success payload."
    }
    $updatedStrategy = [string]$post.proxy_pool.strategy
    Write-Host ("Updated strategy: {0}" -f $updatedStrategy) -ForegroundColor Green

    Write-Step 5 "Verify persisted runtime snapshot"
    $after = Api-Get "/api/proxy/pool/strategy"
    if ([string]$after.strategy -ne $normalizedTarget) {
        throw "Expected strategy '$normalizedTarget', got '$($after.strategy)'."
    }
    Write-Host ("Verified strategy after update: {0}" -f $after.strategy) -ForegroundColor Green

    Write-Step 6 "Result summary"
    Write-Host ("Original strategy: {0}" -f $originalStrategy)
    Write-Host ("Target strategy:   {0}" -f $normalizedTarget)
    Write-Host ("Final strategy:    {0}" -f $after.strategy)
    Write-Host ""
    Write-Host "PASS: Dedicated pool-strategy endpoint is working." -ForegroundColor Green
}
finally {
    if (-not $KeepChange.IsPresent -and $originalStrategy -and $updatedStrategy -and ($originalStrategy -ne $updatedStrategy)) {
        try {
            $restoreAttempted = $true
            Api-PostJson -Path "/api/proxy/pool/strategy" -Payload @{ strategy = $originalStrategy } | Out-Null
            Write-Host ("Restored original strategy: {0}" -f $originalStrategy) -ForegroundColor Gray
        } catch {
            Write-Host "Warning: failed to restore original strategy automatically." -ForegroundColor Yellow
        }
    } elseif ($KeepChange.IsPresent) {
        Write-Host "KeepChange set: strategy left as updated value." -ForegroundColor Gray
    } elseif ($restoreAttempted) {
        Write-Host "Restore attempt completed." -ForegroundColor Gray
    }
}

