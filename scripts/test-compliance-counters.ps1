<#
.SYNOPSIS
Smoke-test compliance counters in Gephyr.

.DESCRIPTION
Starts (or uses) a Gephyr instance, ensures compliance mode is enabled,
sends test traffic, and verifies compliance counters change as expected.
Can optionally run in stress mode with concurrent requests to observe
in-flight counter behavior during active load.

.PARAMETER Port
Proxy port. Default: 8045.

.PARAMETER ContainerName
Docker container name used by console.ps1. Default: gephyr.

.PARAMETER Image
Docker image tag used by console.ps1. Default: gephyr:latest.

.PARAMETER DataDir
Gephyr data directory passed to console.ps1.

.PARAMETER RequestCount
Number of burst requests to send. Default: 5.

.PARAMETER StressMode
Send burst requests concurrently and poll in-flight counters during load.

.PARAMETER PollInFlightAttempts
How many times to poll in-flight counters while stress jobs are running.

.PARAMETER PollInFlightDelayMs
Delay between in-flight polling attempts in milliseconds.

.PARAMETER Model
Primary model to try first.

.PARAMETER FallbackModels
Fallback models used if primary model fails.

.PARAMETER AutoLogin
If no accounts are linked, starts OAuth login flow automatically.

.PARAMETER SkipStart
Use currently running server instead of starting via console.ps1.

.PARAMETER Help
Print usage/examples and exit.

.EXAMPLE
.\scripts\test-compliance-counters.ps1

.EXAMPLE
.\scripts\test-compliance-counters.ps1 -StressMode -RequestCount 10

.EXAMPLE
.\scripts\test-compliance-counters.ps1 -SkipStart -RequestCount 3

.EXAMPLE
Get-Help .\scripts\test-compliance-counters.ps1 -Detailed
#>
param(
    [int]$Port = 8045,
    [string]$ContainerName = "gephyr",
    [string]$Image = "gephyr:latest",
    [string]$DataDir = "$env:USERPROFILE\.gephyr",
    [int]$RequestCount = 5,
    [switch]$StressMode,
    [int]$PollInFlightAttempts = 25,
    [int]$PollInFlightDelayMs = 150,
    [string]$Model = "gpt-5.3-codex",
    [string[]]$FallbackModels = @("gemini-3-flash", "gemini-3.0-flash", "claude-sonnet-4-5"),
    [switch]$AutoLogin,
    [switch]$SkipStart,
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
    Write-Host "  .\scripts\test-compliance-counters.ps1 [options]"
    Write-Host ""
    Write-Host "Common examples:" -ForegroundColor Cyan
    Write-Host "  .\scripts\test-compliance-counters.ps1"
    Write-Host "  .\scripts\test-compliance-counters.ps1 -StressMode -RequestCount 10"
    Write-Host "  .\scripts\test-compliance-counters.ps1 -SkipStart -RequestCount 3"
    Write-Host "  .\scripts\test-compliance-counters.ps1 -AutoLogin"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  -Port <int>                     Default: 8045"
    Write-Host "  -RequestCount <int>             Default: 5"
    Write-Host "  -StressMode                     Concurrent burst + in-flight polling"
    Write-Host "  -PollInFlightAttempts <int>     Default: 25"
    Write-Host "  -PollInFlightDelayMs <int>      Default: 150"
    Write-Host "  -Model <string>                 Default: gpt-5.3-codex"
    Write-Host "  -FallbackModels <string[]>      Default: gemini-3-flash, gemini-3.0-flash, claude-sonnet-4-5"
    Write-Host "  -AutoLogin                      Starts OAuth flow if no account linked"
    Write-Host "  -SkipStart                      Uses currently running server"
    Write-Host "  -Help                           Print this usage"
    Write-Host ""
    Write-Host "PowerShell native help:" -ForegroundColor Cyan
    Write-Host "  Get-Help .\scripts\test-compliance-counters.ps1 -Detailed"
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
    $json = $Payload | ConvertTo-Json -Depth 100
    Invoke-RestMethod -Uri "$BaseUrl$Path" -Headers $headers -Method Post -Body $json -TimeoutSec 60
}

function To-IntMap {
    param([object]$InputObject)
    $map = @{}
    if ($null -eq $InputObject) {
        return $map
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($k in $InputObject.Keys) {
            $map[[string]$k] = [int]$InputObject[$k]
        }
        return $map
    }
    foreach ($p in $InputObject.PSObject.Properties) {
        $map[[string]$p.Name] = [int]$p.Value
    }
    return $map
}

function Ensure-AccountLinked {
    $accountsResp = Api-Get "/api/accounts"
    $accounts = @()
    if ($accountsResp -and $accountsResp.accounts) {
        $accounts = @($accountsResp.accounts)
    }

    if ($accounts.Count -gt 0) {
        return $accounts
    }

    if (-not $AutoLogin.IsPresent) {
        throw "No linked accounts found. Re-run with -AutoLogin or login first."
    }

    Write-Host "No linked accounts found. Starting OAuth login flow..." -ForegroundColor Yellow
    & $ConsoleScript -Command login -Port $Port -ContainerName $ContainerName -Image $Image -DataDir $DataDir

    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 2
        $accountsResp = Api-Get "/api/accounts"
        $accounts = @()
        if ($accountsResp -and $accountsResp.accounts) {
            $accounts = @($accountsResp.accounts)
        }
        if ($accounts.Count -gt 0) {
            return $accounts
        }
    }

    throw "No accounts linked after OAuth flow."
}

function Invoke-TestRequest {
    param(
        [string]$RequestModel,
        [string]$Prompt,
        [switch]$AllowError
    )

    $headers = Get-AuthHeaders
    $headers["Content-Type"] = "application/json"
    $body = @{
        model = $RequestModel
        messages = @(
            @{
                role = "user"
                content = $Prompt
            }
        )
    } | ConvertTo-Json -Depth 8

    try {
        $resp = Invoke-WebRequest -Uri "$BaseUrl/v1/chat/completions" -Method Post -Headers $headers -Body $body -TimeoutSec 120
        return [PSCustomObject]@{
            Status = [int]$resp.StatusCode
            AccountEmail = [string]$resp.Headers["X-Account-Email"]
            MappedModel = [string]$resp.Headers["X-Mapped-Model"]
            Error = $null
        }
    } catch {
        if (-not $AllowError.IsPresent) {
            throw
        }

        $statusCode = 0
        $errorBody = $_.ErrorDetails.Message
        if (-not $errorBody) {
            $errorBody = $_.Exception.Message
        }
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        }
        return [PSCustomObject]@{
            Status = $statusCode
            AccountEmail = $null
            MappedModel = $null
            Error = $errorBody
        }
    }
}

function Select-WorkingModel {
    param([string]$DiscoveryPrompt)

    $candidates = New-Object System.Collections.Generic.List[string]
    $candidates.Add($Model)
    foreach ($m in $FallbackModels) {
        if (-not [string]::IsNullOrWhiteSpace($m) -and -not $candidates.Contains($m)) {
            $candidates.Add($m)
        }
    }

    $failures = @()
    foreach ($candidate in $candidates) {
        Write-Host ("Trying model: {0}" -f $candidate) -ForegroundColor Gray
        $res = Invoke-TestRequest -RequestModel $candidate -Prompt $DiscoveryPrompt -AllowError
        if ($res.Status -eq 200) {
            return [PSCustomObject]@{
                Model = $candidate
                FirstResult = $res
                Failures = $failures
            }
        }

        $failures += [PSCustomObject]@{
            model = $candidate
            status = $res.Status
        }
    }

    $summary = ($failures | ForEach-Object { "$($_.model):$($_.status)" }) -join ", "
    throw "No working model found. Attempts: $summary"
}

Write-Section "Gephyr Compliance Counters Smoke Test"
Write-Host "This script sends a request burst and verifies compliance counters move." -ForegroundColor Gray
Write-Host "Checks:" -ForegroundColor Gray
Write-Host "  - POST /api/proxy/compliance available" -ForegroundColor Gray
Write-Host "  - compliance enabled with provided thresholds" -ForegroundColor Gray
Write-Host "  - global/account request counters increase after traffic" -ForegroundColor Gray
Write-Host "  - optional stress mode to observe in-flight counters during active load" -ForegroundColor Gray

if (-not (Test-Path $ConsoleScript)) {
    throw "console.ps1 not found at $ConsoleScript"
}

if ($Help.IsPresent) {
    Show-Usage
    return
}

Load-EnvLocal
Assert-DockerReady
[void](Get-AuthHeaders)

if ($RequestCount -lt 1) {
    throw "RequestCount must be >= 1"
}
if ($PollInFlightAttempts -lt 1) {
    throw "PollInFlightAttempts must be >= 1"
}
if ($PollInFlightDelayMs -lt 10) {
    throw "PollInFlightDelayMs must be >= 10"
}

if (-not $SkipStart.IsPresent) {
    Write-Step 1 "Start server with admin API enabled"
    Start-Server
    if (-not (Wait-ServiceReady)) {
        throw "Service did not become ready on $BaseUrl"
    }
    Write-Host "Service is ready." -ForegroundColor Green
} else {
    Write-Step 1 "Using running server (SkipStart)"
}

Write-Step 2 "Verify route capability"
$cap = Api-Get "/api/version/routes"
$hasCompliancePost = $false
if ($cap -and $cap.routes) {
    $hasCompliancePost = [bool]$cap.routes.'POST /api/proxy/compliance'
}
if (-not $hasCompliancePost) {
    throw "Running image does not expose POST /api/proxy/compliance. Rebuild/restart image."
}
Write-Host ("Running version: {0}" -f $cap.version) -ForegroundColor Green

Write-Step 3 "Ensure at least one account is linked"
$accounts = Ensure-AccountLinked
Write-Host ("Linked accounts: {0}" -f $accounts.Count) -ForegroundColor Green

Write-Step 4 "Enable compliance via dedicated endpoint"
$compliancePayload = @{
    enabled = $true
    max_global_requests_per_minute = 120
    max_account_requests_per_minute = 20
    max_account_concurrency = 2
    risk_cooldown_seconds = 300
    max_retry_attempts = 2
}
$updateResp = Api-PostJson -Path "/api/proxy/compliance" -Payload $compliancePayload
$hasOkField = ($null -ne $updateResp) -and ($updateResp.PSObject.Properties.Name -contains "ok")
if ($hasOkField -and -not [bool]$updateResp.ok) {
    throw "Compliance update endpoint reported failure."
}

$verify = Api-Get "/api/proxy/compliance"
if (-not $verify -or -not $verify.config -or -not [bool]$verify.config.enabled) {
    throw "Compliance config was not enabled after update call."
}
Write-Host "Compliance config updated." -ForegroundColor Green

Write-Step 5 "Capture counters before traffic"
$before = $verify
$beforeGlobal = [int]$before.global_requests_in_last_minute
$beforeAccountMap = To-IntMap -InputObject $before.account_requests_in_last_minute
Write-Host (
    "Captured snapshot: global={0}, accounts={1}, cooldowns={2}" -f
    $beforeGlobal,
    $beforeAccountMap.Count,
    (To-IntMap -InputObject $before.account_cooldown_seconds_remaining).Count
) -ForegroundColor Gray

Write-Step 6 "Pick a working model and send request burst"
$runId = [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss")
$discoveryPrompt = "Compliance smoke discovery run=$runId"
$selected = Select-WorkingModel -DiscoveryPrompt $discoveryPrompt
$selectedModel = [string]$selected.Model
$probeRequests = @($selected.Failures).Count + 1
Write-Host ("Selected model: {0}" -f $selectedModel) -ForegroundColor Green

$sent = 0
$ok = 0
$accountHits = @{}
$peakInFlightObserved = 0

if ($StressMode.IsPresent) {
    Write-Host ("Stress mode enabled: launching {0} concurrent requests..." -f $RequestCount) -ForegroundColor Yellow

    $jobs = @()
    for ($i = 1; $i -le $RequestCount; $i++) {
        $prompt = "Compliance stress request $i run=$runId. Reply in one sentence."
        $jobs += Start-Job -ArgumentList $BaseUrl, $env:API_KEY, $selectedModel, $prompt, $i -ScriptBlock {
            param($baseUrl, $apiKey, $model, $prompt, $index)
            $headers = @{
                Authorization = "Bearer $apiKey"
                "Content-Type" = "application/json"
            }
            $body = @{
                model = $model
                messages = @(
                    @{
                        role = "user"
                        content = $prompt
                    }
                )
            } | ConvertTo-Json -Depth 8

            try {
                $resp = Invoke-WebRequest -Uri "$baseUrl/v1/chat/completions" -Method Post -Headers $headers -Body $body -TimeoutSec 120
                [PSCustomObject]@{
                    Index = [int]$index
                    Status = [int]$resp.StatusCode
                    AccountEmail = [string]$resp.Headers["X-Account-Email"]
                    Error = $null
                }
            } catch {
                $statusCode = 0
                $errorBody = $_.ErrorDetails.Message
                if (-not $errorBody) {
                    $errorBody = $_.Exception.Message
                }
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
                }
                [PSCustomObject]@{
                    Index = [int]$index
                    Status = [int]$statusCode
                    AccountEmail = $null
                    Error = [string]$errorBody
                }
            }
        }
    }

    for ($p = 1; $p -le $PollInFlightAttempts; $p++) {
        $running = @($jobs | Where-Object { $_.State -eq "Running" }).Count
        if ($running -eq 0) {
            break
        }
        try {
            $snap = Api-Get "/api/proxy/compliance"
            $inFlightMapDuring = To-IntMap -InputObject $snap.account_in_flight
            $inFlightTotalDuring = (($inFlightMapDuring.Values | Measure-Object -Sum).Sum)
            if ($null -eq $inFlightTotalDuring) { $inFlightTotalDuring = 0 }
            if ($inFlightTotalDuring -gt $peakInFlightObserved) {
                $peakInFlightObserved = [int]$inFlightTotalDuring
            }
        } catch {
            # Best-effort polling only; request results are authoritative.
        }
        Start-Sleep -Milliseconds $PollInFlightDelayMs
    }

    Wait-Job -Job $jobs | Out-Null
    $results = Receive-Job -Job $jobs
    Remove-Job -Job $jobs | Out-Null

    foreach ($res in ($results | Sort-Object Index)) {
        $sent++
        if ($res.Status -eq 200) {
            $ok++
            if ($res.AccountEmail) {
                if (-not $accountHits.ContainsKey($res.AccountEmail)) {
                    $accountHits[$res.AccountEmail] = 0
                }
                $accountHits[$res.AccountEmail]++
            }
            Write-Host ("  #{0}: 200 ({1})" -f $res.Index, $res.AccountEmail) -ForegroundColor DarkGreen
        } else {
            Write-Host ("  #{0}: {1}" -f $res.Index, $res.Status) -ForegroundColor Yellow
        }
    }
} else {
    for ($i = 1; $i -le $RequestCount; $i++) {
        $prompt = "Compliance smoke request $i run=$runId. Reply in one sentence."
        $res = Invoke-TestRequest -RequestModel $selectedModel -Prompt $prompt -AllowError
        $sent++
        if ($res.Status -eq 200) {
            $ok++
            if ($res.AccountEmail) {
                if (-not $accountHits.ContainsKey($res.AccountEmail)) {
                    $accountHits[$res.AccountEmail] = 0
                }
                $accountHits[$res.AccountEmail]++
            }
            Write-Host ("  #{0}: 200 ({1})" -f $i, $res.AccountEmail) -ForegroundColor DarkGreen
        } else {
            Write-Host ("  #{0}: {1}" -f $i, $res.Status) -ForegroundColor Yellow
        }
    }
}

if ($ok -eq 0) {
    throw "All smoke requests failed. Cannot validate counter movement."
}

Write-Step 7 "Capture counters after traffic"
$after = Api-Get "/api/proxy/compliance"
$afterGlobal = [int]$after.global_requests_in_last_minute
$afterAccountMap = To-IntMap -InputObject $after.account_requests_in_last_minute
$afterInFlight = To-IntMap -InputObject $after.account_in_flight
$afterCooldown = To-IntMap -InputObject $after.account_cooldown_seconds_remaining
Write-Host (
    "Captured snapshot: global={0}, accounts={1}, cooldowns={2}" -f
    $afterGlobal,
    $afterAccountMap.Count,
    $afterCooldown.Count
) -ForegroundColor Gray

$globalDelta = $afterGlobal - $beforeGlobal
$burstRequests = $sent
$expectedTracked = $probeRequests + $burstRequests

Write-Step 8 "Result summary"
Write-Host ("Probe requests:     {0}" -f $probeRequests)
Write-Host ("Burst requests:     {0}" -f $burstRequests)
Write-Host ("Expected tracked:   {0}" -f $expectedTracked)
Write-Host ("Requests sent:      {0}" -f $sent)
Write-Host ("Requests succeeded: {0}" -f $ok)
Write-Host ("Model used:         {0}" -f $selectedModel)
Write-Host ("Global before:      {0}" -f $beforeGlobal)
Write-Host ("Global after:       {0}" -f $afterGlobal)
Write-Host ("Global delta:       {0}" -f $globalDelta)

if ($accountHits.Count -gt 0) {
    Write-Host ""
    Write-Host "Observed account hits (from response headers):"
    foreach ($k in $accountHits.Keys) {
        Write-Host ("  {0}: {1}" -f $k, $accountHits[$k])
    }
}

Write-Host ""
Write-Host "Account counter deltas:"
$keys = New-Object System.Collections.Generic.HashSet[string]
foreach ($k in $beforeAccountMap.Keys) { [void]$keys.Add([string]$k) }
foreach ($k in $afterAccountMap.Keys) { [void]$keys.Add([string]$k) }

if ($keys.Count -eq 0) {
    Write-Host "  (no account counters recorded)"
} else {
    foreach ($k in $keys) {
        $b = if ($beforeAccountMap.ContainsKey($k)) { $beforeAccountMap[$k] } else { 0 }
        $a = if ($afterAccountMap.ContainsKey($k)) { $afterAccountMap[$k] } else { 0 }
        $d = $a - $b
        Write-Host ("  {0}: {1} -> {2} (delta {3})" -f $k, $b, $a, $d)
    }
}

Write-Host ""
Write-Host ("In-flight map now:  {0}" -f (($afterInFlight | ConvertTo-Json -Compress)))
Write-Host ("Cooldown map now:   {0}" -f (($afterCooldown | ConvertTo-Json -Compress)))
if ($StressMode.IsPresent) {
    Write-Host ("Peak in-flight observed during load: {0}" -f $peakInFlightObserved)
}

if ($globalDelta -lt 1) {
    throw "FAIL: global compliance counter did not increase."
}

Write-Host ""
Write-Host "PASS: Compliance counters moved after request burst." -ForegroundColor Green
