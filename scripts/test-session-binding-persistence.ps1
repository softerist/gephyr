<#
.SYNOPSIS
Validate sticky session binding persistence across container restart.

.DESCRIPTION
Runs an end-to-end flow:
1) Starts Gephyr with admin API enabled
2) Verifies sticky/persistence config prerequisites
3) Sends a deterministic-session request
4) Confirms session binding file entry exists
5) Restarts container
6) Sends same-session request and confirms binding continuity

.PARAMETER Port
Proxy port. Default: 8045.

.PARAMETER ContainerName
Docker container name used by console.ps1. Default: gephyr.

.PARAMETER Image
Docker image tag used by console.ps1. Default: gephyr:latest.

.PARAMETER DataDir
Gephyr data directory passed to console.ps1.

.PARAMETER Model
Primary model to try first.

.PARAMETER FallbackModels
Fallback models if primary model fails.

.PARAMETER Prompt
Base prompt used to derive deterministic session_id.

.PARAMETER AutoLogin
If no accounts linked, starts OAuth login flow automatically.

.PARAMETER NoPause
Skips interactive "Press Enter" pause before restart step.

.PARAMETER Help
Print usage/examples and exit.

.EXAMPLE
.\scripts\test-session-binding-persistence.ps1

.EXAMPLE
.\scripts\test-session-binding-persistence.ps1 -AutoLogin -NoPause

.EXAMPLE
Get-Help .\scripts\test-session-binding-persistence.ps1 -Detailed
#>
param(
    [int]$Port = 8045,
    [string]$ContainerName = "gephyr",
    [string]$Image = "gephyr:latest",
    [string]$DataDir = "$env:USERPROFILE\.gephyr",
    [string]$Model = "gpt-5.3-codex",
    [string[]]$FallbackModels = @("gemini-3-flash", "gemini-3.0-flash", "claude-sonnet-4-5"),
    [string]$Prompt = "Persistent session binding validation prompt for restart testing.",
    [switch]$AutoLogin,
    [switch]$NoPause,
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
    Write-Host "  .\scripts\test-session-binding-persistence.ps1 [options]"
    Write-Host ""
    Write-Host "Common examples:" -ForegroundColor Cyan
    Write-Host "  .\scripts\test-session-binding-persistence.ps1"
    Write-Host "  .\scripts\test-session-binding-persistence.ps1 -AutoLogin -NoPause"
    Write-Host "  .\scripts\test-session-binding-persistence.ps1 -Model gemini-3-flash -NoPause"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  -Port <int>                     Default: 8045"
    Write-Host "  -ContainerName <string>         Default: gephyr"
    Write-Host "  -Image <string>                 Default: gephyr:latest"
    Write-Host "  -DataDir <string>               Default: %USERPROFILE%\.gephyr"
    Write-Host "  -Model <string>                 Default: gpt-5.3-codex"
    Write-Host "  -FallbackModels <string[]>      Default: gemini-3-flash, gemini-3.0-flash, claude-sonnet-4-5"
    Write-Host "  -Prompt <string>                Base prompt for deterministic session id"
    Write-Host "  -AutoLogin                      Starts OAuth flow if no account linked"
    Write-Host "  -NoPause                        Skips interactive pause before restart"
    Write-Host "  -Help                           Print this usage"
    Write-Host ""
    Write-Host "PowerShell native help:" -ForegroundColor Cyan
    Write-Host "  Get-Help .\scripts\test-session-binding-persistence.ps1 -Detailed"
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

function Pause-IfNeeded {
    param([string]$Message = "Press Enter to continue")
    if (-not $NoPause.IsPresent) {
        [void](Read-Host $Message)
    }
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

function Stop-Server {
    & $ConsoleScript -Command stop -Port $Port -ContainerName $ContainerName -Image $Image -DataDir $DataDir
}

function Start-LoginFlow {
    & $ConsoleScript -Command login -Port $Port -ContainerName $ContainerName -Image $Image -DataDir $DataDir
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

function Has-ObjectProperty {
    param(
        [object]$Object,
        [string]$Name
    )
    return ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name)
}

function Get-SessionIdFromPrompt {
    param([string]$Text)

    $clean = $Text.Trim()
    if ($clean.Length -le 10) {
        throw "Prompt must be > 10 chars to match OpenAI session extraction logic."
    }
    if ($clean.Contains("<system-reminder>")) {
        throw "Prompt cannot contain '<system-reminder>' for deterministic session-id generation."
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($clean)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $hex = ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
    return "sid-$($hex.Substring(0,16))"
}

function Invoke-TestRequest {
    param(
        [string]$MessageText,
        [string]$RequestModel = $Model,
        [switch]$AllowError
    )

    $headers = Get-AuthHeaders
    $headers["Content-Type"] = "application/json"

    $body = @{
        model = $RequestModel
        messages = @(
            @{
                role = "user"
                content = $MessageText
            }
        )
    } | ConvertTo-Json -Depth 8

    try {
        $resp = Invoke-WebRequest -Uri "$BaseUrl/v1/chat/completions" -Method Post -Headers $headers -Body $body -TimeoutSec 120
        $json = $null
        if ($resp.Content) {
            try { $json = $resp.Content | ConvertFrom-Json } catch {}
        }

        $email = $null
        if ($resp.Headers["X-Account-Email"]) {
            $email = [string]$resp.Headers["X-Account-Email"]
        }

        return [PSCustomObject]@{
            status = [int]$resp.StatusCode
            account_email = $email
            response_id = if ($json) { $json.id } else { $null }
            mapped_model = $resp.Headers["X-Mapped-Model"]
            request_model = $RequestModel
            error_message = $null
        }
    } catch {
        $statusCode = $null
        $errorBody = $_.ErrorDetails.Message
        if (-not $errorBody) {
            $errorBody = $_.Exception.Message
        }

        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        }
        if (-not $statusCode -and $errorBody -match '"code"\s*:\s*(\d{3})') {
            $statusCode = [int]$matches[1]
        }
        if (-not $statusCode) {
            $statusCode = 0
        }

        if (-not $AllowError.IsPresent) {
            throw
        }

        return [PSCustomObject]@{
            status = $statusCode
            account_email = $null
            response_id = $null
            mapped_model = $null
            request_model = $RequestModel
            error_message = $errorBody
        }
    }
}

function Invoke-TestRequestWithModelFallback {
    param([string]$MessageText)

    $candidates = @()
    $candidates += $Model
    foreach ($m in $FallbackModels) {
        if (-not [string]::IsNullOrWhiteSpace($m)) {
            $candidates += $m
        }
    }

    $unique = New-Object System.Collections.Generic.List[string]
    foreach ($m in $candidates) {
        if (-not $unique.Contains($m)) {
            $unique.Add($m)
        }
    }

    $attempts = @()
    foreach ($candidate in $unique) {
        Write-Host ("Trying model: {0}" -f $candidate) -ForegroundColor Gray
        $res = Invoke-TestRequest -MessageText $MessageText -RequestModel $candidate -AllowError
        if ($res.status -eq 200) {
            return @{
                Success = $true
                Result = $res
                Attempts = $attempts
            }
        }

        $attempts += [PSCustomObject]@{
            model = $candidate
            status = $res.status
            error = $res.error_message
        }
    }

    return @{
        Success = $false
        Result = $null
        Attempts = $attempts
    }
}

function Get-BindingMap {
    $path = Join-Path $DataDir "session_bindings.json"
    if (-not (Test-Path $path)) {
        return @{ Path = $path; Map = @{}; Exists = $false }
    }
    $raw = Get-Content -Path $path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @{ Path = $path; Map = @{}; Exists = $true }
    }
    $map = ConvertFrom-Json -InputObject $raw -AsHashtable
    if ($null -eq $map) {
        $map = @{}
    }
    return @{ Path = $path; Map = $map; Exists = $true }
}

Write-Section "Gephyr Persistent Session Binding Restart Test"
Write-Host "This script validates sticky session continuity across container restart." -ForegroundColor Gray
Write-Host "Validation signals used:" -ForegroundColor Gray
Write-Host "  - same deterministic session_id before/after restart" -ForegroundColor Gray
Write-Host "  - same X-Account-Email before/after restart" -ForegroundColor Gray
Write-Host "  - session key present in session_bindings.json" -ForegroundColor Gray

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

$originalPreferredAccount = $null
$shouldRestorePreferred = $false

try {
    Write-Step 1 "Start server with admin API enabled"
    Start-Server
    if (-not (Wait-ServiceReady)) {
        throw "Service did not become ready on $BaseUrl"
    }
    Write-Host "Service is ready." -ForegroundColor Green

    Write-Step 2 "Check config prerequisites (persist_session_bindings + scheduling mode)"
    $cap = Api-Get "/api/version/routes"
    $hasStickyPatch = $false
    if ($cap -and $cap.routes) {
        $hasStickyPatch = [bool]$cap.routes.'POST /api/proxy/sticky'
    }
    $cfg = Api-Get "/api/config"
    $configChanged = $false

    if ($null -eq $cfg.proxy) {
        throw "Runtime /api/config response is missing 'proxy'. Cannot validate prerequisites."
    }

    $hasPersistSnake = Has-ObjectProperty -Object $cfg.proxy -Name "persist_session_bindings"
    $hasPersistCamel = Has-ObjectProperty -Object $cfg.proxy -Name "persistSessionBindings"

    if (-not ($hasPersistSnake -or $hasPersistCamel)) {
        throw @"
Current runtime does not expose proxy.persist_session_bindings in /api/config.
This usually means the running image is older than the persistence implementation.

Rebuild and run the latest local image, then rerun this script:
  docker build -t gephyr:latest -f docker/Dockerfile .
"@
    }

    $persistEnabled = if ($hasPersistSnake) {
        [bool]$cfg.proxy.persist_session_bindings
    } else {
        [bool]$cfg.proxy.persistSessionBindings
    }

    if (-not $persistEnabled) {
        Write-Host "persist_session_bindings=false -> enabling it for this test." -ForegroundColor Yellow
        if ($hasPersistSnake) {
            $cfg.proxy.persist_session_bindings = $true
        } else {
            $cfg.proxy.persistSessionBindings = $true
        }
        $configChanged = $true
    }

    $hasScheduling = Has-ObjectProperty -Object $cfg.proxy -Name "scheduling"
    if (-not $hasScheduling -or $null -eq $cfg.proxy.scheduling) {
        throw "Runtime /api/config is missing proxy.scheduling. Cannot validate sticky mode prerequisite."
    }

    $hasSchedulingMode = Has-ObjectProperty -Object $cfg.proxy.scheduling -Name "mode"
    if (-not $hasSchedulingMode) {
        throw "Runtime /api/config is missing proxy.scheduling.mode. Cannot validate sticky mode prerequisite."
    }

    $currentMode = [string]$cfg.proxy.scheduling.mode
    if ($currentMode -eq "performance_first" -or $currentMode -eq "PerformanceFirst") {
        Write-Host "scheduling.mode=performance_first disables sticky behavior -> switching to balance for this test." -ForegroundColor Yellow
        $cfg.proxy.scheduling.mode = "Balance"
        $configChanged = $true
    }

    if ($configChanged) {
        if ($hasStickyPatch) {
            $persistTarget = if ($hasPersistSnake) {
                [bool]$cfg.proxy.persist_session_bindings
            } else {
                [bool]$cfg.proxy.persistSessionBindings
            }
            $maxWait = 60
            if (Has-ObjectProperty -Object $cfg.proxy.scheduling -Name "max_wait_seconds") {
                $maxWait = [int]$cfg.proxy.scheduling.max_wait_seconds
            } elseif (Has-ObjectProperty -Object $cfg.proxy.scheduling -Name "maxWaitSeconds") {
                $maxWait = [int]$cfg.proxy.scheduling.maxWaitSeconds
            }

            Api-PostJson -Path "/api/proxy/sticky" -Payload @{
                persist_session_bindings = $persistTarget
                scheduling = @{
                    mode = [string]$cfg.proxy.scheduling.mode
                    max_wait_seconds = $maxWait
                }
            } | Out-Null
            Write-Host "Sticky config updated via /api/proxy/sticky (hot-applied)." -ForegroundColor Green
        } else {
            Api-PostJson -Path "/api/config" -Payload @{ config = $cfg } | Out-Null
            Write-Host "Config updated. Restarting server so token manager picks up changes..." -ForegroundColor Yellow
            Stop-Server
            Start-Server
            if (-not (Wait-ServiceReady)) {
                throw "Service did not become ready after config restart."
            }
        }
    } else {
        Write-Host "Config looks good for persistence test." -ForegroundColor Green
    }

    Write-Step 3 "Neutralize preferred-account override (if set)"
    $preferred = Api-Get "/api/proxy/preferred-account"
    if ($null -ne $preferred -and -not [string]::IsNullOrWhiteSpace([string]$preferred)) {
        $originalPreferredAccount = [string]$preferred
        $shouldRestorePreferred = $true
        Write-Host "Preferred account was set to: $originalPreferredAccount. Temporarily clearing it for sticky-session validation." -ForegroundColor Yellow
        Api-PostJson -Path "/api/proxy/preferred-account" -Payload @{ accountId = $null } | Out-Null
    } else {
        Write-Host "No preferred account override detected." -ForegroundColor Green
    }

    Write-Step 4 "Ensure at least one linked account exists"
    $accountsResp = Api-Get "/api/accounts"
    $accounts = @()
    if ($accountsResp -and $accountsResp.accounts) {
        $accounts = @($accountsResp.accounts)
    }

    if ($accounts.Count -eq 0) {
        Write-Host "No linked accounts found." -ForegroundColor Yellow
        if ($AutoLogin.IsPresent) {
            Write-Host "Starting OAuth login flow..." -ForegroundColor Yellow
            Start-LoginFlow
            Pause-IfNeeded "Complete browser OAuth login now, then press Enter"
            $accountReady = $false
            for ($i = 0; $i -lt 30; $i++) {
                Start-Sleep -Seconds 2
                $accountsResp = Api-Get "/api/accounts"
                $accounts = @()
                if ($accountsResp -and $accountsResp.accounts) {
                    $accounts = @($accountsResp.accounts)
                }
                if ($accounts.Count -gt 0) {
                    $accountReady = $true
                    break
                }
            }
            if (-not $accountReady) {
                throw "No accounts linked after OAuth flow."
            }
        } else {
            throw "No linked accounts found. Re-run with -AutoLogin or link account(s) first."
        }
    }

    Write-Host ("Linked accounts: {0}" -f $accounts.Count) -ForegroundColor Green
    if ($accounts.Count -lt 2) {
        Write-Host "Note: only one account linked. This still tests persistence, but account-stickiness proof is weaker than multi-account." -ForegroundColor Yellow
    }

    $emailToId = @{}
    foreach ($acc in $accounts) {
        if ($acc.email -and $acc.id) {
            $emailToId[[string]$acc.email] = [string]$acc.id
        }
    }

    Write-Step 5 "Create deterministic test session and send pre-restart request"
    $runId = [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss")
    $testPrompt = "$Prompt run=$runId please answer in one short sentence."
    $sessionId = Get-SessionIdFromPrompt -Text $testPrompt
    Write-Host "Derived session_id: $sessionId" -ForegroundColor Gray

    $modelSelection = Invoke-TestRequestWithModelFallback -MessageText $testPrompt
    if (-not $modelSelection.Success) {
        $attemptSummary = ($modelSelection.Attempts | ForEach-Object { "$($_.model):$($_.status)" }) -join ", "
        throw "No test model succeeded. Attempts: $attemptSummary"
    }

    $before = $modelSelection.Result
    $selectedModel = [string]$before.request_model
    Write-Host ("Selected working model for this test run: {0}" -f $selectedModel) -ForegroundColor Green

    if ($before.status -ne 200) {
        throw "Pre-restart request failed with status $($before.status)."
    }
    if (-not $before.account_email) {
        throw "Pre-restart response did not include X-Account-Email; cannot validate binding."
    }
    Write-Host ("Pre-restart account: {0}" -f $before.account_email) -ForegroundColor Green

    Write-Step 6 "Verify session binding file entry exists before restart"
    $bindingInfoBefore = Get-BindingMap
    if (-not $bindingInfoBefore.Exists) {
        throw "Binding file not found: $($bindingInfoBefore.Path)"
    }
    $boundAccountIdBefore = $bindingInfoBefore.Map[$sessionId]
    if (-not $boundAccountIdBefore) {
        throw "Session id '$sessionId' not found in $($bindingInfoBefore.Path)"
    }
    Write-Host ("session_bindings.json maps {0} -> {1}" -f $sessionId, $boundAccountIdBefore) -ForegroundColor Green

    if ($emailToId.ContainsKey($before.account_email)) {
        $expectedId = $emailToId[$before.account_email]
        if ($expectedId -ne [string]$boundAccountIdBefore) {
            Write-Host ("Warning: header email maps to account id '{0}', but file has '{1}'." -f $expectedId, $boundAccountIdBefore) -ForegroundColor Yellow
        }
    } else {
        Write-Host "Warning: pre-restart account email not found in current /api/accounts response." -ForegroundColor Yellow
    }

    Pause-IfNeeded

    Write-Step 7 "Stop container (simulate downtime) and start again"
    Stop-Server
    Start-Server
    if (-not (Wait-ServiceReady)) {
        throw "Service did not become ready after restart."
    }
    Write-Host "Service restarted and healthy." -ForegroundColor Green

    Write-Step 8 "Send same-session request after restart"
    $after = Invoke-TestRequest -MessageText $testPrompt -RequestModel $selectedModel
    if ($after.status -ne 200) {
        throw "Post-restart request failed with status $($after.status)."
    }
    if (-not $after.account_email) {
        throw "Post-restart response did not include X-Account-Email; cannot validate binding."
    }
    Write-Host ("Post-restart account: {0}" -f $after.account_email) -ForegroundColor Green

    Write-Step 9 "Re-check binding file and conclude"
    $bindingInfoAfter = Get-BindingMap
    $boundAccountIdAfter = $bindingInfoAfter.Map[$sessionId]
    if (-not $boundAccountIdAfter) {
        throw "Session id '$sessionId' missing from binding file after restart."
    }

    $sameEmail = ($before.account_email -eq $after.account_email)
    $sameFileBinding = ([string]$boundAccountIdBefore -eq [string]$boundAccountIdAfter)

    Write-Host ""
    Write-Host "Result summary:" -ForegroundColor Cyan
    Write-Host ("  session_id:          {0}" -f $sessionId)
    Write-Host ("  pre account email:   {0}" -f $before.account_email)
    Write-Host ("  post account email:  {0}" -f $after.account_email)
    Write-Host ("  file binding before: {0}" -f $boundAccountIdBefore)
    Write-Host ("  file binding after:  {0}" -f $boundAccountIdAfter)

    if ($sameEmail -and $sameFileBinding) {
        Write-Host ""
        Write-Host "PASS: Session binding persisted and restored across restart." -ForegroundColor Green
    } else {
        throw "FAIL: Binding continuity check failed (email match: $sameEmail, file binding match: $sameFileBinding)."
    }
}
finally {
    if ($shouldRestorePreferred -and $originalPreferredAccount) {
        try {
            Api-PostJson -Path "/api/proxy/preferred-account" -Payload @{ accountId = $originalPreferredAccount } | Out-Null
            Write-Host "Restored original preferred account: $originalPreferredAccount" -ForegroundColor Gray
        } catch {
            Write-Host "Warning: failed to restore preferred account automatically: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
