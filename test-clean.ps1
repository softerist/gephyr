[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$SkipBuild,
    [switch]$UseBuildCache,
    [switch]$SkipLogin,
    [switch]$NoBrowser,
    [switch]$RunApiTest,
    [switch]$DisableAdminAfter,
    [int]$Port = 8045,
    [string]$Image = "gephyr:latest",
    [string]$Model = "gpt-5.3-codex",
    [string]$Prompt = "hello from gephyr",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CommandArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Check Docker availability early to fail fast with a single message
function Test-DockerAvailable {
    try {
        $null = docker info 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$consoleScript = Join-Path $scriptDir "console.ps1"
$allowGuardScript = Join-Path $scriptDir "scripts/check-allow-attributes.ps1"

if (-not (Test-Path $consoleScript)) {
    throw "Missing script: $consoleScript"
}
if (-not (Test-Path $allowGuardScript)) {
    throw "Missing script: $allowGuardScript"
}

if ($CommandArgs -and $CommandArgs.Count -gt 0) {
    $firstArg = $CommandArgs[0].ToLowerInvariant()
    $passthroughCommands = @("status", "health", "accounts", "login", "restart", "api-test")

    if ($passthroughCommands -contains $firstArg) {
        Write-Host "Forwarding to console.ps1: $($CommandArgs -join ' ')"
        & $consoleScript @CommandArgs
        exit $LASTEXITCODE
    }

    throw "Unknown positional argument(s): $($CommandArgs -join ' '). Use named flags for test-clean.ps1 or call .\console.ps1 <command>."
}

if (-not (Test-DockerAvailable)) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                     DOCKER IS NOT RUNNING                        ║" -ForegroundColor Red
    Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
    Write-Host "║  The Docker daemon is not accessible.                            ║" -ForegroundColor Yellow
    Write-Host "║                                                                  ║" -ForegroundColor Yellow
    Write-Host "║  Please ensure:                                                  ║" -ForegroundColor Yellow
    Write-Host "║    1. Docker Desktop is installed                                ║" -ForegroundColor Yellow
    Write-Host "║    2. Docker Desktop is running (check system tray)              ║" -ForegroundColor Yellow
    Write-Host "║    3. Docker engine has finished starting up                     ║" -ForegroundColor Yellow
    Write-Host "║                                                                  ║" -ForegroundColor Yellow
    Write-Host "║  On Windows, look for the Docker whale icon in your system tray. ║" -ForegroundColor Yellow
    Write-Host "║  If it's animating, Docker is still starting up.                 ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    exit 1
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    Write-Host "==> $Name"
    & $Action
    Write-Host ""
}

function Invoke-DockerBuildWithGuidance {
    param(
        [Parameter(Mandatory = $true)][string[]]$Args
    )

    & docker @Args
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "Docker build failed." -ForegroundColor Red
        Write-Host "Try repairing builder cache, then retry:" -ForegroundColor Yellow
        Write-Host "  .\console.ps1 docker-repair" -ForegroundColor Yellow
        Write-Host "If still failing, use aggressive mode:" -ForegroundColor Yellow
        Write-Host "  .\console.ps1 docker-repair -Aggressive" -ForegroundColor Yellow
        throw "Docker build failed with exit code $LASTEXITCODE"
    }
}

function Wait-OAuthAccountLink {
    param(
        [int]$TimeoutSec = 180,
        [int]$PollSec = 2
    )

    $apiKey = $env:GEPHYR_API_KEY
    if (-not $apiKey) {
        $envPath = Join-Path $scriptDir ".env.local"
        if (Test-Path $envPath) {
            foreach ($raw in Get-Content $envPath) {
                $line = $raw.Trim()
                if ($line -and -not $line.StartsWith("#") -and $line.StartsWith("GEPHYR_API_KEY=")) {
                    $apiKey = $line.Split("=", 2)[1].Trim().Trim('"').Trim("'")
                    break
                }
            }
        }
    }

    if (-not $apiKey) {
        Write-Warning "[W-OAUTH-MISSING-API-KEY] Skipping OAuth wait: GEPHYR_API_KEY is missing (env and .env.local)."
        return $false
    }

    $headers = @{ Authorization = "Bearer $apiKey" }
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $startAt = Get-Date
    $nextProgressAt = $startAt.AddSeconds(10)
    $statusEndpointSupported = $true
    $lastKnownPhase = $null

    Write-Host "Waiting for OAuth callback/account link (timeout: ${TimeoutSec}s)..."
    Write-Host "Complete login in your browser, then this script will continue automatically."

    while ((Get-Date) -lt $deadline) {
        if ($statusEndpointSupported) {
            try {
                $statusResp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/auth/status" -Headers $headers -Method Get -TimeoutSec 8
                $phase = ""
                if ($statusResp -and $statusResp.phase) {
                    $phase = "$($statusResp.phase)".ToLowerInvariant()
                }
                if ($phase) {
                    $lastKnownPhase = $phase
                }

                if ($phase -eq "linked") {
                    if ($statusResp.account_email) {
                        Write-Host "OAuth account linked ($($statusResp.account_email))."
                    } else {
                        Write-Host "OAuth account linked."
                    }
                    return $true
                }
                if ($phase -eq "failed") {
                    $detail = if ($statusResp -and $statusResp.detail) { "$($statusResp.detail)" } else { "unknown_error" }
                    Write-Warning "OAuth wait aborted [E-OAUTH-FLOW-FAILED]: $detail"
                    return $false
                }
                if ($phase -eq "cancelled") {
                    $detail = if ($statusResp -and $statusResp.detail) { "$($statusResp.detail)" } else { "oauth_flow_cancelled" }
                    Write-Warning "OAuth wait aborted [E-OAUTH-FLOW-CANCELLED]: $detail"
                    return $false
                }
            } catch {
                $statusCode = $null
                if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    try {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                    } catch {
                        $statusCode = $null
                    }
                }

                if ($statusCode -eq 401) {
                    Write-Warning "OAuth wait aborted [E-OAUTH-STATUS-401]: /api/auth/status returned 401 Unauthorized. Verify GEPHYR_API_KEY in shell/.env.local and restart container."
                    return $false
                }
                if ($statusCode -eq 404) {
                    Write-Warning "[W-OAUTH-STATUS-UNSUPPORTED] OAuth status endpoint not available on this runtime; falling back to legacy /api/accounts polling."
                    $statusEndpointSupported = $false
                }
            }
        }

        if (-not $statusEndpointSupported) {
            try {
                $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 8
                $count = 0
                if ($resp -and $resp.accounts) {
                    $count = @($resp.accounts).Count
                }
                if ($count -gt 0) {
                    Write-Host "OAuth account linked ($count account(s) found)."
                    return $true
                }
            } catch {
                $statusCode = $null
                if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    try {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                    } catch {
                        $statusCode = $null
                    }
                }

                if ($statusCode -eq 401) {
                    Write-Warning "OAuth wait aborted [E-OAUTH-ACCOUNTS-401]: /api/accounts returned 401 Unauthorized. Verify GEPHYR_API_KEY in shell/.env.local and restart container."
                    return $false
                }
                if ($statusCode -eq 404) {
                    Write-Warning "OAuth wait aborted [E-OAUTH-ACCOUNTS-404]: /api/accounts returned 404. Ensure admin API is enabled (ABV_ENABLE_ADMIN_API=true)."
                    return $false
                }
            }
        }

        $now = Get-Date
        if ($now -ge $nextProgressAt) {
            $elapsed = [int]($now - $startAt).TotalSeconds
            if ($lastKnownPhase) {
                Write-Host "Still waiting for OAuth linkage... ${elapsed}s elapsed (phase: $lastKnownPhase)."
            } else {
                Write-Host "Still waiting for OAuth linkage... ${elapsed}s elapsed."
            }
            try {
                $recentLogs = docker logs --tail 160 gephyr 2>&1
                if ($recentLogs -match "encryption_key_unavailable|Failed to save account in background OAuth") {
                    Write-Warning "OAuth callback succeeded but account persistence failed [E-CRYPTO-KEY-UNAVAILABLE] (missing/invalid ABV_ENCRYPTION_KEY; in Docker/container environments machine UID may be unavailable). Remediation: set ABV_ENCRYPTION_KEY in .env.local, restart container, then rerun login."
                    return $false
                }
                if ($recentLogs -match "OAuth callback state mismatch") {
                    Write-Warning "[E-OAUTH-STATE-MISMATCH] OAuth callback state mismatch detected. Restart login flow and complete only the latest opened OAuth URL."
                    return $false
                }
                if ($recentLogs -match "Background OAuth exchange failed:") {
                    Write-Warning "[E-OAUTH-TOKEN-EXCHANGE] OAuth wait aborted: token exchange failed. Check network/proxy settings and Google OAuth client credentials."
                    return $false
                }
                if ($recentLogs -match "Background OAuth error: Google did not return a refresh_token") {
                    Write-Warning "[E-OAUTH-REFRESH-MISSING] OAuth wait aborted: Google returned no refresh_token. Revoke prior app consent and retry."
                    return $false
                }
                if ($recentLogs -match "Failed to fetch user info in background OAuth:") {
                    Write-Warning "[E-OAUTH-USER-INFO] OAuth wait aborted: token accepted but user-info lookup failed."
                    return $false
                }
            } catch {
                # If docker logs is unavailable temporarily, continue polling.
            }
            $nextProgressAt = $nextProgressAt.AddSeconds(10)
        }

        Start-Sleep -Seconds $PollSec
    }

    Write-Warning "[W-OAUTH-TIMEOUT] Timed out waiting for OAuth account linkage. You can still finish OAuth and rerun .\console.ps1 accounts."
    return $false
}

Invoke-Step -Name "Running allow-attribute guard" -Action {
    & $allowGuardScript
}

if (-not $SkipBuild) {
    Invoke-Step -Name "Building image $Image" -Action {
        $buildArgs = @("build", "-t", $Image, "-f", "docker/Dockerfile", ".")
        if (-not $UseBuildCache) {
            $buildArgs = @("build", "--no-cache", "-t", $Image, "-f", "docker/Dockerfile", ".")
        }
        Invoke-DockerBuildWithGuidance -Args $buildArgs
    }
}

Invoke-Step -Name "Restarting container with admin API enabled" -Action {
    & $consoleScript restart -EnableAdminApi -Image $Image -Port $Port
}

Invoke-Step -Name "Health check" -Action {
    & $consoleScript health -Port $Port
}

if (-not $SkipLogin) {
    if (-not $env:ABV_ENCRYPTION_KEY) {
        $envPath = Join-Path $scriptDir ".env.local"
        $hasEncryptionKey = $false
        if (Test-Path $envPath) {
            foreach ($raw in Get-Content $envPath) {
                $line = $raw.Trim()
                if ($line -and -not $line.StartsWith("#") -and $line.StartsWith("ABV_ENCRYPTION_KEY=")) {
                    $value = $line.Split("=", 2)[1].Trim().Trim('"').Trim("'")
                    if ($value) {
                        $hasEncryptionKey = $true
                    }
                    break
                }
            }
        }
        if (-not $hasEncryptionKey) {
            Write-Warning "[W-CRYPTO-KEY-MISSING] ABV_ENCRYPTION_KEY is not set. In Docker/container environments machine UID may be unavailable, so OAuth callback may succeed in browser while account save fails. Remediation: set ABV_ENCRYPTION_KEY, restart container, then rerun login."
        }
    }

    Invoke-Step -Name "Starting OAuth login flow" -Action {
        & $consoleScript login -NoBrowser:$NoBrowser -Image $Image -Port $Port
    }

    Invoke-Step -Name "Waiting for OAuth account linkage" -Action {
        Wait-OAuthAccountLink | Out-Null
    }
}

Invoke-Step -Name "List accounts" -Action {
    & $consoleScript accounts -Port $Port
}

if ($RunApiTest) {
    Invoke-Step -Name "Run API test" -Action {
        & $consoleScript "api-test" -Model $Model -Prompt $Prompt -Port $Port
    }
}

if ($DisableAdminAfter) {
    Invoke-Step -Name "Restarting with admin API disabled" -Action {
        & $consoleScript restart -Image $Image -Port $Port
    }
}

Write-Host "test-clean completed."
