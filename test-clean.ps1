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
    [string]$Prompt = "hello from gephyr"
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

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$consoleScript = Join-Path $scriptDir "console.ps1"
$allowGuardScript = Join-Path $scriptDir "scripts/check-allow-attributes.ps1"

if (-not (Test-Path $consoleScript)) {
    throw "Missing script: $consoleScript"
}
if (-not (Test-Path $allowGuardScript)) {
    throw "Missing script: $allowGuardScript"
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
        Write-Warning "Skipping OAuth wait: GEPHYR_API_KEY is missing (env and .env.local)."
        return $false
    }

    $headers = @{ Authorization = "Bearer $apiKey" }
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $startAt = Get-Date
    $nextProgressAt = $startAt.AddSeconds(10)

    Write-Host "Waiting for OAuth callback/account link (timeout: ${TimeoutSec}s)..."
    Write-Host "Complete login in your browser, then this script will continue automatically."

    while ((Get-Date) -lt $deadline) {
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
            # Service may still be transitioning; keep polling.
        }

        $now = Get-Date
        if ($now -ge $nextProgressAt) {
            $elapsed = [int]($now - $startAt).TotalSeconds
            Write-Host "Still waiting for OAuth linkage... ${elapsed}s elapsed."
            $nextProgressAt = $nextProgressAt.AddSeconds(10)
        }

        Start-Sleep -Seconds $PollSec
    }

    Write-Warning "Timed out waiting for OAuth account linkage. You can still finish OAuth and rerun .\console.ps1 accounts."
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
        & docker @buildArgs
    }
}

Invoke-Step -Name "Restarting container with admin API enabled" -Action {
    & $consoleScript restart -EnableAdminApi -Image $Image -Port $Port
}

Invoke-Step -Name "Health check" -Action {
    & $consoleScript health -Port $Port
}

if (-not $SkipLogin) {
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
