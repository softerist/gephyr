param(
    [switch]$SkipBuild,
    [switch]$UseBuildCache,
    [switch]$SkipLogin,
    [switch]$NoBrowser,
    [switch]$RunApiTest,
    [switch]$DisableAdminAfter,
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

if (-not (Test-Path $consoleScript)) {
    throw "Missing script: $consoleScript"
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
    & $consoleScript restart -EnableAdminApi -Image $Image
}

Invoke-Step -Name "Health check" -Action {
    & $consoleScript health
}

if (-not $SkipLogin) {
    Invoke-Step -Name "Starting OAuth login flow" -Action {
        & $consoleScript login -NoBrowser:$NoBrowser -Image $Image
    }
}

Invoke-Step -Name "List accounts" -Action {
    & $consoleScript accounts
}

if ($RunApiTest) {
    Invoke-Step -Name "Run API test" -Action {
        & $consoleScript "api-test" -Model $Model -Prompt $Prompt
    }
}

if ($DisableAdminAfter) {
    Invoke-Step -Name "Restarting with admin API disabled" -Action {
        & $consoleScript restart -Image $Image
    }
}

Write-Host "test-clean completed."
