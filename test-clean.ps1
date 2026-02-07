param(
    [switch]$SkipBuild,
    [switch]$UseBuildCache,
    [switch]$SkipLogin,
    [switch]$NoBrowser,
    [switch]$RunApiTest,
    [switch]$DisableAdminAfter,
    [string]$Image = "gephyr:latest",
    [string]$Model = "gpt-4o-mini",
    [string]$Prompt = "hello from gephyr"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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
