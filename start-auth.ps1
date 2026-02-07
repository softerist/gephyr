param(
    [Parameter(Position = 0)]
    [string]$Command = "login",
    [switch]$Help,
    [switch]$EnableAdminApi,
    [int]$Port = 8045,
    [string]$ContainerName = "gephyr",
    [string]$Image = "gephyr:latest",
    [string]$DataDir = "$env:USERPROFILE\.gephyr",
    [int]$LogLines = 120,
    [string]$Model = "gpt-4o-mini",
    [string]$Prompt = "hello from gephyr",
    [switch]$NoBrowser,
    [switch]$NoRestartAfterRotate
)

$scriptPath = Join-Path $PSScriptRoot "start-docker.ps1"
if (-not (Test-Path $scriptPath)) {
    Write-Error "Missing script: $scriptPath"
    exit 1
}

if ($Help -or $Command -in @("--help", "-h", "-?", "?", "/help")) {
    $Command = "help"
}

& $scriptPath `
    -Command $Command `
    -EnableAdminApi:$EnableAdminApi `
    -Port $Port `
    -ContainerName $ContainerName `
    -Image $Image `
    -DataDir $DataDir `
    -LogLines $LogLines `
    -Model $Model `
    -Prompt $Prompt `
    -NoBrowser:$NoBrowser `
    -NoRestartAfterRotate:$NoRestartAfterRotate
