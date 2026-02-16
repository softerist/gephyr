param(
    [int]$Port = 8045,
    [string]$Image = "gephyr:latest"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$console = Join-Path $repoRoot "console.ps1"
$envFile = Join-Path $repoRoot ".env.local"

if (-not (Test-Path $console)) {
    throw "console.ps1 not found at $console"
}

function Load-EnvLocal {
    if (-not (Test-Path $envFile)) {
        return
    }
    foreach ($raw in Get-Content $envFile) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) {
            continue
        }
        $parts = $line.Split("=", 2)
        $k = $parts[0].Trim()
        $v = $parts[1].Trim().Trim('"').Trim("'")
        if ($k) {
            [Environment]::SetEnvironmentVariable($k, $v)
        }
    }
}

function Ensure-ApiKey {
    if (-not $env:API_KEY) {
        Load-EnvLocal
    }
    if (-not $env:API_KEY -and (Test-Path $envFile)) {
        $legacy = Get-Content $envFile |
            Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*_API_KEY=' } |
            Select-Object -First 1
        if ($legacy) {
            $env:API_KEY = ($legacy.Split("=", 2)[1]).Trim().Trim('"').Trim("'")
        }
    }
    if (-not $env:API_KEY) {
        throw "Missing API_KEY. Set API_KEY in env or .env.local before running this smoke script."
    }
}

Write-Host "==> Restarting container (admin API enabled)"
& $console restart -EnableAdminApi -Port $Port -Image $Image | Out-Null

Write-Host "==> Health check (/health)"
& $console health -Port $Port -Quiet | Out-Null

Write-Host "==> Fetching /api/version/routes"
$null = Ensure-ApiKey
$cid = "smoke-admin-routes-" + ([guid]::NewGuid().ToString())
$rid = $cid + ":1"
$headers = @{
    Authorization      = "Bearer $($env:API_KEY)"
    "x-correlation-id" = $cid
    "x-request-id"     = $rid
}
$resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/version/routes" -Headers $headers -Method Get -TimeoutSec 10

if (-not $resp -or -not $resp.routes) {
    throw "Smoke failed: /api/version/routes returned unexpected payload"
}

$routeCount = 0
try {
    $routeCount = @($resp.routes.Keys).Count
} catch {
    $routeCount = 0
}
Write-Host "OK smoke-admin-routes (routes keys: $routeCount)"
