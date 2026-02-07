param(
    [Parameter(Position = 0)]
    [string]$Command = "start",
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

$ErrorActionPreference = "Stop"
$envFilePath = Join-Path $PSScriptRoot ".env.local"

function Write-Usage {
    @"
Usage:
  .\start-docker.ps1 <command> [options]
  .\start-docker.ps1 -Command <command> [options]

Commands:
  help         Show this help
  start        Start container (default)
  stop         Stop and remove container
  restart      Restart container
  status       Show container status
  logs         Show container logs
  health       Call /healthz with API key
  login        Start container with admin API, fetch /api/auth/url, open browser
  oauth/auth   Alias for login
  accounts     Call /api/accounts
  api-test     Run one API test completion
  rotate-key   Generate new API key, save to .env.local, and optionally restart
  logout       Remove linked account(s) via admin API
  logout-and-stop  Logout accounts, then stop container

Options:
  -EnableAdminApi        Enable admin API on start/restart (default false)
  -Port <int>            Host port (default 8045)
  -ContainerName <name>  Container name (default gephyr)
  -Image <name>          Docker image (default gephyr:latest)
  -DataDir <path>        Host data dir (default %USERPROFILE%\.gephyr)
  -LogLines <int>        Number of log lines for logs command (default 120)
  -Model <name>          Model for api-test (default gpt-4o-mini)
  -Prompt <text>         Prompt for api-test
  -NoBrowser             Do not open browser for login command
  -NoRestartAfterRotate  Rotate key without container restart

Examples:
  .\start-docker.ps1 start
  .\start-docker.ps1 login
  .\start-docker.ps1 logs -LogLines 200
  .\start-docker.ps1 rotate-key
  .\start-docker.ps1 logout
  .\start-docker.ps1 logout-and-stop
  .\start-docker.ps1 -Command login

Troubleshooting:
  If health returns 401, your local GEPHYR_API_KEY does not match the running container.
  Use:
    .\start-docker.ps1 -Command restart
  Or rotate via rotate-key and let it restart automatically.

OAuth Login:
  The `login` command requires Google OAuth credentials to be provided via env vars passed into the container:
    GEPHYR_GOOGLE_OAUTH_CLIENT_ID
    (optional) GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET
"@ | Write-Host
}

function Load-EnvLocal {
    if (-not (Test-Path $envFilePath)) {
        return
    }

    foreach ($raw in Get-Content $envFilePath) {
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

function Save-EnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $lines = @()
    if (Test-Path $envFilePath) {
        $lines = Get-Content $envFilePath
    } else {
        $lines += "# Local-only secrets for Gephyr scripts"
    }

    $updated = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^$([regex]::Escape($Name))=") {
            $lines[$i] = "$Name=$Value"
            $updated = $true
            break
        }
    }
    if (-not $updated) {
        $lines += "$Name=$Value"
    }
    Set-Content -Path $envFilePath -Value $lines -Encoding UTF8
}

function Ensure-ApiKey {
    if (-not $env:GEPHYR_API_KEY) {
        throw "Missing GEPHYR_API_KEY. Set env var or create .env.local with GEPHYR_API_KEY=..."
    }
}

function Get-AuthHeaders {
    Ensure-ApiKey
    return @{ Authorization = "Bearer $($env:GEPHYR_API_KEY)" }
}

function Test-ContainerExists {
    return docker ps -a --format '{{.Names}}' | Select-String -Pattern "^$([regex]::Escape($ContainerName))$" -Quiet
}

function Remove-ContainerIfExists {
    if (Test-ContainerExists) {
        docker rm -f $ContainerName | Out-Null
    }
}

function Start-Container {
    param([bool]$AdminApiEnabled)
    Ensure-ApiKey

    if (-not (Test-Path $DataDir)) {
        New-Item -Path $DataDir -ItemType Directory | Out-Null
    }

    Remove-ContainerIfExists

    $adminApi = if ($AdminApiEnabled) { "true" } else { "false" }

    $oauthArgs = @()
    if ($env:GEPHYR_GOOGLE_OAUTH_CLIENT_ID) {
        $oauthArgs += @("-e", "GEPHYR_GOOGLE_OAUTH_CLIENT_ID=$($env:GEPHYR_GOOGLE_OAUTH_CLIENT_ID)")
    }
    if ($env:GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET) {
        $oauthArgs += @("-e", "GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET=$($env:GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET)")
    }

    $containerId = docker run --rm -d --name $ContainerName `
        -p "127.0.0.1:$Port`:8045" `
        -e API_KEY=$env:GEPHYR_API_KEY `
        -e AUTH_MODE=strict `
        -e ABV_ENABLE_ADMIN_API=$adminApi `
        -e ALLOW_LAN_ACCESS=true `
        @oauthArgs `
        -v "${DataDir}:/home/gephyr/.gephyr" `
        $Image

    if (-not $containerId) {
        throw "Failed to start container."
    }

    Write-Host "Started container: $ContainerName"
    Write-Host "Admin API enabled: $adminApi"
}

function Stop-Container {
    if (Test-ContainerExists) {
        docker rm -f $ContainerName | Out-Null
        Write-Host "Stopped container: $ContainerName"
    } else {
        Write-Host "Container not found: $ContainerName"
    }
}

function Wait-ServiceReady {
    param(
        [int]$Attempts = 40,
        [int]$DelayMs = 500
    )

    $headers = Get-AuthHeaders
    for ($i = 0; $i -lt $Attempts; $i++) {
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/healthz" -Headers $headers -UseBasicParsing -TimeoutSec 2
            if ($resp.StatusCode -eq 200) {
                return $true
            }
        } catch {
            Start-Sleep -Milliseconds $DelayMs
        }
    }
    return $false
}

function Show-Status {
    Write-Host "NAMES`tSTATUS`tPORTS`tIMAGE"
    docker ps -a --format "{{.Names}}`t{{.Status}}`t{{.Ports}}`t{{.Image}}" |
        Where-Object { $_ -match "^$([regex]::Escape($ContainerName))`t" }
}

function Show-Logs {
    if (-not (Test-ContainerExists)) {
        throw "Container not found: $ContainerName"
    }
    docker logs --tail $LogLines $ContainerName
}

function Show-Health {
    $headers = Get-AuthHeaders
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -Headers $headers -Method Get -TimeoutSec 10
        $health | Format-Table -AutoSize
    } catch {
        throw "Health check failed. If status is 401, your local GEPHYR_API_KEY does not match the running container; run restart or rotate-key."
    }
}

function Show-Accounts {
    $headers = Get-AuthHeaders
    Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 20
}

function Logout-Accounts {
    $headers = Get-AuthHeaders

    $accountsResponse = $null
    try {
        $accountsResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 20
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "404|Not Found") {
            throw "Logout requires admin API. Restart with admin API enabled, then run logout again."
        } elseif ($msg -match "401|Unauthorized") {
            throw "Logout failed with 401. API key mismatch. Run restart or rotate-key."
        } else {
            throw "Failed to query accounts for logout: $msg"
        }
    }

    $accounts = @()
    if ($accountsResponse -and $accountsResponse.accounts) {
        $accounts = @($accountsResponse.accounts)
    }

    if ($accounts.Count -eq 0) {
        Write-Host "No linked accounts found."
        return
    }

    $removed = 0
    foreach ($acc in $accounts) {
        $id = [string]$acc.id
        if (-not $id) {
            continue
        }
        try {
            Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts/$id" -Headers $headers -Method Delete -TimeoutSec 20 | Out-Null
            $removed++
            Write-Host "Removed account: $id"
        } catch {
            Write-Warning "Failed to remove account $id : $($_.Exception.Message)"
        }
    }

    Write-Host "Logout completed. Removed $removed account(s)."
}

function Logout-AndStop {
    Logout-Accounts
    Stop-Container
}

function Run-ApiTest {
    $headers = Get-AuthHeaders
    $headers["Content-Type"] = "application/json"
    $body = @{
        model = $Model
        messages = @(
            @{
                role = "user"
                content = $Prompt
            }
        )
    } | ConvertTo-Json -Depth 10

    $res = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/v1/chat/completions" -Method Post -Headers $headers -Body $body -TimeoutSec 60
    [PSCustomObject]@{
        id = $res.id
        model = $res.model
        finish_reason = $res.choices[0].finish_reason
        total_tokens = $res.usage.total_tokens
    } | Format-List
}

function Start-OAuthFlow {
    Start-Container -AdminApiEnabled $true
    if (-not (Wait-ServiceReady)) {
        throw "Service did not become ready on http://127.0.0.1:$Port."
    }

    $headers = Get-AuthHeaders
    $oauth = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/auth/url" -Headers $headers -Method Get -TimeoutSec 15
    if (-not $oauth.url) {
        throw "OAuth URL was not returned by /api/auth/url."
    }

    Write-Host "OAuth URL:"
    Write-Host $oauth.url
    if (-not $NoBrowser) {
        Start-Process $oauth.url
    }
}

function New-GephyrApiKey {
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return "gph_$token"
}

function Rotate-ApiKey {
    $newKey = New-GephyrApiKey
    $env:GEPHYR_API_KEY = $newKey
    Save-EnvValue -Name "GEPHYR_API_KEY" -Value $newKey
    Write-Host "Generated new API key and saved it to .env.local"

    if ($NoRestartAfterRotate) {
        Write-Host "No restart requested. Restart manually to apply the new key."
        return
    }

    Start-Container -AdminApiEnabled $EnableAdminApi.IsPresent
    if (Wait-ServiceReady) {
        Show-Health
    } else {
        throw "Container restarted but health check did not pass."
    }
}

Load-EnvLocal

if ($Help -or $Command -in @("--help", "-h", "-?", "?", "/help")) {
    $Command = "help"
}

switch ($Command) {
    "help" { Write-Usage }
    "start" {
        Start-Container -AdminApiEnabled $EnableAdminApi.IsPresent
        if (Wait-ServiceReady) { Show-Health } else { throw "Service did not become ready." }
    }
    "stop" { Stop-Container }
    "restart" {
        Stop-Container
        Start-Container -AdminApiEnabled $EnableAdminApi.IsPresent
        if (Wait-ServiceReady) { Show-Health } else { throw "Service did not become ready." }
    }
    "status" { Show-Status }
    "logs" { Show-Logs }
    "health" { Show-Health }
    "login" { Start-OAuthFlow }
    "oauth" { Start-OAuthFlow }
    "auth" { Start-OAuthFlow }
    "accounts" { Show-Accounts }
    "api-test" { Run-ApiTest }
    "rotate-key" { Rotate-ApiKey }
    "logout" { Logout-Accounts }
    "logout-and-stop" { Logout-AndStop }
    default { Write-Usage }
}
