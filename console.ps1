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
    [string]$Model = "gpt-5.3-codex",
    [string]$Prompt = "hello from gephyr",
    [switch]$NoBrowser,
    [switch]$NoRestartAfterRotate,
    [switch]$Aggressive
)

$ErrorActionPreference = "Stop"
$envFilePath = Join-Path $PSScriptRoot ".env.local"

function Write-Usage {
    @"
Usage:
  .\console.ps1 <command> [options]
  .\console.ps1 -Command <command> [options]

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
  docker-repair  Repair Docker builder cache issues (e.g., missing snapshot errors)
  logout       Remove linked account(s) via admin API
  logout-and-stop  Logout accounts, then stop container

Options:
  -EnableAdminApi        Enable admin API on start/restart (default false)
  -Port <int>            Host port (default 8045)
  -ContainerName <name>  Container name (default gephyr)
  -Image <name>          Docker image (default gephyr:latest)
  -DataDir <path>        Host data dir (default %USERPROFILE%\.gephyr)
  -LogLines <int>        Number of log lines for logs command (default 120)
  -Model <name>          Model for api-test (default gpt-5.3-codex)
  -Prompt <text>         Prompt for api-test
  -NoBrowser             Do not open browser for login command
  -NoRestartAfterRotate  Rotate key without container restart
  -Aggressive            For docker-repair: remove all builder cache (slower next build)

Examples:
  .\console.ps1 start
  .\console.ps1 login
  .\console.ps1 logs -LogLines 200
  .\console.ps1 rotate-key
  .\console.ps1 docker-repair
  .\console.ps1 docker-repair -Aggressive
  .\console.ps1 logout
  .\console.ps1 logout-and-stop
  .\console.ps1 -Command login

Troubleshooting:
  If health returns 401, your local GEPHYR_API_KEY does not match the running container.
  Use:
    .\console.ps1 -Command restart
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

function Write-ContainerNotFoundNextSteps {
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "    1. Start it: .\console.ps1 start" -ForegroundColor Yellow
    Write-Host "    2. If image is missing, build it:" -ForegroundColor Yellow
    Write-Host "       docker build -t $Image -f docker/Dockerfile ." -ForegroundColor Yellow
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
        Write-ContainerNotFoundNextSteps
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
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                      GEPHYR STATUS                            " -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    # Docker Container Status
    Write-Host "┌─ Docker Container ─────────────────────────────────────────────" -ForegroundColor DarkGray
    $containerInfo = docker ps -a --format "{{.Names}}|{{.Status}}|{{.Ports}}|{{.Image}}" |
        Where-Object { $_ -match "^$([regex]::Escape($ContainerName))\|" }

    if ($containerInfo) {
        $parts = $containerInfo -split '\|'
        Write-Host "  Container:  " -NoNewline -ForegroundColor Gray
        Write-Host $parts[0] -ForegroundColor White
        Write-Host "  Status:     " -NoNewline -ForegroundColor Gray
        if ($parts[1] -match "^Up") {
            Write-Host $parts[1] -ForegroundColor Green
        } else {
            Write-Host $parts[1] -ForegroundColor Red
        }
        Write-Host "  Ports:      " -NoNewline -ForegroundColor Gray
        Write-Host $parts[2] -ForegroundColor White
        Write-Host "  Image:      " -NoNewline -ForegroundColor Gray
        Write-Host $parts[3] -ForegroundColor White
    } else {
        Write-Host "  Container not found: $ContainerName" -ForegroundColor Red
        Write-ContainerNotFoundNextSteps
    }
    Write-Host ""

    # API Configuration
    Write-Host "┌─ API Configuration ────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Base URL:   " -NoNewline -ForegroundColor Gray
    Write-Host "http://127.0.0.1:$Port" -ForegroundColor Yellow

    if ($env:GEPHYR_API_KEY) {
        $maskedKey = $env:GEPHYR_API_KEY.Substring(0, [Math]::Min(8, $env:GEPHYR_API_KEY.Length)) + "..." + $env:GEPHYR_API_KEY.Substring([Math]::Max(0, $env:GEPHYR_API_KEY.Length - 4))
        Write-Host "  API Key:    " -NoNewline -ForegroundColor Gray
        Write-Host $maskedKey -ForegroundColor Yellow
    } else {
        Write-Host "  API Key:    " -NoNewline -ForegroundColor Gray
        Write-Host "(not set)" -ForegroundColor Red
    }
    Write-Host ""

    # Health Check (if container is running)
    if ($containerInfo -and ($containerInfo -match "Up")) {
        Write-Host "┌─ Service Health ───────────────────────────────────────────────" -ForegroundColor DarkGray
        try {
            $headers = Get-AuthHeaders
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -Headers $headers -Method Get -TimeoutSec 5
            Write-Host "  Health:     " -NoNewline -ForegroundColor Gray
            Write-Host "OK" -ForegroundColor Green
            if ($health.accounts_loaded) {
                Write-Host "  Accounts:   " -NoNewline -ForegroundColor Gray
                Write-Host "$($health.accounts_loaded) loaded" -ForegroundColor White
            }
            if ($health.version) {
                Write-Host "  Version:    " -NoNewline -ForegroundColor Gray
                Write-Host $health.version -ForegroundColor White
            }
        } catch {
            Write-Host "  Health:     " -NoNewline -ForegroundColor Gray
            Write-Host "FAILED (API key mismatch or service error)" -ForegroundColor Red
        }
        Write-Host ""
    }

    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Logs {
    if (-not (Test-ContainerExists)) {
        Write-Host "Container not found: $ContainerName" -ForegroundColor Red
        Write-ContainerNotFoundNextSteps
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
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 20
    $accounts = @()
    if ($resp -and $resp.accounts) {
        $accounts = @($resp.accounts)
    }

    if ($accounts.Count -eq 0) {
        [PSCustomObject]@{
            status = "No linked accounts"
            current_account_id = $resp.current_account_id
        } | Format-Table -AutoSize
        return
    }

    $accounts |
        Select-Object id, email, name, is_current, disabled, proxy_disabled, last_used |
        Format-Table -AutoSize

    if ($resp.current_account_id) {
        Write-Host "Current account id: $($resp.current_account_id)"
    }
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
    $choice = $res.choices[0]
    $answer = ""

    if ($null -ne $choice.message) {
        if ($choice.message.content -is [string]) {
            $answer = $choice.message.content
        } elseif ($choice.message.content -is [System.Array]) {
            $parts = @()
            foreach ($item in $choice.message.content) {
                if ($item.text) {
                    $parts += [string]$item.text
                } elseif ($item.content) {
                    $parts += [string]$item.content
                }
            }
            $answer = ($parts -join "`n").Trim()
        }
    }

    if ([string]::IsNullOrWhiteSpace($answer) -and $choice.text) {
        $answer = [string]$choice.text
    }

    [PSCustomObject]@{
        id = $res.id
        model = $res.model
        finish_reason = $choice.finish_reason
        total_tokens = $res.usage.total_tokens
        answer = $answer
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

function Repair-DockerBuilder {
    param([switch]$AggressiveMode)

    Write-Host "Running Docker builder repair..." -ForegroundColor Cyan
    if ($AggressiveMode) {
        Write-Host "Mode: aggressive (will remove all builder cache)." -ForegroundColor Yellow
    } else {
        Write-Host "Mode: safe (prunes unused builder cache)." -ForegroundColor Yellow
    }

    $pruneFlag = if ($AggressiveMode) { "-af" } else { "-f" }

    & docker buildx inspect --bootstrap | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to bootstrap Docker buildx. Restart Docker Desktop and retry."
    }

    & docker buildx prune $pruneFlag
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to run 'docker buildx prune $pruneFlag'."
    }

    & docker builder prune $pruneFlag
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to run 'docker builder prune $pruneFlag'."
    }

    Write-Host ""
    Write-Host "Builder repair completed." -ForegroundColor Green
    Write-Host "Next step: retry your image build." -ForegroundColor Green
    Write-Host "  docker build -t $Image -f docker/Dockerfile ." -ForegroundColor Green
}

Load-EnvLocal

function Test-DockerAvailable {
    try {
        $null = docker info 2>&1
        if ($LASTEXITCODE -ne 0) {
            return $false
        }
        return $true
    } catch {
        return $false
    }
}

function Assert-DockerRunning {
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
}

# Commands that require Docker
$dockerCommands = @("start", "stop", "restart", "status", "logs", "health", "login", "oauth", "auth", "accounts", "api-test", "rotate-key", "docker-repair", "logout", "logout-and-stop")

if ($Help -or $Command -in @("--help", "-h", "-?", "?", "/help")) {
    $Command = "help"
}

# Check Docker availability for commands that need it
if ($Command -in $dockerCommands) {
    Assert-DockerRunning
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
    "docker-repair" { Repair-DockerBuilder -AggressiveMode:$Aggressive.IsPresent }
    "logout" { Logout-Accounts }
    "logout-and-stop" { Logout-AndStop }
    default { Write-Usage }
}
