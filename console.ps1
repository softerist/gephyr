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
    [switch]$Aggressive,
    [switch]$Json,
    [switch]$Quiet,
    [switch]$NoCache,
    [switch]$SingleAttempt,
    [switch]$TestPipe,
    [string]$ClaudeModel = "claude-haiku-4-5",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = "Stop"
$envFilePath = Join-Path $PSScriptRoot ".env.local"

# Some environments (e.g. `test-clean.ps1`) run with `Set-StrictMode -Version Latest`,
# which turns reads of unset variables into hard errors. Predefine our script-scoped
# correlation/request sequence variables so helper functions can safely read/update them.
$script:ConsoleCorrelationId = $null
$script:ConsoleRequestSeq = 0

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
  health       Call /health with API key
  check        Run account token health check (refresh expiring tokens)
  canary       Show/Run TLS stealth canary probe (use --run to trigger)
  login        Start container with admin API, fetch /api/auth/url, open browser
  oauth/auth   Alias for login
  accounts     Call /api/accounts
  api-test     Run one API test completion
  api-test-all Run one quick API test per provider (OpenAI/Claude/Gemini)
  rotate-key   Generate new API key, save to .env.local, and optionally restart
  docker-repair  Repair Docker builder cache issues (e.g., missing snapshot errors)
  rebuild      Rebuild Docker image from source
  update       Pull latest code, rebuild image, and restart container
  version      Show version from Cargo.toml
  accounts-signout <accountId|email>  Sign out one account (revoke + local token clear/disable)
  accounts-signout-and-delete <accountId|email>  Sign out one account and delete local record
  accounts-signout-all  Sign out all linked accounts (revoke + local token clear/disable)
  accounts-signout-all-and-stop  Sign out all linked accounts, then stop container
  accounts-delete <accountId|email>  Delete one local account record (does not revoke)
  accounts-delete-and-stop <accountId|email>  Delete one local account record, then stop container
  accounts-delete-all   Delete local account records (does not revoke)
  accounts-delete-all-and-stop  Delete local accounts, then stop container

Options:
  -EnableAdminApi        Enable admin API on start/restart (default false)
  -Port <int>            Host port (default 8045)
  -ContainerName <name>  Container name (default gephyr)
  -Image <name>          Docker image (default gephyr:latest)
  -DataDir <path>        Host data dir (default %USERPROFILE%\.gephyr)
  -LogLines <int>        Number of log lines for logs command (default 120)
  -Model <name>          Model for api-test and OpenAI test in api-test-all (default gpt-5.3-codex)
  -ClaudeModel <name>    Model for Claude test in api-test-all (default claude-haiku-4-5)
  -Prompt <text>         Prompt for api-test
  -NoBrowser             Do not open browser for login command
  -NoRestartAfterRotate  Rotate key without container restart
  -Aggressive            For docker-repair: remove all builder cache (slower next build)
  -Json                  Output machine-readable JSON (for status, health, accounts)
  -Quiet                 Suppress non-essential output (for CI/automation)
  -NoCache               For rebuild: build without Docker cache
  -SingleAttempt         For api-test-all: temporarily force single-attempt retry policy
                         (proxy.compliance.enabled=true + max_retry_attempts=1)
  -TestPipe              For api-test-all pipeline safety: applies -SingleAttempt and
                         temporarily sets auto_refresh=false
                         Aliases via ExtraArgs: --no-retry, --single-attempt, --test-pipe

Examples:
  .\console.ps1 start
  .\console.ps1 login
  .\console.ps1 logs -LogLines 200
  .\console.ps1 api-test-all
  .\console.ps1 api-test-all -SingleAttempt
  .\console.ps1 api-test-all -TestPipe
  .\console.ps1 rotate-key
  .\console.ps1 rebuild
  .\console.ps1 rebuild -NoCache
  .\console.ps1 docker-repair
  .\console.ps1 docker-repair -Aggressive
  .\console.ps1 accounts-signout <accountId|email>
  .\console.ps1 accounts-signout-and-delete <accountId|email>
  .\console.ps1 accounts-signout-all
  .\console.ps1 accounts-signout-all-and-stop
  .\console.ps1 accounts-delete <accountId|email>
  .\console.ps1 accounts-delete-and-stop <accountId|email>
  .\console.ps1 accounts-delete-all
  .\console.ps1 accounts-delete-all-and-stop
  .\console.ps1 -Command login

Troubleshooting:
  If health returns 401, your local API_KEY does not match the running container.
  Use:
    .\console.ps1 -Command restart
  Or rotate via rotate-key and let it restart automatically.

OAuth Login:
  The `login` command requires Google OAuth credentials to be provided via env vars passed into the container:
    GOOGLE_OAUTH_CLIENT_ID
    (optional) GOOGLE_OAUTH_CLIENT_SECRET
  Optional identity/scheduler hardening envs are also passed through when set:
    ALLOW_LAN_ACCESS
    ALLOWED_GOOGLE_DOMAINS
    TLS_BACKEND
    TLS_CANARY_URL
    TLS_CANARY_TIMEOUT_SECS
    TLS_CANARY_REQUIRED
    SCHEDULER_REFRESH_JITTER_MIN_SECONDS
    SCHEDULER_REFRESH_JITTER_MAX_SECONDS
    SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS
    SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS
    STARTUP_HEALTH_DELAY_MIN_SECONDS
    STARTUP_HEALTH_DELAY_MAX_SECONDS
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
    if (-not $env:API_KEY -and (Test-Path $envFilePath)) {
        $legacy = Get-Content $envFilePath |
            Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*_API_KEY=' } |
            Select-Object -First 1
        if ($legacy) {
            $env:API_KEY = ($legacy.Split("=", 2)[1]).Trim().Trim('"').Trim("'")
        }
    }

    if (-not $env:API_KEY) {
        throw "Missing API_KEY. Set env var or create .env.local with API_KEY=..."
    }
}

function Get-ConsoleCorrelationId {
    if (-not $script:ConsoleCorrelationId) {
        $script:ConsoleCorrelationId = "console.ps1-" + ([guid]::NewGuid().ToString())
        $script:ConsoleRequestSeq = 0
    }
    return $script:ConsoleCorrelationId
}

function Get-AuthHeaders {
    Ensure-ApiKey
    $cid = Get-ConsoleCorrelationId
    $script:ConsoleRequestSeq++
    $rid = "${cid}:$($script:ConsoleRequestSeq)"
    return @{
        Authorization      = "Bearer $($env:API_KEY)"
        "x-correlation-id" = $cid
        "x-request-id"     = $rid
    }
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

function Get-FriendlyModelName {
    param([string]$ModelId)

    if (-not $ModelId) {
        return "-"
    }

    $id = ($ModelId -replace '^models/', '').ToLowerInvariant()

    # Known UI-style labels used by current providers.
    $known = @{
        "claude-sonnet-4-6"          = "Claude Sonnet 4.6 (Thinking)"
        "claude-sonnet-4-6-thinking" = "Claude Sonnet 4.6 (Thinking)"
        "claude-opus-4-6"            = "Claude Opus 4.6 (Thinking)"
        "claude-opus-4-6-thinking"   = "Claude Opus 4.6 (Thinking)"
        "claude-sonnet-4-5"          = "Claude Sonnet 4.5 (Thinking)"
        "claude-sonnet-4-5-thinking" = "Claude Sonnet 4.5 (Thinking)"
        "claude-opus-4-5"            = "Claude Opus 4.5 (Thinking)"
        "claude-opus-4-5-thinking"   = "Claude Opus 4.5 (Thinking)"
        "claude-haiku-4-5"           = "Claude Haiku 4.5"
        "gemini-3.1-pro-high"        = "Gemini 3.1 Pro (High)"
        "gemini-3.1-pro-low"         = "Gemini 3.1 Pro (Low)"
        "gemini-3-pro-high"          = "Gemini 3 Pro (High)"
        "gemini-3-pro-low"           = "Gemini 3 Pro (Low)"
        "gemini-3-pro-image"         = "Gemini 3 Pro Image"
        "gemini-3-flash"             = "Gemini 3 Flash"
        "gemini-2.5-pro"             = "Gemini 2.5 Pro"
        "gemini-2.5-flash"           = "Gemini 2.5 Flash"
        "gemini-2.5-flash-thinking"  = "Gemini 2.5 Flash (Thinking)"
        "gemini-2.5-flash-lite"      = "Gemini 2.5 Flash Lite"
        "gpt-oss-120b-medium"        = "GPT-OSS 120B (Medium)"
    }
    if ($known.ContainsKey($id)) {
        return $known[$id]
    }

    # Generic Claude fallback.
    if ($id -match '^claude-(sonnet|opus|haiku)-(\d+)-(\d+)(-thinking)?$') {
        $family = (Get-Culture).TextInfo.ToTitleCase($Matches[1])
        $ver = "$($Matches[2]).$($Matches[3])"
        if ($Matches[4]) {
            return "Claude $family $ver (Thinking)"
        }
        return "Claude $family $ver"
    }

    # Generic Gemini fallback.
    if ($id -match '^gemini-(\d+(?:\.\d+)?)-pro-high$') {
        return "Gemini $($Matches[1]) Pro (High)"
    }
    if ($id -match '^gemini-(\d+(?:\.\d+)?)-pro-low$') {
        return "Gemini $($Matches[1]) Pro (Low)"
    }
    if ($id -match '^gemini-(\d+(?:\.\d+)?)-pro-image$') {
        return "Gemini $($Matches[1]) Pro Image"
    }
    if ($id -match '^gemini-(\d+(?:\.\d+)?)-pro$') {
        return "Gemini $($Matches[1]) Pro"
    }
    if ($id -match '^gemini-(\d+(?:\.\d+)?)-flash-thinking$') {
        return "Gemini $($Matches[1]) Flash (Thinking)"
    }
    if ($id -match '^gemini-(\d+(?:\.\d+)?)-flash-lite$') {
        return "Gemini $($Matches[1]) Flash Lite"
    }
    if ($id -match '^gemini-(\d+(?:\.\d+)?)-flash$') {
        return "Gemini $($Matches[1]) Flash"
    }

    return ($ModelId -replace '^models/', '')
}

function Start-Container {
    param([bool]$AdminApiEnabled)
    Ensure-ApiKey

    if (-not (Test-Path $DataDir)) {
        New-Item -Path $DataDir -ItemType Directory | Out-Null
    }

    Remove-ContainerIfExists

    $adminApi = if ($AdminApiEnabled) { "true" } else { "false" }
    # In Docker, the service must bind 0.0.0.0 to be reachable via port mapping.
    # Host exposure is still restricted by "-p 127.0.0.1:...".
    if ($env:ALLOW_LAN_ACCESS -and $env:ALLOW_LAN_ACCESS.Trim().ToLower() -in @("0", "false", "no", "off")) {
        Write-Warning "ALLOW_LAN_ACCESS=$($env:ALLOW_LAN_ACCESS) would bind 127.0.0.1 inside the container and break Docker port mapping; forcing ALLOW_LAN_ACCESS=true for docker run."
    }
    $allowLan = "true"

    if (-not $env:GOOGLE_OAUTH_CLIENT_ID -and (Test-Path $envFilePath)) {
        $legacy = Get-Content $envFilePath |
            Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*_OAUTH_CLIENT_ID=' } |
            Select-Object -First 1
        if ($legacy) {
            $env:GOOGLE_OAUTH_CLIENT_ID = ($legacy.Split("=", 2)[1]).Trim().Trim('"').Trim("'")
        }
    }
    if (-not $env:GOOGLE_OAUTH_CLIENT_SECRET -and (Test-Path $envFilePath)) {
        $legacy = Get-Content $envFilePath |
            Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*_OAUTH_CLIENT_SECRET=' } |
            Select-Object -First 1
        if ($legacy) {
            $env:GOOGLE_OAUTH_CLIENT_SECRET = ($legacy.Split("=", 2)[1]).Trim().Trim('"').Trim("'")
        }
    }

    $oauthArgs = @()
    if ($env:GOOGLE_OAUTH_CLIENT_ID) {
        $oauthArgs += @("-e", "GOOGLE_OAUTH_CLIENT_ID=$($env:GOOGLE_OAUTH_CLIENT_ID)")
    }
    if ($env:GOOGLE_OAUTH_CLIENT_SECRET) {
        $oauthArgs += @("-e", "GOOGLE_OAUTH_CLIENT_SECRET=$($env:GOOGLE_OAUTH_CLIENT_SECRET)")
    }
    $runtimeArgs = @()
    if ($env:ENCRYPTION_KEY) {
        $runtimeArgs += @("-e", "ENCRYPTION_KEY=$($env:ENCRYPTION_KEY)")
    }
    if ($env:WEB_PASSWORD) {
        $runtimeArgs += @("-e", "WEB_PASSWORD=$($env:WEB_PASSWORD)")
    }
    if ($env:PUBLIC_URL) {
        $runtimeArgs += @("-e", "PUBLIC_URL=$($env:PUBLIC_URL)")
    }
    if ($env:MAX_BODY_SIZE) {
        $runtimeArgs += @("-e", "MAX_BODY_SIZE=$($env:MAX_BODY_SIZE)")
    }
    if ($env:SHUTDOWN_DRAIN_TIMEOUT_SECS) {
        $runtimeArgs += @("-e", "SHUTDOWN_DRAIN_TIMEOUT_SECS=$($env:SHUTDOWN_DRAIN_TIMEOUT_SECS)")
    }
    if ($env:ADMIN_STOP_SHUTDOWN) {
        $runtimeArgs += @("-e", "ADMIN_STOP_SHUTDOWN=$($env:ADMIN_STOP_SHUTDOWN)")
    }
    if ($env:ALLOWED_GOOGLE_DOMAINS) {
        $runtimeArgs += @("-e", "ALLOWED_GOOGLE_DOMAINS=$($env:ALLOWED_GOOGLE_DOMAINS)")
    }
    if ($env:TLS_BACKEND) {
        $runtimeArgs += @("-e", "TLS_BACKEND=$($env:TLS_BACKEND)")
    }
    if ($env:TLS_CANARY_URL) {
        $runtimeArgs += @("-e", "TLS_CANARY_URL=$($env:TLS_CANARY_URL)")
    }
    if ($env:TLS_CANARY_TIMEOUT_SECS) {
        $runtimeArgs += @("-e", "TLS_CANARY_TIMEOUT_SECS=$($env:TLS_CANARY_TIMEOUT_SECS)")
    }
    if ($env:TLS_CANARY_REQUIRED) {
        $runtimeArgs += @("-e", "TLS_CANARY_REQUIRED=$($env:TLS_CANARY_REQUIRED)")
    }
    if ($env:SCHEDULER_REFRESH_JITTER_MIN_SECONDS) {
        $runtimeArgs += @("-e", "SCHEDULER_REFRESH_JITTER_MIN_SECONDS=$($env:SCHEDULER_REFRESH_JITTER_MIN_SECONDS)")
    }
    if ($env:SCHEDULER_REFRESH_JITTER_MAX_SECONDS) {
        $runtimeArgs += @("-e", "SCHEDULER_REFRESH_JITTER_MAX_SECONDS=$($env:SCHEDULER_REFRESH_JITTER_MAX_SECONDS)")
    }
    if ($env:SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS) {
        $runtimeArgs += @("-e", "SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS=$($env:SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS)")
    }
    if ($env:SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS) {
        $runtimeArgs += @("-e", "SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS=$($env:SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS)")
    }
    if ($env:STARTUP_HEALTH_DELAY_MIN_SECONDS) {
        $runtimeArgs += @("-e", "STARTUP_HEALTH_DELAY_MIN_SECONDS=$($env:STARTUP_HEALTH_DELAY_MIN_SECONDS)")
    }
    if ($env:STARTUP_HEALTH_DELAY_MAX_SECONDS) {
        $runtimeArgs += @("-e", "STARTUP_HEALTH_DELAY_MAX_SECONDS=$($env:STARTUP_HEALTH_DELAY_MAX_SECONDS)")
    }
    if ($env:GEPHYR_DISABLE_PROMPT_ROUTES) {
        $runtimeArgs += @("-e", "GEPHYR_DISABLE_PROMPT_ROUTES=$($env:GEPHYR_DISABLE_PROMPT_ROUTES)")
    }

    $containerId = docker run --rm -d --name $ContainerName `
        -p "127.0.0.1:$Port`:8045" `
        -e API_KEY=$env:API_KEY `
        -e AUTH_MODE=strict `
        -e ENABLE_ADMIN_API=$adminApi `
        -e ALLOW_LAN_ACCESS=$allowLan `
        @oauthArgs `
        @runtimeArgs `
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
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -Headers $headers -UseBasicParsing -TimeoutSec 2
            if ($resp.StatusCode -eq 200) {
                return $true
            }
        } catch {
            # Surface API key mismatch explicitly; otherwise this looks like a startup hang.
            try {
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 401) {
                    throw "Health check failed with 401 (API key mismatch). Run restart or rotate-key."
                }
            } catch {}
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

    if ($env:API_KEY) {
        $maskedKey = $env:API_KEY.Substring(0, [Math]::Min(8, $env:API_KEY.Length)) + "..." + $env:API_KEY.Substring([Math]::Max(0, $env:API_KEY.Length - 4))
        Write-Host "  API Key:    " -NoNewline -ForegroundColor Gray
        Write-Host $maskedKey -ForegroundColor Yellow
    } else {
        Write-Host "  API Key:    " -NoNewline -ForegroundColor Gray
        Write-Host "(not set)" -ForegroundColor Red
    }
    Write-Host ""

    # Health Check (if container is running)
    $healthData = $null
    if ($containerInfo -and ($containerInfo -match "Up")) {
        Write-Host "┌─ Service Health ───────────────────────────────────────────────" -ForegroundColor DarkGray
        try {
            $headers = Get-AuthHeaders
            $healthData = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -Headers $headers -Method Get -TimeoutSec 5
            Write-Host "  Health:     " -NoNewline -ForegroundColor Gray
            Write-Host "OK" -ForegroundColor Green
            if ($healthData.version) {
                Write-Host "  Version:    " -NoNewline -ForegroundColor Gray
                Write-Host $healthData.version -ForegroundColor White
            }
        } catch {
            Write-Host "  Health:     " -NoNewline -ForegroundColor Gray
            Write-Host "FAILED (API key mismatch or service error)" -ForegroundColor Red
        }
        Write-Host ""

        # Linked Accounts
        Write-Host "┌─ Linked Accounts ──────────────────────────────────────────────" -ForegroundColor DarkGray
        $accountsFetched = $false
        try {
            $headers = Get-AuthHeaders
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 10
            $accounts = @()
            if ($resp -and $resp.accounts) {
                $accounts = @($resp.accounts)
            }
            if ($accounts.Count -eq 0) {
                Write-Host "  (none)" -ForegroundColor DarkGray
            } else {
                $currentId = $resp.current_account_id

                # First pass: compute column widths
                $maxEmail = 5
                $maxName = 1
                $maxModel = 10
                foreach ($acc in $accounts) {
                    if ($acc.email.Length -gt $maxEmail) { $maxEmail = $acc.email.Length }
                    $dn = if ($acc.name) { $acc.name } else { "-" }
                    if ($dn.Length -gt $maxName) { $maxName = $dn.Length }
                    if ($acc.quota -and $acc.quota.models) {
                        foreach ($m in @($acc.quota.models)) {
                            $rawModel = ($m.name -replace '^models/', '')
                            $displayModel = Get-FriendlyModelName $rawModel
                            $sn = $displayModel.Length
                            if ($sn -gt $maxModel) { $maxModel = $sn }
                        }
                    }
                }
                $emailPad = $maxEmail
                $namePad = $maxName + 2  # +2 for parens
                $modelPad = $maxModel + 2

                # Second pass: render
                foreach ($acc in $accounts) {
                    $marker = if ($acc.id -eq $currentId) { "►" } else { " " }
                    $status = "active"
                    $statusColor = "Green"
                    if ($acc.disabled) {
                        $status = "disabled"
                        $statusColor = "Red"
                    } elseif ($acc.proxy_disabled) {
                        $status = "proxy-off"
                        $statusColor = "Yellow"
                    }
                    $displayName = if ($acc.name) { $acc.name } else { "-" }
                    $emailStr = $acc.email.PadRight($emailPad)
                    $nameStr = "($displayName)".PadRight($namePad)

                    Write-Host "  $marker " -NoNewline -ForegroundColor Cyan
                    Write-Host "$emailStr" -NoNewline -ForegroundColor White
                    Write-Host "  $nameStr" -NoNewline -ForegroundColor DarkGray
                    Write-Host "  [$status]" -ForegroundColor $statusColor

                    # Token expiry display
                    if ($acc.token_expiry -and $acc.token_expiry -gt 0) {
                        $expiryUtc = [DateTimeOffset]::FromUnixTimeSeconds($acc.token_expiry).UtcDateTime
                        $expiryLocal = $expiryUtc.ToLocalTime()
                        $remaining = $expiryUtc - [DateTime]::UtcNow
                        $expiryStr = $expiryLocal.ToString("yyyy-MM-dd HH:mm:ss")
                        if ($remaining.TotalSeconds -le 0) {
                            $expiryColor = "Red"
                            $expiryLabel = "EXPIRED"
                        } elseif ($remaining.TotalMinutes -le 30) {
                            $expiryColor = "Yellow"
                            $expiryLabel = "expires in $([Math]::Floor($remaining.TotalMinutes))m"
                        } else {
                            $expiryColor = "Green"
                            $totalMin = [Math]::Floor($remaining.TotalMinutes)
                            if ($totalMin -ge 60) {
                                $expiryLabel = "expires in $([Math]::Floor($remaining.TotalHours))h $($totalMin % 60)m"
                            } else {
                                $expiryLabel = "expires in ${totalMin}m"
                            }
                        }
                        Write-Host "      Token: " -NoNewline -ForegroundColor DarkGray
                        Write-Host "$expiryStr" -NoNewline -ForegroundColor White
                        Write-Host " ($expiryLabel)" -ForegroundColor $expiryColor
                    }

                    # Quota display
                    if ($acc.quota) {
                        $q = $acc.quota
                        $tierStr = if ($q.subscription_tier) { $q.subscription_tier } else { "unknown" }
                        $agoStr = "(unknown)"
                        if ($q.last_updated -and $q.last_updated -gt 0) {
                            $updatedAt = [DateTimeOffset]::FromUnixTimeSeconds($q.last_updated).UtcDateTime
                            $elapsed = [DateTime]::UtcNow - $updatedAt
                            if ($elapsed.TotalMinutes -lt 1) { $agoStr = "just now" }
                            elseif ($elapsed.TotalMinutes -lt 60) { $agoStr = "$([Math]::Floor($elapsed.TotalMinutes))m ago" }
                            elseif ($elapsed.TotalHours -lt 24) { $agoStr = "$([Math]::Floor($elapsed.TotalHours))h ago" }
                            else { $agoStr = "$([Math]::Floor($elapsed.TotalDays))d ago" }
                        }
                        if ($q.is_forbidden) {
                            Write-Host "      Tier: " -NoNewline -ForegroundColor DarkGray
                            Write-Host "$tierStr" -NoNewline -ForegroundColor White
                            Write-Host "  " -NoNewline
                            Write-Host "[FORBIDDEN]" -ForegroundColor Red
                        } else {
                            Write-Host "      Tier: " -NoNewline -ForegroundColor DarkGray
                            Write-Host "$tierStr" -NoNewline -ForegroundColor White
                            Write-Host " | Updated: " -NoNewline -ForegroundColor DarkGray
                            Write-Host "$agoStr" -ForegroundColor DarkGray

                            $models = @()
                            if ($q.models) { $models = @($q.models) }
                            $modelOrder = @(
                                'claude-opus-4-6-thinking', 'claude-opus-4-6',
                                'claude-sonnet-4-6-thinking', 'claude-sonnet-4-6',
                                'claude-opus-4-5-thinking', 'claude-opus-4-5',
                                'claude-sonnet-4-5-thinking', 'claude-sonnet-4-5',
                                'claude-haiku-4-5',
                                'gemini-3.1-pro-high', 'gemini-3-pro-high',
                                'gemini-3.1-pro-low', 'gemini-3-pro-low',
                                'gemini-3-flash',
                                'gemini-2.5-pro',
                                'gemini-2.5-flash-thinking',
                                'gemini-2.5-flash-lite',
                                'gemini-2.5-flash',
                                'gemini-3-pro-image'
                            )
                            $models = $models | Sort-Object {
                                $n = $_.name -replace '^models/', ''
                                for ($i = 0; $i -lt $modelOrder.Count; $i++) {
                                    if ($n -match [regex]::Escape($modelOrder[$i])) { return $i }
                                }
                                return 999
                            }
                            foreach ($m in $models) {
                                $pct = [Math]::Max(0, [Math]::Min(100, $m.percentage))
                                $barWidth = 20
                                $filled = [Math]::Floor($pct / 100.0 * $barWidth)
                                $empty = $barWidth - $filled
                                $bar = ("█" * $filled) + ("░" * $empty)
                                $rawModel = $m.name -replace '^models/', ''
                                $displayModel = Get-FriendlyModelName $rawModel
                                $padded = $displayModel.PadRight($modelPad)
                                $barColor = if ($pct -ge 70) { "Green" } elseif ($pct -ge 30) { "Yellow" } else { "Red" }
                                $pctStr = "$pct%".PadLeft(4)

                                Write-Host "      $padded " -NoNewline -ForegroundColor DarkGray
                                Write-Host "$bar" -NoNewline -ForegroundColor $barColor
                                Write-Host "  $pctStr" -NoNewline -ForegroundColor White

                                if ($null -ne $m.request_count -and $m.request_count -gt 0) {
                                    $reqStr = "($($m.request_count) reqs)"
                                    Write-Host "  $reqStr" -NoNewline -ForegroundColor DarkCyan
                                }

                                if ($displayModel.ToLowerInvariant() -ne $rawModel.ToLowerInvariant()) {
                                    Write-Host "  [$rawModel]" -NoNewline -ForegroundColor DarkGray
                                }

                                if ($pct -le 50 -and $m.reset_time) {
                                    try {
                                        $resetDt = [DateTime]::Parse($m.reset_time).ToLocalTime()
                                        $resetStr = $resetDt.ToString("HH:mm")
                                        Write-Host "  ⟳ $resetStr" -NoNewline -ForegroundColor DarkGray
                                    } catch {}
                                }
                                Write-Host ""
                            }
                        }
                    } else {
                        Write-Host "      (quota data not fetched yet, try again in a few moments...)" -ForegroundColor DarkGray
                    }
                }
            }
            $accountsFetched = $true
        } catch {
            # Admin API not enabled or auth error — fall back to health count
            $adminApiError = $_.Exception.Message
        }
        if (-not $accountsFetched) {
            if ($healthData -and $healthData.accounts_loaded) {
                Write-Host "  $($healthData.accounts_loaded) account(s) loaded" -ForegroundColor White
                Write-Host "  (start with --admin-api to see full account details)" -ForegroundColor DarkGray
            } elseif ($healthData) {
                # Health check succeeded but /api/accounts failed
                if ($adminApiError -match "404|Not Found") {
                    Write-Host "  (admin API not enabled — start with -EnableAdminApi to view accounts)" -ForegroundColor DarkGray
                } elseif ($adminApiError -match "401|Unauthorized") {
                    Write-Host "  (admin API returned 401 — API key mismatch; run restart or rotate-key)" -ForegroundColor Red
                } else {
                    Write-Host "  (could not query accounts — $adminApiError)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  (health check failed — cannot determine account status)" -ForegroundColor Red
            }
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
    param([switch]$AsJson)
    $headers = Get-AuthHeaders
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -Headers $headers -Method Get -TimeoutSec 10
        if ($AsJson) {
            $health | ConvertTo-Json -Depth 5
        } else {
            $health | Format-Table -AutoSize
        }
    } catch {
        if ($AsJson) {
            @{ error = "Health check failed" } | ConvertTo-Json
        } else {
            throw "Health check failed. If status is 401, your local API_KEY does not match the running container; run restart or rotate-key."
        }
    }
}

function Show-AccountHealthCheck {
    param([switch]$AsJson)
    $headers = Get-AuthHeaders
    Write-Host ""
    Write-Host "  Running account health check..." -ForegroundColor Cyan
    Write-Host ""
    try {
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts/health-check" -Headers $headers -Method Post -TimeoutSec 60
    } catch {
        Write-Host "  Health check failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($AsJson) {
        $resp | ConvertTo-Json -Depth 5
        return
    }

    # Summary line
    $summary = "  Total: $($resp.total) | Skipped: $($resp.skipped) | Refreshed: $($resp.refreshed) | Disabled: $($resp.disabled) | Errors: $($resp.network_errors)"
    if ($resp.disabled -gt 0 -or $resp.network_errors -gt 0) {
        Write-Host $summary -ForegroundColor Yellow
    } else {
        Write-Host $summary -ForegroundColor Green
    }
    Write-Host ""

    # Per-account results
    foreach ($acct in $resp.accounts) {
        $statusColor = switch ($acct.status) {
            "ok"        { "Green" }
            "refreshed" { "Cyan" }
            "disabled"  { "Red" }
            "error"     { "Yellow" }
            default     { "White" }
        }
        $statusTag = "[$($acct.status.ToUpper())]".PadRight(12)
        $detail = if ($acct.detail) { " -- $($acct.detail)" } else { "" }
        Write-Host "    $statusTag $($acct.email)$detail" -ForegroundColor $statusColor
    }
    Write-Host ""
}

function Show-TlsCanary {
    param([switch]$Run, [switch]$AsJson)
    $headers = Get-AuthHeaders
    $method = if ($Run) { "Post" } else { "Get" }
    $uri = if ($Run) { "http://127.0.0.1:$Port/api/proxy/tls-canary/run" } else { "http://127.0.0.1:$Port/api/proxy/tls-canary" }

    if ($Run) {
        Write-Host ""
        Write-Host "  Running TLS startup canary probe..." -ForegroundColor Cyan
        Write-Host ""
    }

    try {
        $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method $method -TimeoutSec 15
        if ($AsJson) {
            $resp | ConvertTo-Json -Depth 5
            return
        }

        $snapshot = if ($Run) { $resp.tls_canary } else { $resp }
        $configuredColor = if ($snapshot.configured) { "Green" } else { "Gray" }
        $requiredColor = if ($snapshot.required) { "Yellow" } else { "Gray" }

        Write-Host ""
        Write-Host "  TLS Canary Snapshot:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    Configured: " -NoNewline; Write-Host "$($snapshot.configured)" -ForegroundColor $configuredColor
        Write-Host "    Required:   " -NoNewline; Write-Host "$($snapshot.required)" -ForegroundColor $requiredColor
        Write-Host "    URL:        $($snapshot.url)"
        Write-Host "    Timeout:    $($snapshot.timeout_seconds)s"

        if ($snapshot.last_checked_unix) {
            $lastChecked = [DateTimeOffset]::FromUnixTimeSeconds($snapshot.last_checked_unix).LocalDateTime
            Write-Host "    Last Check: $($lastChecked.ToString("yyyy-MM-dd HH:mm:ss"))"
        }

        if ($snapshot.last_http_status) {
            $color = if ($snapshot.last_http_status -lt 400) { "Green" } else { "Red" }
            Write-Host "    HTTP Status:" -NoNewline; Write-Host " $($snapshot.last_http_status)" -ForegroundColor $color
        }

        if ($snapshot.last_error) {
            Write-Host "    Last Error: $($snapshot.last_error)" -ForegroundColor Red
        } else {
            if ($snapshot.configured) {
                Write-Host "    Status:     OK" -ForegroundColor Green
            }
        }
        Write-Host ""
    } catch {
        if ($AsJson) {
            @{ error = "Canary check failed"; message = $_.Exception.Message } | ConvertTo-Json
        } else {
            Write-Host "  Canary check failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Show-Accounts {
    param([switch]$AsJson)
    $headers = Get-AuthHeaders
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 20

    if ($AsJson) {
        $resp | ConvertTo-Json -Depth 5
        return
    }

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

function Get-AccountsResponseOrRestartAdmin {
    $headers = Get-AuthHeaders
    try {
        return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 20
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "404|Not Found") {
            Write-Host "Admin API not enabled. Restarting container with admin API..." -ForegroundColor Yellow
            Stop-Container
            Start-Container -AdminApiEnabled $true
            if (-not (Wait-ServiceReady)) {
                throw "Service did not become ready after restart."
            }
            return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 20
        } elseif ($msg -match "401|Unauthorized") {
            throw "Accounts query failed with 401. API key mismatch. Run restart or rotate-key."
        }
        throw "Failed to query accounts: $msg"
    }
}

function Remove-Accounts {
    $headers = Get-AuthHeaders

    try {
        $accountsResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 20
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "404|Not Found") {
            Write-Host "Admin API not enabled. Restarting container with admin API..." -ForegroundColor Yellow
            Stop-Container
            Start-Container -AdminApiEnabled $true
            if (-not (Wait-ServiceReady)) {
                throw "Service did not become ready after restart."
            }
            # Retry after restart
            $accountsResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 20
        } elseif ($msg -match "401|Unauthorized") {
            throw "Accounts delete-all failed with 401. API key mismatch. Run restart or rotate-key."
        } else {
            throw "Failed to query accounts for accounts-delete-all: $msg"
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
            Write-Warning "[W-ACCOUNT-REMOVE-FAILED] Failed to remove account $id : $($_.Exception.Message)"
        }
    }

    Write-Host "Accounts delete-all completed. Removed $removed account(s)."
}

function Logout-AndStop {
    Logout-AllAccounts
    Stop-Container
}

function Accounts-SignoutAll {
    Logout-AllAccounts
}

function Accounts-SignoutAllAndStop {
    Logout-AndStop
}

function Accounts-DeleteAll {
    Remove-Accounts
}

function Accounts-DeleteAllAndStop {
    Remove-Accounts-AndStop
}

function Remove-Accounts-AndStop {
    Remove-Accounts
    Stop-Container
}

function Logout-AllAccounts {
    $headers = Get-AuthHeaders
    $headers["Content-Type"] = "application/json"
    $body = @{ revokeRemote = $true; deleteLocal = $false } | ConvertTo-Json

    try {
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts/logout-all" -Headers $headers -Method Post -Body $body -TimeoutSec 60
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "404|Not Found") {
            Write-Host "Admin API not enabled. Restarting container with admin API..." -ForegroundColor Yellow
            Stop-Container
            Start-Container -AdminApiEnabled $true
            if (-not (Wait-ServiceReady)) {
                throw "Service did not become ready after restart."
            }
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts/logout-all" -Headers $headers -Method Post -Body $body -TimeoutSec 60
        } elseif ($msg -match "401|Unauthorized") {
            throw "Accounts signout-all failed with 401. API key mismatch. Run restart or rotate-key."
        } else {
            throw "Accounts signout-all failed: $msg"
        }
    }

    $total = if ($resp.total) { [int]$resp.total } else { 0 }
    $loggedOut = if ($resp.logged_out) { [int]$resp.logged_out } else { 0 }
    $failed = @()
    if ($resp.failed) { $failed = @($resp.failed) }

    Write-Host "Accounts signout-all completed. total=$total logged_out=$loggedOut failed=$($failed.Count)"
    if ($failed.Count -gt 0) {
        foreach ($f in $failed) {
            Write-Warning "[W-ACCOUNTS-SIGNOUT-ALL-FAILED] $($f.account_id) $($f.email) : $($f.error)"
        }
    }
}

function Resolve-AccountId {
    $ref = $null
    if ($ExtraArgs -and $ExtraArgs.Count -ge 1 -and $ExtraArgs[0]) {
        $ref = [string]$ExtraArgs[0]
    } elseif ($env:ACCOUNT_REF) {
        $ref = [string]$env:ACCOUNT_REF
    } elseif ($env:ACCOUNT_ID) {
        $ref = [string]$env:ACCOUNT_ID
    } elseif ($env:ACCOUNT_EMAIL) {
        $ref = [string]$env:ACCOUNT_EMAIL
    }
    if (-not $ref) {
        throw "Missing accountId/email. Usage: .\\console.ps1 accounts-signout <accountId|email> (or set ACCOUNT_REF/ACCOUNT_ID/ACCOUNT_EMAIL)"
    }
    return Resolve-AccountIdFromRef -Ref $ref
}

function Resolve-AccountIdFromRef {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Ref
    )

    $trimmed = $Ref.Trim()
    if (-not $trimmed) {
        throw "Missing account reference (empty)."
    }

    # Most account IDs are UUIDs; if it looks like one, use it directly.
    if ($trimmed -match '^[0-9a-fA-F-]{36}$') {
        return $trimmed
    }

    $resp = Get-AccountsResponseOrRestartAdmin
    $accounts = @()
    if ($resp -and $resp.accounts) { $accounts = @($resp.accounts) }

    $matches = @(
        $accounts | Where-Object {
            $_.id -eq $trimmed -or ($_.email -and ([string]$_.email).ToLower() -eq $trimmed.ToLower())
        }
    )

    if ($matches.Count -eq 1) {
        return [string]$matches[0].id
    }
    if ($matches.Count -gt 1) {
        throw "Account ref '$trimmed' is ambiguous. Use the exact account id."
    }
    throw "No account matched '$trimmed'. Run .\\console.ps1 accounts to list ids/emails."
}

function Logout-Account {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountId,
        [bool]$DeleteLocal = $false
    )

    $headers = Get-AuthHeaders
    $headers["Content-Type"] = "application/json"
    $body = @{ revokeRemote = $true; deleteLocal = $DeleteLocal } | ConvertTo-Json

    try {
        return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts/$AccountId/logout" -Headers $headers -Method Post -Body $body -TimeoutSec 60
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "404|Not Found") {
            Write-Host "Admin API not enabled. Restarting container with admin API..." -ForegroundColor Yellow
            Stop-Container
            Start-Container -AdminApiEnabled $true
            if (-not (Wait-ServiceReady)) {
                throw "Service did not become ready after restart."
            }
            return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts/$AccountId/logout" -Headers $headers -Method Post -Body $body -TimeoutSec 60
        } elseif ($msg -match "401|Unauthorized") {
            throw "Account signout failed with 401. API key mismatch. Run restart or rotate-key."
        } else {
            throw "Account signout failed: $msg"
        }
    }
}

function Accounts-Signout {
    $id = Resolve-AccountId
    $resp = Logout-Account -AccountId $id -DeleteLocal:$false
    Write-Host "Account signout completed. id=$id deleted=$($resp.deleted)"
}

function Accounts-SignoutAndDelete {
    $id = Resolve-AccountId
    $resp = Logout-Account -AccountId $id -DeleteLocal:$true
    Write-Host "Account signout+delete completed. id=$id deleted=$($resp.deleted)"
}

function Delete-AccountLocal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountId
    )

    $headers = Get-AuthHeaders
    try {
        return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts/$AccountId" -Headers $headers -Method Delete -TimeoutSec 20
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "404|Not Found") {
            Write-Host "Admin API not enabled. Restarting container with admin API..." -ForegroundColor Yellow
            Stop-Container
            Start-Container -AdminApiEnabled $true
            if (-not (Wait-ServiceReady)) {
                throw "Service did not become ready after restart."
            }
            return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts/$AccountId" -Headers $headers -Method Delete -TimeoutSec 20
        } elseif ($msg -match "401|Unauthorized") {
            throw "Account delete failed with 401. API key mismatch. Run restart or rotate-key."
        } else {
            throw "Account delete failed: $msg"
        }
    }
}

function Accounts-Delete {
    $id = Resolve-AccountId
    Delete-AccountLocal -AccountId $id | Out-Null
    Write-Host "Account delete completed. id=$id"
}

function Accounts-DeleteAndStop {
    Accounts-Delete
    Stop-Container
}

function Get-HttpErrorBody {
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    $body = $null
    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $body = [string]$ErrorRecord.ErrorDetails.Message
        }
    } catch {}

    if ([string]::IsNullOrWhiteSpace($body)) {
        try {
            if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.Content) {
                $body = $ErrorRecord.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            }
        } catch {}
    }

    return $body
}

function Invoke-GephyrApiJson {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)]$Body,
        [int]$TimeoutSec = 60
    )

    $headers = Get-AuthHeaders
    $headers["Content-Type"] = "application/json"
    $bodyJson = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }

    try {
        $response = Invoke-RestMethod -Uri $Uri -Method Post -Headers $headers -Body $bodyJson -TimeoutSec $TimeoutSec -ErrorAction Stop
        return [PSCustomObject]@{
            name = $Name
            ok = $true
            status_code = 200
            response = $response
            raw_error_body = $null
            parsed_error = $null
            error_message = $null
        }
    } catch {
        $statusCode = 0
        try {
            if ($_.Exception.Response) {
                if ($_.Exception.Response.StatusCode -is [int]) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                } elseif ($_.Exception.Response.StatusCode.value__) {
                    $statusCode = [int]$_.Exception.Response.StatusCode.value__
                } elseif ($_.Exception.Response.StatusCode) {
                    $statusCode = [int][string]$_.Exception.Response.StatusCode
                }
            }
        } catch {}

        if ($statusCode -eq 0) {
            $msg = [string]$_.Exception.Message
            if ($msg -match '\b([1-5][0-9]{2})\b') {
                $statusCode = [int]$Matches[1]
            }
        }

        $rawErrorBody = Get-HttpErrorBody -ErrorRecord $_
        $parsedError = $null
        if (-not [string]::IsNullOrWhiteSpace($rawErrorBody)) {
            try {
                $parsedError = $rawErrorBody | ConvertFrom-Json -ErrorAction Stop
            } catch {}
        }

        return [PSCustomObject]@{
            name = $Name
            ok = $false
            status_code = $statusCode
            response = $null
            raw_error_body = $rawErrorBody
            parsed_error = $parsedError
            error_message = [string]$_.Exception.Message
        }
    }
}

function Get-ClaudeQuotaResetHint {
    param([Parameter(Mandatory = $true)]$CallResult)

    if ($CallResult.ok) { return $null }

    $parts = @()
    if ($CallResult.error_message) { $parts += [string]$CallResult.error_message }
    if ($CallResult.raw_error_body) { $parts += [string]$CallResult.raw_error_body }
    if ($CallResult.parsed_error -and $CallResult.parsed_error.error -and $CallResult.parsed_error.error.message) {
        $parts += [string]$CallResult.parsed_error.error.message
    }
    $combined = ($parts -join "`n")
    if ([string]::IsNullOrWhiteSpace($combined)) { return $null }
    if ($CallResult.status_code -ne 429 -and $combined -notmatch 'RESOURCE_EXHAUSTED|rateLimitExceeded|quota') {
        return $null
    }

    if ($combined -match '"quotaResetTimeStamp"\s*:\s*"([^"]+)"') {
        return "Claude quota exhausted. Reset time: $($Matches[1])."
    }
    if ($combined -match 'quota will reset after ([^"\.\n]+)') {
        return "Claude quota exhausted. Reset after: $($Matches[1])."
    }
    if ($combined -match '"retryDelay"\s*:\s*"([^"]+)"') {
        return "Claude quota exhausted. Retry delay: $($Matches[1])."
    }

    return "Claude quota exhausted (HTTP 429)."
}

function Write-ClaudeQuotaWarning {
    param([Parameter(Mandatory = $true)]$CallResult)

    $hint = Get-ClaudeQuotaResetHint -CallResult $CallResult
    if ($hint) {
        Write-Warning "[W-CLAUDE-QUOTA] $hint"
    }
}

function Set-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Value
    )

    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) {
        $prop.Value = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function Get-OrCreateObjectProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $prop = $Object.PSObject.Properties[$Name]
    if ($prop -and $null -ne $prop.Value) {
        return $prop.Value
    }

    $child = [PSCustomObject]@{}
    if ($prop) {
        $prop.Value = $child
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $child
    }
    return $child
}

function Apply-ApiTestConfigOverride {
    param(
        [switch]$EnableSingleAttemptMode,
        [switch]$DisableAutoRefresh
    )

    $configPath = Join-Path $DataDir "config.json"
    if (-not (Test-Path $configPath)) {
        Write-Warning "[W-API-TEST-CONFIG] config.json not found at $configPath; cannot apply temporary retry/refresh overrides."
        return $null
    }

    $rawConfig = $null
    $config = $null
    try {
        $rawConfig = Get-Content $configPath -Raw
        $config = $rawConfig | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Warning "[W-API-TEST-CONFIG] Failed to parse config.json for temporary override: $($_.Exception.Message)"
        return $null
    }

    $changed = $false

    if ($EnableSingleAttemptMode) {
        $proxy = Get-OrCreateObjectProperty -Object $config -Name "proxy"
        $compliance = Get-OrCreateObjectProperty -Object $proxy -Name "compliance"

        if (-not $compliance.enabled) {
            Set-ObjectPropertyValue -Object $compliance -Name "enabled" -Value $true
            $changed = $true
        }
        if ($compliance.max_retry_attempts -ne 1) {
            Set-ObjectPropertyValue -Object $compliance -Name "max_retry_attempts" -Value 1
            $changed = $true
        }
    }

    if ($DisableAutoRefresh -and $config.auto_refresh -ne $false) {
        Set-ObjectPropertyValue -Object $config -Name "auto_refresh" -Value $false
        $changed = $true
    }

    if (-not $changed) {
        return [PSCustomObject]@{
            applied = $false
            path = $configPath
            original_json = $rawConfig
        }
    }

    $updatedJson = $config | ConvertTo-Json -Depth 25
    Set-Content -Path $configPath -Value $updatedJson -Encoding UTF8

    return [PSCustomObject]@{
        applied = $true
        path = $configPath
        original_json = $rawConfig
    }
}

function Restore-ApiTestConfigOverride {
    param([Parameter(Mandatory = $false)]$OverrideContext)

    if (-not $OverrideContext) {
        return
    }
    if (-not $OverrideContext.applied) {
        return
    }

    try {
        Set-Content -Path $OverrideContext.path -Value $OverrideContext.original_json -Encoding UTF8
        Write-Host "Restored config after api-test-all temporary override." -ForegroundColor DarkGray
    } catch {
        Write-Warning "[W-API-TEST-CONFIG-RESTORE] Failed to restore original config: $($_.Exception.Message)"
    }
}

function Run-ApiTest {
    $body = @{
        model = $Model
        max_tokens = 96
        messages = @(
            @{
                role = "user"
                content = $Prompt
            }
        )
    }

    $result = Invoke-GephyrApiJson -Name "openai" -Uri "http://127.0.0.1:$Port/v1/chat/completions" -Body $body -TimeoutSec 60
    if (-not $result.ok) {
        if ($Model -match '(?i)^claude') {
            Write-ClaudeQuotaWarning -CallResult $result
        }
        $detail = if ($result.raw_error_body) { $result.raw_error_body } else { $result.error_message }
        throw "API test failed (HTTP $($result.status_code)): $detail"
    }

    $res = $result.response
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

function Run-ApiTestAll {
    $extraNoRetry = $ExtraArgs -contains "--no-retry" -or $ExtraArgs -contains "--single-attempt"
    $extraTestPipe = $ExtraArgs -contains "--test-pipe"
    $singleAttemptMode = $SingleAttempt.IsPresent -or $extraNoRetry -or $TestPipe.IsPresent -or $extraTestPipe
    $disableAutoRefresh = $TestPipe.IsPresent -or $extraTestPipe

    $overrideContext = Apply-ApiTestConfigOverride `
        -EnableSingleAttemptMode:$singleAttemptMode `
        -DisableAutoRefresh:$disableAutoRefresh

    if ($overrideContext -and $overrideContext.applied) {
        $modeLabel = if ($disableAutoRefresh) { "test-pipe" } elseif ($singleAttemptMode) { "single-attempt" } else { "default" }
        Write-Host "Applied temporary api-test-all runtime override mode: $modeLabel" -ForegroundColor DarkGray
    }

    try {
        $tests = @(
            @{
                Name = "OpenAI"
                Uri = "http://127.0.0.1:$Port/v1/chat/completions"
                Body = @{
                    model = $Model
                    max_tokens = 64
                    messages = @(
                        @{
                            role = "user"
                            content = "Reply with exactly OK."
                        }
                    )
                }
                Validate = {
                    param($response)
                    if ($response.choices -and $response.choices.Count -gt 0) { return $null }
                    return "missing choices in response"
                }
                WarnClaude = $false
            },
            @{
                Name = "Claude"
                Uri = "http://127.0.0.1:$Port/v1/messages"
                Body = @{
                    model = $ClaudeModel
                    max_tokens = 64
                    messages = @(
                        @{
                            role = "user"
                            content = "Reply with exactly OK."
                        }
                    )
                }
                Validate = {
                    param($response)
                    if ($response.content -or $response.id -or $response.type) { return $null }
                    return "missing content/id in response"
                }
                WarnClaude = $true
            },
            @{
                Name = "Gemini"
                Uri = "http://127.0.0.1:$Port/v1beta/models/gemini-2.5-flash:generateContent"
                Body = @{
                    generationConfig = @{
                        maxOutputTokens = 64
                    }
                    contents = @(
                        @{
                            role = "user"
                            parts = @(
                                @{
                                    text = "Reply with exactly OK."
                                }
                            )
                        }
                    )
                }
                Validate = {
                    param($response)
                    if ($response.candidates -and $response.candidates.Count -gt 0) { return $null }
                    return "missing candidates in response"
                }
                WarnClaude = $false
            }
        )

        $results = @()
        foreach ($test in $tests) {
            $call = Invoke-GephyrApiJson -Name $test.Name -Uri $test.Uri -Body $test.Body -TimeoutSec 60
            if ($test.WarnClaude) {
                Write-ClaudeQuotaWarning -CallResult $call
            }

            if ($call.ok) {
                $validationError = & $test.Validate $call.response
                if ([string]::IsNullOrWhiteSpace([string]$validationError)) {
                    $results += [PSCustomObject]@{
                        provider = $test.Name
                        pass = $true
                        status_code = 200
                        reason = ""
                    }
                } else {
                    $results += [PSCustomObject]@{
                        provider = $test.Name
                        pass = $false
                        status_code = 200
                        reason = [string]$validationError
                    }
                }
            } else {
                $reason = if ($call.raw_error_body) { [string]$call.raw_error_body } else { [string]$call.error_message }
                $reason = ($reason -replace '\s+', ' ').Trim()
                if ($reason.Length -gt 220) {
                    $reason = $reason.Substring(0, 220) + "..."
                }
                $results += [PSCustomObject]@{
                    provider = $test.Name
                    pass = $false
                    status_code = $call.status_code
                    reason = $reason
                }
            }
        }

        if ($Json) {
            [PSCustomObject]@{
                passed = (@($results | Where-Object { $_.pass }).Count)
                failed = (@($results | Where-Object { -not $_.pass }).Count)
                results = $results
            } | ConvertTo-Json -Depth 8
            return
        }

        Write-Host ""
        Write-Host "API test-all results:" -ForegroundColor Cyan
        foreach ($r in $results) {
            if ($r.pass) {
                Write-Host ("  [PASS] {0}" -f $r.provider) -ForegroundColor Green
            } else {
                Write-Host ("  [FAIL] {0} (HTTP {1})" -f $r.provider, $r.status_code) -ForegroundColor Red
                if ($r.reason) {
                    Write-Host ("         {0}" -f $r.reason) -ForegroundColor DarkYellow
                }
            }
        }

        $passCount = @($results | Where-Object { $_.pass }).Count
        $failCount = @($results | Where-Object { -not $_.pass }).Count
        Write-Host ""
        if ($failCount -eq 0) {
            Write-Host "Summary: $passCount passed, $failCount failed." -ForegroundColor Green
        } else {
            Write-Host "Summary: $passCount passed, $failCount failed." -ForegroundColor Yellow
        }
    } finally {
        Restore-ApiTestConfigOverride -OverrideContext $overrideContext
    }
}

function Start-OAuthFlow {
    Start-Container -AdminApiEnabled $true
    if (-not (Wait-ServiceReady)) {
        throw "Service did not become ready on http://127.0.0.1:$Port."
    }

    if (-not $env:ENCRYPTION_KEY) {
        Write-Warning "[W-CRYPTO-KEY-MISSING] ENCRYPTION_KEY is not set in your shell/.env.local. In Docker/container environments machine UID may be unavailable. Remediation: set ENCRYPTION_KEY, restart container, then rerun login."
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
    $env:API_KEY = $newKey
    Save-EnvValue -Name "API_KEY" -Value $newKey
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

function Invoke-Rebuild {
    param([switch]$UseNoCache)

    $dockerfilePath = Join-Path $PSScriptRoot "docker/Dockerfile"
    if (-not (Test-Path $dockerfilePath)) {
        throw "Dockerfile not found at: $dockerfilePath"
    }

    if (-not $Quiet) {
        Write-Host "Building Docker image: $Image" -ForegroundColor Cyan
        if ($UseNoCache) {
            Write-Host "Mode: no-cache (clean build)" -ForegroundColor Yellow
        }
    }

    $buildArgs = @("build", "-t", $Image, "-f", "docker/Dockerfile", ".")
    if ($UseNoCache) {
        $buildArgs = @("build", "--no-cache", "-t", $Image, "-f", "docker/Dockerfile", ".")
    }

    & docker @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Docker build failed with exit code $LASTEXITCODE"
    }

    if (-not $Quiet) {
        Write-Host ""
        Write-Host "Build completed: $Image" -ForegroundColor Green
    }
}

function Update-Gephyr {
    $repoRoot = $PSScriptRoot

    # 1. Pre-flight: warn about uncommitted changes
    $gitStatus = git -C $repoRoot status --porcelain 2>$null
    if ($gitStatus) {
        Write-Host "" 
        Write-Host "  WARNING: You have uncommitted changes:" -ForegroundColor Yellow
        $gitStatus | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
        Write-Host ""
        $confirm = Read-Host "  Continue with update? (y/N)"
        if ($confirm -notin @("y", "Y", "yes")) {
            Write-Host "Update cancelled."
            return
        }
    }

    # 2. Pre-flight: check if container is running and healthy
    $wasRunning = $false
    $wasAdminEnabled = $false
    if (Test-ContainerExists) {
        $info = docker ps --format "{{.Names}}|{{.Status}}" | Where-Object { $_ -match "^$([regex]::Escape($ContainerName))\|" }
        if ($info -and ($info -match "Up")) {
            $wasRunning = $true
            Write-Host "Container is running. Checking health before update..." -ForegroundColor Cyan
            try {
                $headers = Get-AuthHeaders
                $null = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -Headers $headers -Method Get -TimeoutSec 5
                Write-Host "  Health: OK" -ForegroundColor Green
            } catch {
                Write-Host "  Health: FAILED — proceeding anyway" -ForegroundColor Yellow
            }
            # Check if admin API is enabled
            try {
                $null = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/accounts" -Headers $headers -Method Get -TimeoutSec 5
                $wasAdminEnabled = $true
            } catch {}
        }
    }

    # 3. Git pull
    Write-Host ""
    Write-Host "Pulling latest changes..." -ForegroundColor Cyan
    $pullOutput = git -C $repoRoot pull 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  git pull failed:" -ForegroundColor Red
        Write-Host "  $pullOutput" -ForegroundColor Red
        throw "git pull failed. Resolve conflicts and retry."
    }
    Write-Host "  $pullOutput" -ForegroundColor White

    # 4. Rebuild
    Write-Host ""
    Write-Host "Rebuilding Docker image..." -ForegroundColor Cyan
    Invoke-Rebuild -UseNoCache:$false

    # 5. Restart if was running
    if ($wasRunning) {
        Write-Host ""
        Write-Host "Restarting container..." -ForegroundColor Cyan
        $adminFlag = $EnableAdminApi.IsPresent -or $wasAdminEnabled
        Stop-Container
        Start-Container -AdminApiEnabled $adminFlag
        if (Wait-ServiceReady) {
            Write-Host "  Service is healthy." -ForegroundColor Green
            Show-Status
        } else {
            throw "Service did not become ready after update."
        }
    } else {
        Write-Host ""
        Write-Host "Update complete. Container was not running; start it with: .\console.ps1 start" -ForegroundColor Green
    }
}

function Show-Version {
    $cargoPath = Join-Path $PSScriptRoot "Cargo.toml"
    if (-not (Test-Path $cargoPath)) {
        throw "Cargo.toml not found at: $cargoPath"
    }

    $version = Select-String -Path $cargoPath -Pattern '^version\s*=\s*"([^"]+)"' | 
        ForEach-Object { $_.Matches[0].Groups[1].Value } |
        Select-Object -First 1

    if ($Json) {
        @{ version = $version; image = $Image } | ConvertTo-Json
    } else {
        Write-Host "gephyr $version"
    }
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
$dockerCommands = @(
    "start", "stop", "restart", "status", "logs", "health", "check", "canary",
    "login", "oauth", "auth", "accounts", "api-test", "api-test-all", "rotate-key", "docker-repair", "update",
    "accounts-signout", "accounts-signout-and-delete",
    "accounts-signout-all", "accounts-signout-all-and-stop",
    "accounts-delete", "accounts-delete-and-stop",
    "accounts-delete-all", "accounts-delete-all-and-stop"
)

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
    "health" { Show-Health -AsJson:$Json.IsPresent }
    "check" { Show-AccountHealthCheck -AsJson:$Json.IsPresent }
    "canary" {
        $Run = $false
        if ($ExtraArgs -contains "--run" -or $env:CMD_ARGS -match "--run") { $Run = $true }
        Show-TlsCanary -AsJson:$Json.IsPresent -Run:$Run
    }
    "login" { Start-OAuthFlow }
    "oauth" { Start-OAuthFlow }
    "auth" { Start-OAuthFlow }
    "accounts" { Show-Accounts -AsJson:$Json.IsPresent }
    "api-test" { Run-ApiTest }
    "api-test-all" { Run-ApiTestAll }
    "rotate-key" { Rotate-ApiKey }
    "docker-repair" { Repair-DockerBuilder -AggressiveMode:$Aggressive.IsPresent }
    "rebuild" { Invoke-Rebuild -UseNoCache:$NoCache.IsPresent }
    "update" { Update-Gephyr }
    "version" { Show-Version }
    "accounts-signout" { Accounts-Signout }
    "accounts-signout-and-delete" { Accounts-SignoutAndDelete }
    "accounts-signout-all" { Accounts-SignoutAll }
    "accounts-signout-all-and-stop" { Accounts-SignoutAllAndStop }
    "accounts-delete" { Accounts-Delete }
    "accounts-delete-and-stop" { Accounts-DeleteAndStop }
    "accounts-delete-all" { Accounts-DeleteAll }
    "accounts-delete-all-and-stop" { Accounts-DeleteAllAndStop }
    default { Write-Usage }
}
