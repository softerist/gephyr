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
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
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
  check        Run account token health check (refresh expiring tokens)
  canary       Show/Run TLS stealth canary probe (use --run to trigger)
  login        Start container with admin API, fetch /api/auth/url, open browser
  oauth/auth   Alias for login
  accounts     Call /api/accounts
  api-test     Run one API test completion
  rotate-key   Generate new API key, save to .env.local, and optionally restart
  docker-repair  Repair Docker builder cache issues (e.g., missing snapshot errors)
  rebuild      Rebuild Docker image from source
  update       Pull latest code, rebuild image, and restart container
  version      Show version from Cargo.toml
  accounts-signout-all  Sign out all linked accounts (revoke + local token clear/disable)
  accounts-signout-all-and-stop  Sign out all linked accounts, then stop container
  accounts-delete-all   Delete local account records (does not revoke)
  accounts-delete-all-and-stop  Delete local accounts, then stop container

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
  -Json                  Output machine-readable JSON (for status, health, accounts)
  -Quiet                 Suppress non-essential output (for CI/automation)
  -NoCache               For rebuild: build without Docker cache

Examples:
  .\console.ps1 start
  .\console.ps1 login
  .\console.ps1 logs -LogLines 200
  .\console.ps1 rotate-key
  .\console.ps1 rebuild
  .\console.ps1 rebuild -NoCache
  .\console.ps1 docker-repair
  .\console.ps1 docker-repair -Aggressive
  .\console.ps1 accounts-signout-all
  .\console.ps1 accounts-signout-all-and-stop
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
    $allowLan = if ($env:ALLOW_LAN_ACCESS) { $env:ALLOW_LAN_ACCESS } else { "true" }

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
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/healthz" -Headers $headers -UseBasicParsing -TimeoutSec 2
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
            $healthData = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -Headers $headers -Method Get -TimeoutSec 5
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
                            $sn = ($m.name -replace '^models/', '').Length
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
                            $modelOrder = @('claude-opus', 'claude-sonnet', 'gemini-3-pro-high', 'gemini-3-pro-low', 'gemini-3-flash')
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
                                $shortName = $m.name -replace '^models/', ''
                                $padded = $shortName.PadRight($modelPad)
                                $barColor = if ($pct -ge 70) { "Green" } elseif ($pct -ge 30) { "Yellow" } else { "Red" }
                                $pctStr = "$pct%".PadLeft(4)

                                Write-Host "      $padded " -NoNewline -ForegroundColor DarkGray
                                Write-Host "$bar" -NoNewline -ForegroundColor $barColor
                                Write-Host "  $pctStr" -NoNewline -ForegroundColor White

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
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -Headers $headers -Method Get -TimeoutSec 10
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
                $null = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -Headers $headers -Method Get -TimeoutSec 5
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
    "login", "oauth", "auth", "accounts", "api-test", "rotate-key", "docker-repair", "update",
    "accounts-signout-all", "accounts-signout-all-and-stop",
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
    "rotate-key" { Rotate-ApiKey }
    "docker-repair" { Repair-DockerBuilder -AggressiveMode:$Aggressive.IsPresent }
    "rebuild" { Invoke-Rebuild -UseNoCache:$NoCache.IsPresent }
    "update" { Update-Gephyr }
    "version" { Show-Version }
    "accounts-signout-all" { Accounts-SignoutAll }
    "accounts-signout-all-and-stop" { Accounts-SignoutAllAndStop }
    "accounts-delete-all" { Accounts-DeleteAll }
    "accounts-delete-all-and-stop" { Accounts-DeleteAllAndStop }
    default { Write-Usage }
}
