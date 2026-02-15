param(
    [string]$ConfigPath = "$env:USERPROFILE\.gephyr\config.json",
    [string]$KnownGoodPath = "output/known_good.gephyr_scope.jsonl",
    [string]$KnownGoodSourcePath = "output/known_good.jsonl",
    [ValidateSet("Gephyr", "Antigravity", "Raw")]
    [string]$Scope = "Gephyr",
    [string]$OutGephyrPath = "output/gephyr_google_outbound_headers.jsonl",
    [int]$StartupTimeoutSeconds = 60,
    [switch]$RequireOAuthRelink,
    [switch]$SkipExtendedFlow,
    [switch]$SkipBulkQuotaRefresh,
    [switch]$NoClaudeProbes,
    [string]$AntigravityAllowlistPath = "scripts/allowlists/antigravity_google_endpoints_default_chat.txt"
)

$ErrorActionPreference = "Stop"

function Get-EnvFileValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if (-not (Test-Path $Path)) { return $null }
    foreach ($line in Get-Content $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
        if ($trimmed -match "^\s*$([regex]::Escape($Name))\s*=\s*(.+)\s*$") {
            $value = $Matches[1].Trim()
            if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            return $value
        }
    }
    return $null
}

function Ensure-EnvFromEnvLocal {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$Required
    )
    $current = [Environment]::GetEnvironmentVariable($Name, "Process")
    if (-not $current) {
        $fromEnvLocal = Get-EnvFileValue -Path ".env.local" -Name $Name
        if ($fromEnvLocal) {
            [Environment]::SetEnvironmentVariable($Name, $fromEnvLocal, "Process")
            Write-Host "Loaded $Name from .env.local for this run."
        }
    }
    $current = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ($Required -and -not $current) {
        throw "$Name is required but missing. Set it in environment or .env.local."
    }
}

function Invoke-Api {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [string]$Method = "GET",
        [object]$Body = $null,
        [int]$TimeoutSec = 30,
        [hashtable]$ExtraHeaders = @{},
        [switch]$Raw
    )

    $headers = @{ Authorization = "Bearer $ApiKey" }
    foreach ($key in $ExtraHeaders.Keys) {
        $headers[$key] = $ExtraHeaders[$key]
    }

    if ($null -eq $Body) {
        if ($Raw) {
            return Invoke-WebRequest -Method $Method -Uri $Uri -Headers $headers -TimeoutSec $TimeoutSec
        }
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -TimeoutSec $TimeoutSec
    }

    if (-not $headers.ContainsKey("Content-Type")) {
        $headers["Content-Type"] = "application/json"
    }
    $payload = $Body | ConvertTo-Json -Depth 20 -Compress
    if ($Raw) {
        return Invoke-WebRequest -Method $Method -Uri $Uri -Headers $headers -Body $payload -TimeoutSec $TimeoutSec
    }
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $payload -TimeoutSec $TimeoutSec
}

function Invoke-ParityProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [string]$Method = "POST",
        [object]$Body = $null,
        [int]$TimeoutSec = 120,
        [hashtable]$ExtraHeaders = @{},
        [switch]$Raw
    )

    try {
        if ($Raw) {
            $resp = Invoke-Api -Method $Method -Uri $Uri -ApiKey $ApiKey -Body $Body -TimeoutSec $TimeoutSec -ExtraHeaders $ExtraHeaders -Raw
            $content = [string]$resp.Content
            Write-Host "$Name`: OK (status=$([int]$resp.StatusCode), content_length=$($content.Length))"
        } else {
            $null = Invoke-Api -Method $Method -Uri $Uri -ApiKey $ApiKey -Body $Body -TimeoutSec $TimeoutSec -ExtraHeaders $ExtraHeaders
            Write-Host "$Name`: OK"
        }
        return $true
    } catch {
        Write-Host "$Name failed (continuing): $($_.Exception.Message)"
        return $false
    }
}

function Write-GoogleOutboundRecordsFromLines {
    param(
        [Parameter(Mandatory = $true)][object[]]$Lines,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Cutoff,
        [Parameter(Mandatory = $true)][string]$OutPath
    )
    $ansi = [regex]"\x1B\[[0-9;]*[A-Za-z]"
    foreach ($raw in $Lines) {
        $line = $ansi.Replace([string]$raw, "")
        if ($line -match '^(?<ts>\S+)\s+DEBUG .*google_outbound_headers .*endpoint=(?:"(?<ep1>[^"]+)"|(?<ep2>\S+)) .*mode=(?:"(?<m1>[^"]+)"|(?<m2>\S+)) .*headers=(?<hdr>\{.*\})$') {
            $endpoint = if ($Matches["ep1"]) { $Matches["ep1"] } else { $Matches["ep2"] }
            $mode = if ($Matches["m1"]) { $Matches["m1"] } else { $Matches["m2"] }
            try {
                $ts = [DateTimeOffset]::Parse($Matches["ts"])
            } catch {
                continue
            }
            if ($ts -ge $Cutoff) {
                $obj = [ordered]@{
                    timestamp = $Matches["ts"]
                    endpoint = $endpoint
                    mode = $mode
                    headers = ($Matches["hdr"] | ConvertFrom-Json)
                }
                ($obj | ConvertTo-Json -Compress -Depth 20) | Add-Content $OutPath
            }
        }
    }
}

function Is-GoogleEndpoint {
    param([string]$Endpoint)
    if (-not $Endpoint) { return $false }
    return $Endpoint -match '(?i)^https?://[^/]*(googleapis\.com|google\.com)(?::\d+)?/'
}

function Normalize-Endpoint {
    param([string]$Endpoint)
    if (-not $Endpoint) { return $Endpoint }
    try {
        $uri = [System.Uri]$Endpoint
    } catch {
        return $Endpoint
    }

    $normalizedHost = $uri.Host.ToLowerInvariant()
    if ($normalizedHost -eq "daily-cloudcode-pa.googleapis.com") {
        $normalizedHost = "cloudcode-pa.googleapis.com"
    }

    $portPart = ""
    if (-not $uri.IsDefaultPort) {
        $portPart = ":$($uri.Port)"
    }
    return "{0}://{1}{2}{3}" -f $uri.Scheme.ToLowerInvariant(), $normalizedHost, $portPart, $uri.PathAndQuery
}

function Is-AntigravityUserAgent {
    param([string]$UserAgent)
    if (-not $UserAgent) { return $false }
    return ($UserAgent -match '(?i)^antigravity/') -or ($UserAgent -match '(?i)^google-api-nodejs-client/10\.3\.0$')
}

function Build-GephyrScopedKnownGood {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$GephyrTracePath,
        [Parameter(Mandatory = $true)][string]$OutPath
    )

    if (-not (Test-Path $SourcePath)) {
        throw "Known-good source not found: $SourcePath"
    }
    if (-not (Test-Path $GephyrTracePath)) {
        throw "Gephyr trace not found for Gephyr scope build: $GephyrTracePath"
    }

    $gephyrEndpoints = New-Object System.Collections.Generic.HashSet[string]
    foreach ($line in Get-Content $GephyrTracePath) {
        $trim = $line.Trim()
        if (-not $trim) { continue }
        try {
            $obj = $trim | ConvertFrom-Json
        } catch {
            continue
        }
        $ep = [string]$obj.endpoint
        if (-not (Is-GoogleEndpoint -Endpoint $ep)) { continue }
        [void]$gephyrEndpoints.Add((Normalize-Endpoint -Endpoint $ep))
    }

    $selected = New-Object System.Collections.Generic.List[string]
    foreach ($line in Get-Content $SourcePath) {
        $trim = $line.Trim()
        if (-not $trim) { continue }
        try {
            $obj = $trim | ConvertFrom-Json
        } catch {
            continue
        }
        $ep = [string]$obj.endpoint
        if (-not (Is-GoogleEndpoint -Endpoint $ep)) { continue }
        $normalized = Normalize-Endpoint -Endpoint $ep
        if ($gephyrEndpoints.Contains($normalized)) {
            $selected.Add($trim)
        }
    }

    $selected | Set-Content -Path $OutPath -Encoding UTF8
    return $selected.Count
}

function Build-AntigravityScopedKnownGood {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$AllowlistPath,
        [Parameter(Mandatory = $true)][string]$OutPath
    )

    if (-not (Test-Path $SourcePath)) {
        throw "Known-good source not found: $SourcePath"
    }
    if (-not (Test-Path $AllowlistPath)) {
        throw "Antigravity allowlist not found: $AllowlistPath"
    }

    $allowSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($line in Get-Content $AllowlistPath) {
        $trim = $line.Trim()
        if (-not $trim -or $trim.StartsWith("#")) { continue }
        [void]$allowSet.Add((Normalize-Endpoint -Endpoint $trim))
    }

    $selected = New-Object System.Collections.Generic.List[string]
    foreach ($line in Get-Content $SourcePath) {
        $trim = $line.Trim()
        if (-not $trim) { continue }
        try {
            $obj = $trim | ConvertFrom-Json
        } catch {
            continue
        }
        $ep = [string]$obj.endpoint
        if (-not (Is-GoogleEndpoint -Endpoint $ep)) { continue }
        $normalized = Normalize-Endpoint -Endpoint $ep
        if (-not $allowSet.Contains($normalized)) { continue }

        $ua = $null
        try { $ua = [string]$obj.headers.'user-agent' } catch {}
        if (Is-AntigravityUserAgent -UserAgent $ua) {
            $selected.Add($trim)
        }
    }

    $selected | Set-Content -Path $OutPath -Encoding UTF8
    return $selected.Count
}

if (-not (Test-Path $ConfigPath)) {
    throw "Config not found: $ConfigPath"
}
if ($Scope -eq "Raw" -and -not (Test-Path $KnownGoodPath)) {
    throw "Known-good trace not found: $KnownGoodPath"
}
if ($Scope -ne "Raw" -and -not (Test-Path $KnownGoodSourcePath)) {
    throw "Known-good source trace not found for Scope '$Scope': $KnownGoodSourcePath"
}

Ensure-EnvFromEnvLocal -Name "ENCRYPTION_KEY" -Required
# Needed when -RequireOAuthRelink is requested (server validates these on /api/auth/url).
Ensure-EnvFromEnvLocal -Name "GOOGLE_OAUTH_CLIENT_ID"
Ensure-EnvFromEnvLocal -Name "GOOGLE_OAUTH_CLIENT_SECRET"
Ensure-EnvFromEnvLocal -Name "GOOGLE_OAUTH_REDIRECT_URI"

if ($RequireOAuthRelink) {
    if (-not $env:GOOGLE_OAUTH_CLIENT_ID) {
        throw "GOOGLE_OAUTH_CLIENT_ID is missing. Set it in environment or .env.local before using -RequireOAuthRelink."
    }
    if (-not $env:GOOGLE_OAUTH_CLIENT_SECRET) {
        throw "GOOGLE_OAUTH_CLIENT_SECRET is missing. Set it in environment or .env.local before using -RequireOAuthRelink."
    }
}

Write-Host "Building latest gephyr binary ..."
cargo build --bin gephyr | Out-Null

$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$apiKey = [string]$cfg.proxy.api_key
$port = [int]$cfg.proxy.port
$apiBase = "http://127.0.0.1:$port"

Write-Host "Starting Gephyr with ENABLE_ADMIN_API=true and RUST_LOG=debug ..."
# Stop any pre-existing gephyr instance on the configured port/process list.
Get-Process gephyr -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        Stop-Process -Id $_.Id -ErrorAction Stop
        Write-Host "Stopped existing gephyr process: $($_.Id)"
    } catch {
        Write-Host "Could not stop existing gephyr process $($_.Id): $($_.Exception.Message)"
    }
}

$job = Start-Job -ScriptBlock {
    param(
        [string]$repoPath,
        [string]$encryptionKey,
        [string]$oauthClientId,
        [string]$oauthClientSecret,
        [string]$oauthRedirectUri
    )
    Set-Location $repoPath
    $env:ENABLE_ADMIN_API = "true"
    $env:ABV_ENABLE_ADMIN_API = "true"
    $env:ENCRYPTION_KEY = $encryptionKey
    if ($oauthClientId) { $env:GOOGLE_OAUTH_CLIENT_ID = $oauthClientId }
    if ($oauthClientSecret) { $env:GOOGLE_OAUTH_CLIENT_SECRET = $oauthClientSecret }
    if ($oauthRedirectUri) { $env:GOOGLE_OAUTH_REDIRECT_URI = $oauthRedirectUri }
    $env:RUST_LOG = "debug"
    & ".\target\debug\gephyr.exe"
} -ArgumentList (Get-Location).Path, $env:ENCRYPTION_KEY, $env:GOOGLE_OAUTH_CLIENT_ID, $env:GOOGLE_OAUTH_CLIENT_SECRET, $env:GOOGLE_OAUTH_REDIRECT_URI

try {
    $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
    $isUp = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $health = Invoke-Api -Uri "$apiBase/api/health" -ApiKey $apiKey -TimeoutSec 3
            if ($null -ne $health) {
                $isUp = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 700
        }
    }
    if (-not $isUp) {
        $jobLog = Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue
        if ($jobLog) {
            Write-Host "Gephyr startup output (tail):"
            $jobLog | Select-Object -Last 60 | ForEach-Object { Write-Host $_ }
        }
        throw "Gephyr admin API did not become reachable on $apiBase"
    }
    Write-Host "API is up at $apiBase"

    try {
        Invoke-Api -Method POST -Uri "$apiBase/api/proxy/start" -ApiKey $apiKey -TimeoutSec 20 | Out-Null
        Write-Host "Proxy service start requested."
    } catch {
        Write-Host "Proxy start returned error (continuing): $($_.Exception.Message)"
    }

    $policy = Invoke-Api -Uri "$apiBase/api/proxy/google/outbound-policy" -ApiKey $apiKey
    Write-Host "Effective mode: $($policy.mode)"
    if ($policy.mimic) {
        Write-Host "Mimic profile: $($policy.mimic.profile)"
        Write-Host "Trigger on auth events: $($policy.mimic.trigger_on_auth_events)"
        Write-Host "Cooldown seconds: $($policy.mimic.cooldown_seconds)"
        Write-Host "Userinfo endpoint: $($policy.mimic.userinfo_endpoint)"
    } else {
        Write-Host "Mimic block missing in outbound policy response."
    }

    if (-not $policy.debug.log_google_outbound_headers) {
        Write-Host "Enabling debug.log_google_outbound_headers via /api/config ..."
        $liveConfig = Invoke-Api -Uri "$apiBase/api/config" -ApiKey $apiKey
        $liveConfig.proxy.debug_logging.log_google_outbound_headers = $true
        Invoke-Api -Method POST -Uri "$apiBase/api/config" -ApiKey $apiKey -Body @{ config = $liveConfig } -TimeoutSec 60 | Out-Null
        $policy = Invoke-Api -Uri "$apiBase/api/proxy/google/outbound-policy" -ApiKey $apiKey
        Write-Host "log_google_outbound_headers now: $($policy.debug.log_google_outbound_headers)"
    }

    $cutoff = [DateTimeOffset]::UtcNow
    Write-Host "Cutoff UTC: $($cutoff.ToString("o"))"
    Write-Host "Diff scope: $Scope"

    if ($RequireOAuthRelink) {
        Write-Host "Preparing OAuth relink URL ..."
        $oauth = Invoke-Api -Uri "$apiBase/api/auth/url" -ApiKey $apiKey -TimeoutSec 30
        if (-not $oauth.url) {
            throw "OAuth prepare did not return a URL."
        }
        Write-Host "Open this URL and complete Google consent:"
        Write-Host $oauth.url
        try {
            Start-Process $oauth.url | Out-Null
        } catch {
            Write-Host "Auto-open failed. Open the URL manually."
        }
        Read-Host "After consent completes in browser, press Enter to continue"

        $linked = $false
        for ($i = 1; $i -le 90; $i++) {
            try {
                $status = Invoke-Api -Uri "$apiBase/api/auth/status" -ApiKey $apiKey -TimeoutSec 10
                $phase = [string]$status.phase
                $detail = [string]$status.detail
                Write-Host "OAuth status [$i/90]: phase=$phase detail=$detail"
                if ($phase -eq "linked") {
                    $linked = $true
                    break
                }
                if ($phase -in @("failed", "rejected", "cancelled")) {
                    break
                }
            } catch {
                Write-Host "OAuth status check error: $($_.Exception.Message)"
            }
            Start-Sleep -Seconds 2
        }
        if (-not $linked) {
            Write-Host "OAuth flow did not reach linked state in this window; continuing anyway."
        }
    }

    $accountsResp = Invoke-Api -Uri "$apiBase/api/accounts" -ApiKey $apiKey
    $accounts = @($accountsResp.accounts)
    $accountId = $accountsResp.current_account_id
    if (-not $accountId -and $accounts.Count -gt 0) {
        $accountId = $accounts[0].id
    }
    Write-Host "Accounts found: $($accounts.Count)"
    Write-Host "Active account id: $accountId"

    if ($accountId) {
        foreach ($acc in $accounts) {
            $targetId = $acc.id
            try {
                Invoke-Api -Method POST -Uri "$apiBase/api/accounts/switch" -ApiKey $apiKey -Body @{ accountId = $targetId } -TimeoutSec 40 | Out-Null
                Write-Host "Switch account call [$targetId]: OK"
            } catch {
                Write-Host "Switch account call [$targetId] failed (continuing): $($_.Exception.Message)"
            }

            try {
                $quota = Invoke-Api -Uri "$apiBase/api/accounts/$targetId/quota" -ApiKey $apiKey -TimeoutSec 60
                $quotaModels = @($quota.models).Count
                Write-Host "Quota fetch call [$targetId]: OK (models=$quotaModels)"
            } catch {
                Write-Host "Quota fetch [$targetId] failed (continuing): $($_.Exception.Message)"
            }
        }
    } else {
        Write-Host "No account found. Skipping switch/quota auth-event triggers."
    }

    try {
        $chat = Invoke-Api -Method POST -Uri "$apiBase/v1/chat/completions" -ApiKey $apiKey -TimeoutSec 120 -Body @{
            model = "gemini-3-flash"
            messages = @(
                @{
                    role = "user"
                    content = "ping from live parity verify"
                }
            )
            max_tokens = 32
        }
        $content = $chat.choices[0].message.content
        if ($content -is [array]) { $content = ($content -join " ") }
        Write-Host "Chat call: OK (content_length=$(([string]$content).Length))"
    } catch {
        Write-Host "Chat call failed: $($_.Exception.Message)"
    }

    if (-not $SkipExtendedFlow) {
        Write-Host "Running extended parity probes across ingress routes ..."
        if ($NoClaudeProbes) {
            Write-Host "Claude probes disabled (-NoClaudeProbes)."
        }

        if (-not $SkipBulkQuotaRefresh) {
            try {
                $bulk = Invoke-Api -Method POST -Uri "$apiBase/api/accounts/refresh" -ApiKey $apiKey -TimeoutSec 180 -ExtraHeaders @{
                    "x-gephyr-confirm-bulk-refresh" = "true"
                }
                Write-Host "Bulk quota refresh: OK (success=$($bulk.success), refreshed=$($bulk.refreshed), failed=$($bulk.failed))"
            } catch {
                Write-Host "Bulk quota refresh failed (continuing): $($_.Exception.Message)"
            }
        } else {
            Write-Host "Bulk quota refresh skipped."
        }

        $geminiBody = @{
            contents = @(
                @{
                    role = "user"
                    parts = @(
                        @{
                            text = "ping from live parity verify (gemini ingress)"
                        }
                    )
                }
            )
            generationConfig = @{
                maxOutputTokens = 32
            }
        }
        $openAiChatBody = @{
            model = "gemini-3-flash"
            messages = @(
                @{
                    role = "user"
                    content = "ping from live parity verify (chat/completions)"
                }
            )
            max_tokens = 32
        }
        $openAiCompletionsBody = @{
            model = "gemini-3-flash"
            prompt = "ping from live parity verify (completions)"
            max_tokens = 32
        }
        $responsesBody = @{
            model = "gemini-3-flash"
            input = "ping from live parity verify (responses)"
            max_output_tokens = 32
        }
        $probeSpecs = @(
            @{
                Name = "/v1/chat/completions"
                Uri = "$apiBase/v1/chat/completions"
                Method = "POST"
                Body = $openAiChatBody
                Raw = $false
            },
            @{
                Name = "/v1/completions"
                Uri = "$apiBase/v1/completions"
                Method = "POST"
                Body = $openAiCompletionsBody
                Raw = $false
            },
            @{
                Name = "/v1/responses"
                Uri = "$apiBase/v1/responses"
                Method = "POST"
                Body = $responsesBody
                Raw = $false
            },
            @{
                Name = "/v1beta/models/gemini-3-flash"
                Uri = "$apiBase/v1beta/models/gemini-3-flash"
                Method = "GET"
                Body = $null
                Raw = $false
            },
            @{
                Name = "/v1beta/models/gemini-3-flash:generateContent"
                Uri = "$apiBase/v1beta/models/gemini-3-flash`:generateContent"
                Method = "POST"
                Body = $geminiBody
                Raw = $false
            },
            @{
                Name = "/v1beta/models/gemini-3-flash:streamGenerateContent?alt=sse"
                Uri = "$apiBase/v1beta/models/gemini-3-flash`:streamGenerateContent?alt=sse"
                Method = "POST"
                Body = $geminiBody
                Raw = $true
            }
        )

        if (-not $NoClaudeProbes) {
            $messagesBody = @{
                model = "claude-opus-4-6-thinking"
                max_tokens = 64
                messages = @(
                    @{
                        role = "user"
                        content = "ping from live parity verify (messages)"
                    }
                )
            }
            $probeSpecs += @{
                Name = "/v1/messages"
                Uri = "$apiBase/v1/messages"
                Method = "POST"
                Body = $messagesBody
                Raw = $false
            }
        }

        $probeTotal = 0
        $probeOk = 0
        foreach ($probe in $probeSpecs) {
            $probeTotal++
            if ($probe.Raw) {
                $ok = Invoke-ParityProbe -Name $probe.Name -Uri $probe.Uri -ApiKey $apiKey -Method $probe.Method -Body $probe.Body -Raw
            } else {
                $ok = Invoke-ParityProbe -Name $probe.Name -Uri $probe.Uri -ApiKey $apiKey -Method $probe.Method -Body $probe.Body
            }
            if ($ok) { $probeOk++ }
        }
        Write-Host "Extended probes complete: $probeOk/$probeTotal succeeded."
    } else {
        Write-Host "Extended parity probes skipped."
    }

    if (Test-Path $OutGephyrPath) {
        Remove-Item $OutGephyrPath -Force
    }
    $logFile = Get-ChildItem "$env:USERPROFILE\.gephyr\logs\app.log*" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if ($logFile) {
        Write-Host "Using log file: $logFile"
        Write-GoogleOutboundRecordsFromLines -Lines (Get-Content $logFile) -Cutoff $cutoff -OutPath $OutGephyrPath
    } else {
        Write-Host "No app.log file found; will try in-memory job output."
    }

    if (-not (Test-Path $OutGephyrPath)) {
        $jobLines = Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue
        if ($jobLines) {
            Write-Host "Falling back to job output for google_outbound_headers extraction."
            Write-GoogleOutboundRecordsFromLines -Lines $jobLines -Cutoff $cutoff -OutPath $OutGephyrPath
        }
    }

    if (-not (Test-Path $OutGephyrPath)) {
        throw "No gephyr_google_outbound_headers records were found after cutoff."
    }

    $lineCount = (Get-Content $OutGephyrPath).Count
    Write-Host "Gephyr trace rows: $lineCount"
    Get-Content $OutGephyrPath | ForEach-Object { ($_ | ConvertFrom-Json).endpoint } |
        Sort-Object -Unique | ForEach-Object { Write-Host "  endpoint: $_" }

    if ($Scope -eq "Gephyr") {
        $scopedCount = Build-GephyrScopedKnownGood -SourcePath $KnownGoodSourcePath -GephyrTracePath $OutGephyrPath -OutPath $KnownGoodPath
        Write-Host "Gephyr-scoped known-good saved: $KnownGoodPath ($scopedCount lines)"
        if ($scopedCount -eq 0) {
            throw "Gephyr-scoped known-good is empty. Source: $KnownGoodSourcePath"
        }
    } elseif ($Scope -eq "Antigravity") {
        $scopedCount = Build-AntigravityScopedKnownGood -SourcePath $KnownGoodSourcePath -AllowlistPath $AntigravityAllowlistPath -OutPath $KnownGoodPath
        Write-Host "Antigravity-scoped known-good saved: $KnownGoodPath ($scopedCount lines)"
        if ($scopedCount -eq 0) {
            throw "Antigravity-scoped known-good is empty. Source: $KnownGoodSourcePath"
        }
    } else {
        Write-Host "Using raw known-good path for diff: $KnownGoodPath"
    }

    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/diff-google-traces.ps1 `
        -KnownGoodPath $KnownGoodPath `
        -GephyrPath $OutGephyrPath `
        -IgnoreConnectionHeader `
        -IgnoreDeviceHeaders | Out-Null

    $txt = "output/google_trace_diff_report.txt"
    if (Test-Path $txt) {
        Write-Host ""
        Write-Host "Diff report head:"
        Get-Content $txt -Head 80
    }
} finally {
    if ($job) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Stopped Gephyr job."
    }
}
