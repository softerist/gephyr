param(
    [int]$Port = 8879,
    [string]$KnownGoodPath = "output/known_good.jsonl",
    [string]$GephyrPath = "output/gephyr_google_outbound_headers.jsonl",
    [string]$MitmdumpPath = "",
    [string[]]$TargetHosts = @(),
    [string[]]$TargetSuffixes = @(),
    [switch]$CaptureAll,
    [switch]$CaptureNoise,
    [switch]$ManageSystemProxy,
    [switch]$KeepSystemProxy,
    [switch]$ManageWinHttpProxy,
    [switch]$KeepWinHttpProxy,
    [switch]$TrustCert,
    [switch]$SkipDiff,
    [switch]$RequireStream,
    [switch]$RequireStrictStream,
    [switch]$AllowMissingStream,
    [switch]$SelfTestProxy,
    [switch]$LaunchAntigravityProxied,
    [string]$AntigravityExe = "",
    [string]$NoProxy = "",
    [switch]$StopExistingAntigravity,
    [switch]$ManageAntigravityIdeProxy,
    [ValidateSet("override","on","off")]
    [string]$AntigravityIdeProxySupport = "override",
    [string]$AntigravitySettingsPath = "",
    [switch]$KeepAntigravityIdeProxy
    ,
    [string[]]$UserAgentContains = @(),
    [string[]]$UserAgentExcludeContains = @(),
    [switch]$TraceLsConnections,
    [string]$TraceLsProcessName = "language_server_windows_x64",
    [string]$TraceLsCsvPath = "",
    [int]$TraceLsPollIntervalMs = 500,
    [int]$AutoCaptureTimeoutSeconds = 0,
    [switch]$AutoStopOnRequirement
)

$ErrorActionPreference = "Stop"
$autoCaptureEnabled = ($AutoCaptureTimeoutSeconds -gt 0)
$captureRestoreHint = if ($autoCaptureEnabled) { "after capture completes." } else { "after you press Enter." }

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Resolve-ProjectPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $projectRoot $Path)
}

function Get-PortListeners {
    param([int]$Port)
    return Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
}

function Resolve-PortOwners {
    param([int]$Port)
    $listeners = Get-PortListeners -Port $Port
    if (-not $listeners) { return @() }

    $owners = @()
    $procIds = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
    foreach ($procId in $procIds) {
        try {
            $p = Get-Process -Id $procId -ErrorAction Stop
            $owners += [pscustomobject]@{
                pid = $procId
                name = $p.ProcessName
                path = $p.Path
            }
        } catch {
            $owners += [pscustomobject]@{
                pid = $procId
                name = "<unknown>"
                path = $null
            }
        }
    }
    return $owners
}

function Resolve-ProcessIdByName {
    param(
        [Parameter(Mandatory = $true)][string]$ProcessName,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -le $deadline) {
        $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc) {
            return $proc.Id
        }
        Start-Sleep -Milliseconds 500
    }
    return $null
}

function Start-ConnectionPollerJob {
    param(
        [int]$ProcId,
        [string]$OutCsv,
        [int]$PollIntervalMs
    )

    $script = {
        param($ProcId, $OutCsv, $PollIntervalMs)
        $ErrorActionPreference = "SilentlyContinue"

        "timestamp_utc,owning_process,local_address,local_port,remote_address,remote_port,state,applied_setting" | Out-File -FilePath $OutCsv -Encoding ascii
        while ($true) {
            $ts = (Get-Date).ToUniversalTime().ToString("o")
            Get-NetTCPConnection -OwningProcess $ProcId -State Established |
                Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting |
                ForEach-Object {
                    "$ts,$($_.OwningProcess),$($_.LocalAddress),$($_.LocalPort),$($_.RemoteAddress),$($_.RemotePort),$($_.State),$($_.AppliedSetting)"
                } | Out-File -FilePath $OutCsv -Append -Encoding ascii
            Start-Sleep -Milliseconds $PollIntervalMs
        }
    }

    return Start-Job -ScriptBlock $script -ArgumentList @($ProcId, $OutCsv, $PollIntervalMs)
}

function Resolve-Mitmdump {
    param([string]$OverridePath)

    if ($OverridePath) {
        if (Test-Path $OverridePath) {
            return (Resolve-Path $OverridePath).Path
        }
        throw "Mitmdump path not found: $OverridePath"
    }

    $cmd = Get-Command "mitmdump" -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        return $cmd.Source
    }

    $candidates = @()
    if ($env:APPDATA) {
        $pyRoot = Join-Path $env:APPDATA "Python"
        if (Test-Path $pyRoot) {
            $candidates += Get-ChildItem -Path $pyRoot -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName "Scripts\mitmdump.exe" }
        }
    }

    $candidates += @(
        (Join-Path $env:USERPROFILE "AppData\Roaming\Python\Python312\Scripts\mitmdump.exe"),
        (Join-Path $env:USERPROFILE "AppData\Roaming\Python\Python313\Scripts\mitmdump.exe"),
        (Join-Path $env:USERPROFILE "AppData\Roaming\Python\Python314\Scripts\mitmdump.exe")
    )

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "Could not find mitmdump.exe. Run: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/setup-mitmproxy.ps1"
}

$mitmdumpExe = Resolve-Mitmdump -OverridePath $MitmdumpPath

if (-not (Test-Path (Join-Path $projectRoot "output"))) {
    New-Item -ItemType Directory -Path (Join-Path $projectRoot "output") | Out-Null
}

$knownGoodAbs = Resolve-ProjectPath -Path $KnownGoodPath
$gephyrAbs = Resolve-ProjectPath -Path $GephyrPath
$knownGoodDir = Split-Path -Parent $knownGoodAbs
if ($knownGoodDir -and -not (Test-Path $knownGoodDir)) {
    New-Item -ItemType Directory -Path $knownGoodDir | Out-Null
}
$captureTempAbs = "$knownGoodAbs.tmp"
$diagAbs = Join-Path $projectRoot "output/known_good_capture_hosts.json"

if (Test-Path $captureTempAbs) { Remove-Item $captureTempAbs -Force }
if (Test-Path $diagAbs) {
    Remove-Item $diagAbs -Force
}

$addonPath = Join-Path $PSScriptRoot "mitm-google-capture.py"
if (-not (Test-Path $addonPath)) {
    throw "Missing addon script: $addonPath"
}

$mitmdumpArgs = @(
    "--listen-host", "127.0.0.1",
    "--listen-port", "$Port",
    "--set", "block_global=false",
    "-s", $addonPath
)

$logStamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$mitmdumpStderrLog = Join-Path $projectRoot ("output/mitmdump_stderr.{0}.log" -f $logStamp)
$mitmdumpStdoutLog = Join-Path $projectRoot ("output/mitmdump_stdout.{0}.log" -f $logStamp)

$ownersBefore = Resolve-PortOwners -Port $Port
if ($ownersBefore.Count -gt 0) {
    # Auto-clear only known stale proxy processes.
    $killable = @($ownersBefore | Where-Object { $_.name -in @("mitmdump", "python") })
    if ($killable.Count -eq $ownersBefore.Count) {
        foreach ($owner in $killable) {
            Write-Host "Stopping existing listener on ${Port}: PID=$($owner.pid) Name=$($owner.name)"
            Stop-Process -Id $owner.pid -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 250
    }

    $ownersAfter = Resolve-PortOwners -Port $Port
    if ($ownersAfter.Count -gt 0) {
        $ownerText = ($ownersAfter | ForEach-Object { "$($_.name) (PID=$($_.pid))" }) -join ", "
        throw "Port 127.0.0.1:$Port is already in use by: $ownerText. Stop that process or run with -Port <free_port>."
    }
}

Write-Host "Starting mitmdump on 127.0.0.1:$Port ..."
$env:GEPHYR_MITM_OUT = $captureTempAbs
$env:GEPHYR_MITM_DIAG_OUT = $diagAbs
$env:GEPHYR_MITM_CAPTURE_ALL = $null
$env:GEPHYR_MITM_CAPTURE_NOISE = $null
$env:GEPHYR_MITM_TARGET_HOSTS = $null
$env:GEPHYR_MITM_TARGET_SUFFIXES = $null
$env:GEPHYR_MITM_UA_CONTAINS = $null
$env:GEPHYR_MITM_UA_EXCLUDE_CONTAINS = $null

function Sanitize-UaToken {
    param([object]$Value)
    $s = ([string]$Value).Trim()
    # Strip wrapping quotes if caller passed them (common when copy/pasting CLI examples).
    $s = $s.Trim("'")
    $s = $s.Trim('"')
    return $s
}

function Sanitize-HostToken {
    param([object]$Value)
    $s = ([string]$Value).Trim()
    $s = $s.Trim("'")
    $s = $s.Trim('"')
    # Drop URL schemes/paths if caller pasted a URL.
    $s = ($s -replace '^(?i)https?://', '')
    $s = ($s -split '/')[0]
    return $s
}

function Sanitize-SuffixToken {
    param([object]$Value)
    $s = ([string]$Value).Trim()
    $s = $s.Trim("'")
    $s = $s.Trim('"')
    # Accept either "openai.com" or ".openai.com" for suffix matching.
    if ($s -and -not $s.StartsWith(".")) { $s = "." + $s }
    return $s
}

if ($TargetHosts -and $TargetHosts.Count -gt 0) {
    $san = @($TargetHosts | ForEach-Object { Sanitize-HostToken $_ } | Where-Object { $_ })
    if ($san.Count -gt 0) {
        $env:GEPHYR_MITM_TARGET_HOSTS = ($san -join ",")
    }
}
if ($TargetSuffixes -and $TargetSuffixes.Count -gt 0) {
    $san = @($TargetSuffixes | ForEach-Object { Sanitize-SuffixToken $_ } | Where-Object { $_ })
    if ($san.Count -gt 0) {
        $env:GEPHYR_MITM_TARGET_SUFFIXES = ($san -join ",")
    }
}

if ($CaptureAll) {
    $env:GEPHYR_MITM_CAPTURE_ALL = "1"
}
if ($CaptureNoise) {
    $env:GEPHYR_MITM_CAPTURE_NOISE = "1"
}

if ($UserAgentContains -and $UserAgentContains.Count -gt 0) {
    # mitm addon treats this as a case-insensitive substring allowlist
    $san = @($UserAgentContains | ForEach-Object { Sanitize-UaToken $_ } | Where-Object { $_ })
    $env:GEPHYR_MITM_UA_CONTAINS = ($san -join ",")
}
if ($UserAgentExcludeContains -and $UserAgentExcludeContains.Count -gt 0) {
    # mitm addon treats this as a case-insensitive substring denylist
    $san = @($UserAgentExcludeContains | ForEach-Object { Sanitize-UaToken $_ } | Where-Object { $_ })
    $env:GEPHYR_MITM_UA_EXCLUDE_CONTAINS = ($san -join ",")
}
$proc = Start-Process -FilePath $mitmdumpExe -ArgumentList $mitmdumpArgs -PassThru -NoNewWindow -RedirectStandardError $mitmdumpStderrLog -RedirectStandardOutput $mitmdumpStdoutLog

$ideProxyWasSet = $false
$ideSettingsAbs = $null
$ideSettingsOriginalRaw = $null
$ideSettingsOriginalExisted = $false

$systemProxyWasSet = $false
$systemProxyOriginal = $null
$systemProxyKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

$winHttpProxyWasSet = $false
$winHttpProxyOriginal = $null

$lsTraceJob = $null
$lsTracePid = $null
$lsTraceCsvAbs = $null

function Get-SystemProxySnapshot {
    param([string]$KeyPath)
    $obj = [ordered]@{
        exists = $false
        ProxyEnable = $null
        ProxyServer = $null
        ProxyOverride = $null
        AutoConfigURL = $null
    }
    if (-not (Test-Path $KeyPath)) { return $obj }
    $obj.exists = $true
    try {
        $p = Get-ItemProperty -Path $KeyPath -ErrorAction Stop
        $obj.ProxyEnable = $p.ProxyEnable
        $obj.ProxyServer = $p.ProxyServer
        $obj.ProxyOverride = $p.ProxyOverride
        $obj.AutoConfigURL = $p.AutoConfigURL
    } catch {}
    return $obj
}

function Get-WinHttpProxySnapshot {
    try {
        $raw = & netsh winhttp show proxy 2>$null
        if (-not $raw) {
            return [ordered]@{ raw = $null; direct = $true; proxy = $null; bypass = $null }
        }
        $text = ($raw | Out-String)
        $direct = $text -match "Direct access \\(no proxy server\\)"
        $proxy = $null
        $bypass = $null
        if (-not $direct) {
            if ($text -match "(?m)^\\s*Proxy Server\\(s\\)\\s*:\\s*(.+)\\s*$") { $proxy = $Matches[1].Trim() }
            if ($text -match "(?m)^\\s*Bypass List\\s*:\\s*(.+)\\s*$") { $bypass = $Matches[1].Trim() }
        }
        return [ordered]@{ raw = $text.TrimEnd(); direct = $direct; proxy = $proxy; bypass = $bypass }
    } catch {
        return [ordered]@{ raw = $null; direct = $true; proxy = $null; bypass = $null }
    }
}

function Set-WinHttpProxy {
    param(
        [string]$ProxyHostPort,
        [string]$BypassList
    )
    if ($BypassList) {
        & netsh winhttp set proxy "$ProxyHostPort" "$BypassList" | Out-Null
    } else {
        & netsh winhttp set proxy "$ProxyHostPort" | Out-Null
    }
}

function Restore-WinHttpProxy {
    param([object]$Snapshot)
    if (-not $Snapshot) { return }
    if ($Snapshot.direct) {
        & netsh winhttp reset proxy | Out-Null
        return
    }
    if ($Snapshot.proxy) {
        if ($Snapshot.bypass -and $Snapshot.bypass -ne "(none)") {
            & netsh winhttp set proxy "$($Snapshot.proxy)" "$($Snapshot.bypass)" | Out-Null
        } else {
            & netsh winhttp set proxy "$($Snapshot.proxy)" | Out-Null
        }
    } else {
        & netsh winhttp reset proxy | Out-Null
    }
}

function Set-SystemProxy {
    param(
        [string]$KeyPath,
        [string]$ProxyUrl,
        [string]$ProxyOverride
    )
    if (-not (Test-Path $KeyPath)) {
        New-Item -Path $KeyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $KeyPath -Name ProxyEnable -Value 1 -Type DWord | Out-Null
    Set-ItemProperty -Path $KeyPath -Name ProxyServer -Value $ProxyUrl -Type String | Out-Null
    if ($ProxyOverride) {
        Set-ItemProperty -Path $KeyPath -Name ProxyOverride -Value $ProxyOverride -Type String | Out-Null
    } else {
        Remove-ItemProperty -Path $KeyPath -Name ProxyOverride -ErrorAction SilentlyContinue
    }
}

function Restore-SystemProxy {
    param(
        [string]$KeyPath,
        [object]$Snapshot
    )
    if (-not $Snapshot) { return }
    if (-not (Test-Path $KeyPath)) {
        New-Item -Path $KeyPath -Force | Out-Null
    }
    if ($Snapshot.ProxyEnable -ne $null) {
        Set-ItemProperty -Path $KeyPath -Name ProxyEnable -Value $Snapshot.ProxyEnable -Type DWord | Out-Null
    } else {
        Remove-ItemProperty -Path $KeyPath -Name ProxyEnable -ErrorAction SilentlyContinue
    }
    foreach ($name in @("ProxyServer", "ProxyOverride", "AutoConfigURL")) {
        $val = $Snapshot.$name
        if ($null -ne $val -and [string]$val -ne "") {
            Set-ItemProperty -Path $KeyPath -Name $name -Value $val -Type String | Out-Null
        } else {
            Remove-ItemProperty -Path $KeyPath -Name $name -ErrorAction SilentlyContinue
        }
    }
}

function Get-LiveCaptureStatus {
    param([string]$CapturePath)

    $result = [ordered]@{
        total_records        = 0
        google_records       = 0
        generation_records   = 0
        stream_records       = 0
        cloudcode_records    = 0
        oauth2_records       = 0
        chatgpt_records      = 0
        chat_openai_records  = 0
        ab_chatgpt_records   = 0
        generation_endpoints = @()
    }

    if (-not (Test-Path $CapturePath)) {
        return [pscustomobject]$result
    }

    $generationEndpointMap = @{}
    $generationPattern = "streamGenerateContent|streamGenerateChat|:generateContent(\?|$)|:generateChat(\?|$)|:generateCode(\?|$)|:completeCode(\?|$)|:internalAtomicAgenticChat(\?|$)|:tabChat(\?|$)"
    $googlePattern = "(?i)^https?://[^/]*(googleapis\.com|google\.com)(?::\d+)?/"

    foreach ($line in (Get-Content -Path $CapturePath -ErrorAction SilentlyContinue)) {
        $trim = $line.Trim()
        if (-not $trim) { continue }
        $obj = $null
        try {
            $obj = $trim | ConvertFrom-Json
        } catch {
            continue
        }

        $endpoint = [string]$obj.endpoint
        if (-not $endpoint) {
            $endpoint = [string]$obj.url
        }
        if (-not $endpoint) { continue }

        $result.total_records++
        if ($endpoint -match $googlePattern) {
            $result.google_records++
        }
        $endpointHost = ""
        try {
            $endpointHost = ([System.Uri]$endpoint).Host.ToLowerInvariant()
        } catch {
            $endpointHost = ""
        }
        switch -Regex ($endpointHost) {
            "^(daily-)?cloudcode-pa\.googleapis\.com$" {
                $result.cloudcode_records++
                break
            }
            "^oauth2\.googleapis\.com$" {
                $result.oauth2_records++
                break
            }
            "^chatgpt\.com$" {
                $result.chatgpt_records++
                break
            }
            "^chat\.openai\.com$" {
                $result.chat_openai_records++
                break
            }
            "^ab\.chatgpt\.com$" {
                $result.ab_chatgpt_records++
                break
            }
        }
        if ($endpoint -match $generationPattern) {
            $result.generation_records++
            $generationEndpointMap[$endpoint] = $true
            if ($endpoint -match "streamGenerate(Content|Chat)") {
                $result.stream_records++
            }
        }
    }

    $result.generation_endpoints = @($generationEndpointMap.Keys | Sort-Object)
    return [pscustomobject]$result
}

function Wait-ForCaptureCompletion {
    param(
        [string]$CapturePath,
        [switch]$RequireStream,
        [switch]$RequireStrictStream,
        [int]$PollSeconds = 3,
        [int]$AutoCaptureTimeoutSeconds = 0,
        [switch]$AutoStopOnRequirement
    )

    $autoMode = ($AutoCaptureTimeoutSeconds -gt 0)
    $deadline = $null
    if ($autoMode) {
        $deadline = (Get-Date).AddSeconds($AutoCaptureTimeoutSeconds)
    }

    $supportsLiveMonitor = $false
    try {
        $supportsLiveMonitor = ($Host.Name -eq "ConsoleHost" -and -not [Console]::IsInputRedirected)
    } catch {
        $supportsLiveMonitor = $false
    }

    if (-not $supportsLiveMonitor -and -not $autoMode) {
        Read-Host "Press Enter when capture is complete"
        return
    }

    if ($autoMode) {
        Write-Host ("Auto capture mode enabled: timeout={0}s" -f $AutoCaptureTimeoutSeconds)
        if ($AutoStopOnRequirement) {
            Write-Host "  [live] Auto-stop when requirement is satisfied."
        } else {
            Write-Host "  [live] Auto-stop on timeout."
        }
    } else {
        Write-Host "Press Enter when capture is complete."
    }
    if ($RequireStrictStream) {
        Write-Host "  [live] Waiting for streaming generation endpoint..." -ForegroundColor DarkYellow
    } elseif ($RequireStream) {
        Write-Host "  [live] Waiting for generation endpoint (content/chat/code)..." -ForegroundColor DarkYellow
    } else {
        Write-Host "  [live] Monitoring capture progress (records/google/generation/stream)." -ForegroundColor DarkGray
    }

    $lastSummary = ""
    $lastRouteSummary = ""
    $satisfiedAnnounced = $false
    $routeHintAnnounced = $false

    while ($true) {
        if (-not $autoMode -and $supportsLiveMonitor) {
            try {
                while ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq [System.ConsoleKey]::Enter) {
                        Write-Host ""
                        return
                    }
                }
            } catch {
                Read-Host "Press Enter when capture is complete"
                return
            }
        }

        $status = Get-LiveCaptureStatus -CapturePath $CapturePath
        $summary = "records={0} google={1} generation={2} stream={3}" -f `
            $status.total_records, $status.google_records, $status.generation_records, $status.stream_records
        if ($summary -ne $lastSummary) {
            Write-Host "  [live] $summary"
            $lastSummary = $summary
        }
        $routeSummary = "cloudcode={0} oauth2={1} chatgpt={2} chat.openai={3} ab.chatgpt={4}" -f `
            $status.cloudcode_records, $status.oauth2_records, $status.chatgpt_records, $status.chat_openai_records, $status.ab_chatgpt_records
        if ($routeSummary -ne $lastRouteSummary) {
            Write-Host "  [live] routes: $routeSummary"
            $lastRouteSummary = $routeSummary
        }

        $isSatisfied = $false
        if ($RequireStrictStream) {
            $isSatisfied = $status.stream_records -gt 0
        } elseif ($RequireStream) {
            $isSatisfied = $status.generation_records -gt 0
        } else {
            # In non-stream mode, any captured target traffic is enough to satisfy capture.
            $isSatisfied = $status.google_records -gt 0
        }

        if ($isSatisfied -and -not $satisfiedAnnounced) {
            if ($RequireStrictStream -or $RequireStream) {
                $epText = if ($status.generation_endpoints.Count -gt 0) {
                    $status.generation_endpoints -join ", "
                } else {
                    "<unknown>"
                }
                Write-Host "  [live] Generation endpoint detected: $epText"
            } else {
                Write-Host "  [live] Target traffic detected."
            }
            Write-Host "  [live] Capture requirement satisfied; you can press Enter to stop." -ForegroundColor Green
            $satisfiedAnnounced = $true
        }
        if ($autoMode -and $AutoStopOnRequirement -and $isSatisfied) {
            Write-Host "  [live] Auto-stop: requirement satisfied." -ForegroundColor Green
            return
        }
        if (
            -not $routeHintAnnounced -and
            $status.generation_records -eq 0 -and
            ($status.chatgpt_records + $status.chat_openai_records + $status.ab_chatgpt_records) -gt $status.cloudcode_records
        ) {
            Write-Host "  [live] Hint: non-Google chat traffic currently dominates over cloudcode traffic." -ForegroundColor DarkYellow
            Write-Host "  [live] Hint: verify you are in the Google-backed chat surface before stopping." -ForegroundColor DarkYellow
            $routeHintAnnounced = $true
        }

        if ($autoMode -and $deadline -and (Get-Date) -ge $deadline) {
            Write-Host ("  [live] Auto-stop: timeout reached ({0}s)." -f $AutoCaptureTimeoutSeconds) -ForegroundColor DarkYellow
            return
        }

        Start-Sleep -Seconds $PollSeconds
    }
}

try {
    Start-Sleep -Milliseconds 700
    if ($proc.HasExited) {
        throw "mitmdump exited early. Check output/mitmdump_stdout.log and output/mitmdump_stderr.log."
    }

    $caCer = Join-Path $env:USERPROFILE ".mitmproxy\mitmproxy-ca-cert.cer"
    Write-Host ""
    Write-Host "Do this now (baseline client, not Gephyr):"
    Write-Host "1) Configure proxy in client/system to 127.0.0.1:$Port"
    Write-Host "2) Trust mitmproxy certificate:"
    if (Test-Path $caCer) {
        Write-Host "   certutil -addstore root `"$caCer`""
        if ($TrustCert) {
            try {
                & certutil -addstore root "$caCer" | Out-Null
                Write-Host "   Installed certificate into Root store."
            } catch {
                Write-Warning "Failed to install certificate automatically. Run as Administrator and execute: certutil -addstore root `"$caCer`""
            }
        }
    } else {
        Write-Host "   Open http://mitm.it from the proxied client and install cert"
    }
    if ($RequireStream -or $RequireStrictStream) {
        Write-Host "3) Trigger baseline flows: login/refresh + loadCodeAssist + fetch models + generate/stream"
        if ($RequireStrictStream) {
            Write-Host "   Strict mode: streamGenerateContent must be captured."
        }
    } else {
        Write-Host "3) Trigger baseline flows: login/refresh + loadCodeAssist + fetch models"
        Write-Host "   (If you want to capture chat/prompt traffic too, do a generate/stream action before stopping capture.)"
    }
    Write-Host ""
    Write-Host "Tip: if your baseline client ignores system proxy, launch Antigravity with explicit proxy env:"
    Write-Host "   pwsh -NoProfile -File scripts/start-antigravity-proxied.ps1 -Port $Port -StopExisting"
    Write-Host ""
    Write-Host "Sanity check (should succeed while capture is running):"
    Write-Host "   pwsh -NoProfile -Command `"Invoke-WebRequest -Uri 'https://oauth2.googleapis.com/tokeninfo?access_token=invalid' -Proxy 'http://127.0.0.1:$Port' -UseBasicParsing`""
    Write-Host ""
    if ($env:GEPHYR_MITM_TARGET_HOSTS -or $env:GEPHYR_MITM_TARGET_SUFFIXES) {
        Write-Host "Capture target hosts: $($env:GEPHYR_MITM_TARGET_HOSTS)"
        Write-Host "Capture target suffixes: $($env:GEPHYR_MITM_TARGET_SUFFIXES)"
        Write-Host ""
    }
    if ($env:GEPHYR_MITM_CAPTURE_ALL) {
        Write-Host "Capture mode: ALL HOSTS (wide open)"
        Write-Warning "capture_all=true: diagnostics 'target' counters include all captured hosts (not Google-only)."
        if ($env:GEPHYR_MITM_CAPTURE_NOISE) {
            Write-Host "Capture noise: enabled (includes tokeninfo, etc.)"
        }
        Write-Host ""
    }
    if ($env:GEPHYR_MITM_UA_CONTAINS) {
        Write-Host "Capture filter: user-agent must contain one of: $env:GEPHYR_MITM_UA_CONTAINS"
        Write-Host ""
    }
    if ($env:GEPHYR_MITM_UA_EXCLUDE_CONTAINS) {
        Write-Host "Capture filter: user-agent must NOT contain any of: $env:GEPHYR_MITM_UA_EXCLUDE_CONTAINS"
        Write-Host ""
    }

    if ($ManageAntigravityIdeProxy) {
	        try {
	            $proxyUrl = "http://127.0.0.1:$Port"
	            $setter = Join-Path $PSScriptRoot "set-antigravity-ide-proxy.ps1"
	            if (-not (Test-Path $setter)) {
	                Write-Warning "Missing IDE proxy setter script: $setter"
	            } else {
	                # Best-effort snapshot so we can restore exactly what was there before the capture.
	                try {
	                    if ($AntigravitySettingsPath) {
	                        $ideSettingsAbs = $AntigravitySettingsPath
	                    } elseif ($env:APPDATA) {
	                        $ideSettingsAbs = (Join-Path $env:APPDATA "Antigravity\User\settings.json")
	                    }
	                    if ($ideSettingsAbs -and (Test-Path $ideSettingsAbs)) {
	                        $ideSettingsOriginalExisted = $true
	                        $ideSettingsOriginalRaw = Get-Content -Path $ideSettingsAbs -Raw
	                    }
	                } catch {
	                    # Non-fatal: if snapshot fails, we can still clear the keys on exit.
	                }

	                $setParams = @{
	                    ProxyUrl = $proxyUrl
	                    ProxySupport = $AntigravityIdeProxySupport
	                }
	                if ($AntigravitySettingsPath) { $setParams.SettingsPath = $AntigravitySettingsPath }
	                & $setter @setParams | Out-Null
	                $ideProxyWasSet = $true
	                Write-Host "Antigravity IDE proxy configured for this capture: $proxyUrl"
	                if (-not $KeepAntigravityIdeProxy) {
	                    Write-Host ("It will be restored automatically {0}" -f $captureRestoreHint)
	                }
	            }
	        } catch {
	            Write-Warning "Failed to set Antigravity IDE proxy automatically: $($_.Exception.Message)"
	        }
        Write-Host ""
    }

    if ($ManageSystemProxy) {
        try {
            $proxyUrl = "http://127.0.0.1:$Port"
            $override = "localhost;127.0.0.1;<local>"
            $systemProxyOriginal = Get-SystemProxySnapshot -KeyPath $systemProxyKey
            Set-SystemProxy -KeyPath $systemProxyKey -ProxyUrl $proxyUrl -ProxyOverride $override
            $systemProxyWasSet = $true
            Write-Host "Set Windows system proxy for this capture:"
            Write-Host "  ProxyEnable=1"
            Write-Host "  ProxyServer=$proxyUrl"
            Write-Host "  ProxyOverride=$override"
            if (-not $KeepSystemProxy) {
                Write-Host ("It will be restored automatically {0}" -f $captureRestoreHint)
            }
        } catch {
            Write-Warning "Failed to set Windows system proxy automatically: $($_.Exception.Message)"
        }
        Write-Host ""
    }

    if ($ManageWinHttpProxy) {
        try {
            $proxyHostPort = "127.0.0.1:$Port"
            $bypass = "localhost;127.0.0.1;<local>"
            $winHttpProxyOriginal = Get-WinHttpProxySnapshot
            Set-WinHttpProxy -ProxyHostPort $proxyHostPort -BypassList $bypass
            $winHttpProxyWasSet = $true
            Write-Host "Set WinHTTP proxy for this capture:"
            Write-Host "  ProxyServer=$proxyHostPort"
            Write-Host "  BypassList=$bypass"
            if (-not $KeepWinHttpProxy) {
                Write-Host ("It will be restored automatically {0}" -f $captureRestoreHint)
            }
        } catch {
            Write-Warning "Failed to set WinHTTP proxy automatically: $($_.Exception.Message)"
        }
        Write-Host ""
    }

    if ($LaunchAntigravityProxied) {
        try {
            $launcher = Join-Path $PSScriptRoot "start-antigravity-proxied.ps1"
            if (-not (Test-Path $launcher)) {
                Write-Warning "Missing Antigravity launcher: $launcher"
            } else {
                # Use named-parameter splatting to avoid positional binding issues.
                $launchParams = @{
                    Port = $Port
                }
                if ($StopExistingAntigravity) { $launchParams.StopExisting = $true }
                if ($AntigravityExe) { $launchParams.AntigravityExe = $AntigravityExe }
                if ($NoProxy) { $launchParams.NoProxy = $NoProxy }
                & $launcher @launchParams | Out-Null
                Write-Host "Launched Antigravity proxied (best-effort)."
            }
        } catch {
            Write-Warning "Failed to launch Antigravity proxied automatically: $($_.Exception.Message)"
        }
        Write-Host ""
    }

    if ($SelfTestProxy) {
        try {
            $status = $null
            try {
                $resp = Invoke-WebRequest -Uri "https://oauth2.googleapis.com/tokeninfo?access_token=invalid" -Proxy "http://127.0.0.1:$Port" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                $status = $resp.StatusCode
            } catch {
                # Windows PowerShell throws on non-2xx; treat that as success if we got an HTTP response.
                $httpResp = $_.Exception.Response
                if ($httpResp -and $httpResp.StatusCode) {
                    $status = [int]$httpResp.StatusCode
                } else {
                    throw
                }
            }
            if ($null -ne $status) {
                Write-Host "Proxy self-test request sent (tokeninfo, HTTP $status)."
            } else {
                Write-Host "Proxy self-test request sent (tokeninfo)."
            }
        } catch {
            Write-Warning "Proxy self-test failed: $($_.Exception.Message)"
        }
        Write-Host ""
    }

    if ($TraceLsConnections) {
        try {
            if ($TraceLsPollIntervalMs -lt 100) {
                throw "TraceLsPollIntervalMs must be >= 100."
            }

            if ($TraceLsCsvPath) {
                $lsTraceCsvAbs = Resolve-ProjectPath -Path $TraceLsCsvPath
            } else {
                $lsTraceCsvAbs = Join-Path $projectRoot ("output/ls_during_capture.{0}.connections.csv" -f $TraceLsProcessName)
            }
            $lsTraceDir = Split-Path -Parent $lsTraceCsvAbs
            if ($lsTraceDir -and -not (Test-Path $lsTraceDir)) {
                New-Item -ItemType Directory -Path $lsTraceDir -Force | Out-Null
            }

            if (Test-Path $lsTraceCsvAbs) {
                Remove-Item $lsTraceCsvAbs -Force -ErrorAction SilentlyContinue
            }

            $lsTracePid = Resolve-ProcessIdByName -ProcessName $TraceLsProcessName -TimeoutSeconds 30
            if ($null -eq $lsTracePid) {
                throw "Could not find process '$TraceLsProcessName' to trace."
            }

            $lsTraceJob = Start-ConnectionPollerJob -ProcId $lsTracePid -OutCsv $lsTraceCsvAbs -PollIntervalMs $TraceLsPollIntervalMs
            Write-Host "LS connection tracing enabled for this capture:"
            Write-Host "  Process=$TraceLsProcessName PID=$lsTracePid"
            Write-Host "  CSV=$lsTraceCsvAbs"
        } catch {
            Write-Warning "Failed to start LS connection tracing: $($_.Exception.Message)"
        }
        Write-Host ""
    }

    Wait-ForCaptureCompletion `
        -CapturePath $captureTempAbs `
        -RequireStream:$RequireStream `
        -RequireStrictStream:$RequireStrictStream `
        -AutoCaptureTimeoutSeconds $AutoCaptureTimeoutSeconds `
        -AutoStopOnRequirement:$AutoStopOnRequirement
}
finally {
    $env:GEPHYR_MITM_OUT = $null
    $env:GEPHYR_MITM_DIAG_OUT = $null
    $env:GEPHYR_MITM_CAPTURE_ALL = $null
    $env:GEPHYR_MITM_CAPTURE_NOISE = $null
    $env:GEPHYR_MITM_TARGET_HOSTS = $null
    $env:GEPHYR_MITM_TARGET_SUFFIXES = $null
    $env:GEPHYR_MITM_UA_CONTAINS = $null
    $env:GEPHYR_MITM_UA_EXCLUDE_CONTAINS = $null
    if ($lsTraceJob) {
        try {
            Stop-Job $lsTraceJob -Force | Out-Null
        } catch {}
        try {
            Remove-Job $lsTraceJob -Force | Out-Null
        } catch {}
        Write-Host "Stopped LS connection tracer."
    }

    if ($TraceLsConnections -and $lsTraceCsvAbs -and (Test-Path $lsTraceCsvAbs)) {
        try {
            $traceRows = Import-Csv -Path $lsTraceCsvAbs
            $proxyRows = @($traceRows | Where-Object { $_.remote_address -eq "127.0.0.1" -and [int]$_.remote_port -eq $Port }).Count
            $public443Rows = @($traceRows | Where-Object { $_.remote_address -ne "127.0.0.1" -and [int]$_.remote_port -eq 443 }).Count
            Write-Host "LS trace saved: $lsTraceCsvAbs"
            Write-Host "LS trace summary: rows=$($traceRows.Count), proxy_127.0.0.1:$Port=$proxyRows, public_443=$public443Rows"
        } catch {
            Write-Warning "Failed to summarize LS trace CSV: $($_.Exception.Message)"
        }
    }

    if ($proc -and -not $proc.HasExited) {
        Write-Host "Stopping mitmdump ..."
        Stop-Process -Id $proc.Id
        Start-Sleep -Milliseconds 250
        if (-not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force
        }
    }

    if ($ideProxyWasSet -and -not $KeepAntigravityIdeProxy) {
	        try {
	            if ($ideSettingsAbs -and $ideSettingsOriginalExisted -and ($null -ne $ideSettingsOriginalRaw)) {
	                try {
	                    $restoreBackup = "{0}.gephyr-before-restore-{1}" -f $ideSettingsAbs, (Get-Date -Format "yyyyMMdd-HHmmss")
	                    if (Test-Path $ideSettingsAbs) {
	                        Copy-Item -Path $ideSettingsAbs -Destination $restoreBackup -Force
	                    }
	                    $ideSettingsOriginalRaw | Set-Content -Path $ideSettingsAbs -Encoding UTF8
	                    Write-Host "Restored Antigravity IDE proxy settings after capture."
	                    Write-Host "Backup: $restoreBackup"
	                } catch {
	                    throw
	                }
	            } else {
	                # Fall back to clearing proxy-related keys only, to preserve any new settings created during the capture.
	                $setter = Join-Path $PSScriptRoot "set-antigravity-ide-proxy.ps1"
	                if (Test-Path $setter) {
	                    $clearParams = @{
	                        Clear = $true
	                    }
	                    if ($AntigravitySettingsPath) { $clearParams.SettingsPath = $AntigravitySettingsPath }
	                    & $setter @clearParams | Out-Null
	                    Write-Host "Cleared Antigravity IDE proxy settings after capture."
	                }
	            }
	        } catch {
	            Write-Warning "Failed to clear Antigravity IDE proxy settings: $($_.Exception.Message)"
	        }
	    }

    if ($systemProxyWasSet -and -not $KeepSystemProxy) {
        try {
            $backupPath = Join-Path $projectRoot ("output\\system_proxy.before_restore.{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
            try {
                ($systemProxyOriginal | ConvertTo-Json -Depth 10) | Set-Content -Path $backupPath -Encoding UTF8
                Write-Host "Saved system proxy snapshot: $backupPath"
            } catch {}
            Restore-SystemProxy -KeyPath $systemProxyKey -Snapshot $systemProxyOriginal
            Write-Host "Restored Windows system proxy settings after capture."
        } catch {
            Write-Warning "Failed to restore Windows system proxy settings: $($_.Exception.Message)"
        }
    }

    if ($winHttpProxyWasSet -and -not $KeepWinHttpProxy) {
        try {
            Restore-WinHttpProxy -Snapshot $winHttpProxyOriginal
            Write-Host "Restored WinHTTP proxy settings after capture."
        } catch {
            Write-Warning "Failed to restore WinHTTP proxy settings: $($_.Exception.Message)"
        }
    }
}

if (-not (Test-Path $captureTempAbs)) {
	$diagSummary = $null
	$diagObj = $null
	if (Test-Path $diagAbs) {
		try {
			$diagObj = Get-Content $diagAbs -Raw | ConvertFrom-Json
			$top = @($diagObj.top_hosts | Select-Object -First 10 | ForEach-Object { "$($_.host) ($($_.count))" })
			$topUas = @($diagObj.top_user_agents | Select-Object -First 8 | ForEach-Object { "$($_.user_agent) ($($_.count))" })
			$topDroppedUas = @($diagObj.top_dropped_user_agents | Select-Object -First 8 | ForEach-Object { "$($_.user_agent) ($($_.count))" })
			$diagSummary = @(
				"Capture diagnostics: total requests seen=$($diagObj.total_requests_seen), target requests seen=$($diagObj.total_target_requests_seen)"
				$(
					if ($diagObj.capture_all -eq $true) {
						"NOTE: capture_all=true; 'target requests/hosts' include all captured hosts."
					} else {
						$null
					}
				)
				"Top observed hosts: $($top -join ', ')"
				"Top user-agents: $($topUas -join ' | ')"
				$(
					if ($topDroppedUas.Count -gt 0) {
						"Top dropped user-agents (filtered out): $($topDroppedUas -join ' | ')"
					} else {
						$null
					}
				)
				"Expected target hosts/suffixes: $((@($diagObj.target_hosts) + @($diagObj.target_suffixes)) -join ', ')"
				"Hints:"
				"  - If total requests seen=0: nothing used the proxy (or traffic bypassed via direct connections)."
				"  - If total>0 but target=0: your UA filters may have excluded all target traffic, or TLS isn't being decrypted."
				"  - Prefer launching Antigravity via scripts/start-antigravity-proxied.ps1 to force proxy env vars."
			) -join "`n"
		} catch {}
	}

    if (Test-Path $mitmdumpStderrLog) {
        $stderrContent = Get-Content $mitmdumpStderrLog -Raw
        if ($stderrContent) {
            Write-Host ""
            Write-Host "=== mitmdump stderr ===" -ForegroundColor Yellow
            Write-Host $stderrContent -ForegroundColor Red
            Write-Host "=======================" -ForegroundColor Yellow
        }
    }
    if (Test-Path $mitmdumpStdoutLog) {
        $stdoutContent = Get-Content $mitmdumpStdoutLog -Raw
        if ($stdoutContent) {
            Write-Host ""
            Write-Host "=== mitmdump stdout ===" -ForegroundColor Yellow
            Write-Host $stdoutContent -ForegroundColor Gray
            Write-Host "=======================" -ForegroundColor Yellow
        }
    }

	$message = @"

  The capture ran, but no known-good trace was produced.
  (Expected output: $knownGoodAbs)

"@
	if ($diagObj -and $diagObj.total_requests_seen -gt 0 -and $diagObj.total_target_requests_seen -eq 0) {
		# This commonly happens when UA allow/deny filters are configured and don't match the client being exercised.
		$message += @"
  We saw traffic through the proxy, but none matched the target filters.

  How to fix this:
    - Check 'Top dropped user-agents' above and adjust -UserAgentContains / -UserAgentExcludeContains.
    - Make sure you exercised the intended baseline client while the proxy was running.

"@
	} else {
		$message += @"
  No requests to Google APIs reached the proxy at all.

  How to fix this:
    - Confirm the baseline client is configured to use proxy 127.0.0.1:$Port.
    - Ensure the mitmproxy CA certificate is trusted.
    - Try launching via: scripts/start-antigravity-proxied.ps1 -Port $Port

"@
	}
	if ($diagSummary) {
		$message += "`n$diagSummary"
	}
	throw $message
}

$lineCount = (Get-Content -Path $captureTempAbs | Measure-Object -Line).Lines
if ($lineCount -eq 0) {
    Remove-Item $captureTempAbs -Force -ErrorAction SilentlyContinue
    throw @"

  The capture file was created but is empty (0 lines).

  This means the proxy was running, but no Google API requests were recorded.

  How to fix this:
    - Confirm the baseline client is actually routing through 127.0.0.1:$Port.
    - Make sure TLS decryption is working (is the mitmproxy CA trusted?).
    - Try launching via: scripts/start-antigravity-proxied.ps1 -Port $Port
"@
}

if ($RequireStream -or $RequireStrictStream) {
    $capturedEndpoints = @(
        Get-Content -Path $captureTempAbs | ForEach-Object {
            try {
                (ConvertFrom-Json $_).endpoint
            } catch {
                $null
            }
        } | Where-Object { $_ }
    )
    $generationEndpoints = @(
        $capturedEndpoints | Where-Object {
            $_ -match "streamGenerateContent|streamGenerateChat|:generateContent(\?|$)|:generateChat(\?|$)|:generateCode(\?|$)|:completeCode(\?|$)|:internalAtomicAgenticChat(\?|$)|:tabChat(\?|$)"
        } | Sort-Object -Unique
    )
    $streamEndpoints = @($generationEndpoints | Where-Object { $_ -match "streamGenerate(Content|Chat)" })
    $hasRequiredGeneration = if ($RequireStrictStream) {
        $streamEndpoints.Count -gt 0
    } else {
        $generationEndpoints.Count -gt 0
    }

    if (-not $hasRequiredGeneration) {
        $diagSummary = $null
        $nonGoogleProviderHint = $null
        if (Test-Path $diagAbs) {
            try {
                $diag = Get-Content $diagAbs -Raw | ConvertFrom-Json
                $top = @($diag.top_hosts | Select-Object -First 10 | ForEach-Object { "$($_.host) ($($_.count))" })
                $topTargets = @($diag.top_target_hosts | Select-Object -First 10 | ForEach-Object { "$($_.host) ($($_.count))" })
                $topTargetUas = @($diag.top_target_user_agents | Select-Object -First 6 | ForEach-Object { "$($_.user_agent) ($($_.count))" })
                $topHostNames = @($diag.top_hosts | ForEach-Object { "$($_.host)" })
                $nonGoogleProviderHosts = @(
                    $topHostNames | Where-Object { $_ -match "chatgpt\.com|chat\.openai\.com|ab\.chatgpt\.com" } | Sort-Object -Unique
                )
                if ($nonGoogleProviderHosts.Count -gt 0) {
                    $nonGoogleProviderHint = @(
                        "Detected likely non-Google chat traffic during capture: $($nonGoogleProviderHosts -join ', ')."
                        "This usually means prompt activity happened in a non-Google chat surface (for example Open Agent Manager/Codex chat),"
                        "while Google Code Assist only emitted bootstrap calls (loadCodeAssist/fetchUserInfo/fetchAvailableModels)."
                        "Use the Google Code Assist chat/prompt surface and wait for streamed output before stopping capture."
                    ) -join "`n"
                }
                $diagSummary = @(
                    "Capture diagnostics: total requests seen=$($diag.total_requests_seen), target requests seen=$($diag.total_target_requests_seen)"
                    $(
                        if ($diag.capture_all -eq $true) {
                            "NOTE: capture_all=true; 'target requests/hosts' include all captured hosts."
                        } else {
                            $null
                        }
                    )
                    "Top observed hosts: $($top -join ', ')"
                    "Top target hosts: $($topTargets -join ', ')"
                    "Top target user-agents: $($topTargetUas -join ' | ')"
                ) -join "`n"
            } catch {}
        }

        $failedPath = "{0}.missing-stream-{1}.jsonl" -f $knownGoodAbs, (Get-Date -Format "yyyyMMdd-HHmmss")
        try {
            Move-Item -Path $captureTempAbs -Destination $failedPath -Force
        } catch {
            # If move fails for any reason, keep the temp file in place so data isn't lost.
            $failedPath = $captureTempAbs
        }

        $missingStreamMessage = @"

  Almost there! The capture ran fine, but we didn't see a generation request come through.

$(
    if ($RequireStrictStream) {
@"
  What's missing:
    We need at least one `streamGenerateContent` call (strict mode is on).
"@
    } else {
@"
  What's missing:
    We need at least one of these endpoints:
      - streamGenerateContent
      - streamGenerateChat
      - generateContent
      - generateChat
      - generateCode
      - completeCode
      - internalAtomicAgenticChat
      - tabChat
"@
    }
)

  Your captured data was saved here (not lost!):
    $failedPath
$(
    if ($diagSummary) {
        "`n$diagSummary"
    } else {
        ""
    }
)
$(
    if ($nonGoogleProviderHint) {
        "`n$nonGoogleProviderHint"
    } else {
        ""
    }
)

  How to fix this:
    1. Re-run this capture script.
    2. While the proxy is active, use the Google Code Assist prompt/chat surface
       (not Open Agent Manager/Codex chat) and ask it something.
    3. Wait until you see tokens streaming for a few seconds, then press Enter to stop.

  Still not working?
    - Your generation may have gone to a non-Google provider. Check 'Top observed hosts' above.
    - Make sure the baseline client is actually routing through the proxy (127.0.0.1:$Port).
"@
        if ($AllowMissingStream) {
            Write-Warning $missingStreamMessage
            if (Test-Path $knownGoodAbs) {
                $backupPath = "{0}.bak-{1}" -f $knownGoodAbs, (Get-Date -Format "yyyyMMdd-HHmmss")
                Move-Item -Path $knownGoodAbs -Destination $backupPath -Force
                Write-Host "Backed up previous known-good trace to: $backupPath"
            }
            Copy-Item -Path $failedPath -Destination $knownGoodAbs -Force
            Write-Warning "AllowMissingStream enabled: proceeding with baseline lacking generation endpoints at $knownGoodAbs"
            if ($SkipDiff) {
                return
            }
            Write-Host "Running diff against Gephyr capture ..."
            & "$PSScriptRoot\diff-google-traces.ps1" -GephyrPath $gephyrAbs -KnownGoodPath $knownGoodAbs
            Write-Host "Done. See:"
            Write-Host "  output/google_trace_diff_report.txt"
            Write-Host "  output/google_trace_diff_report.json"
            return
        }
        throw $missingStreamMessage
    } else {
        if ((-not $RequireStrictStream) -and $streamEndpoints.Count -eq 0) {
            Write-Host "RequireStream satisfied by non-stream generation endpoint(s): $($generationEndpoints -join ', ')"
        }
    }
}

if (Test-Path $knownGoodAbs) {
    $backupPath = "{0}.bak-{1}" -f $knownGoodAbs, (Get-Date -Format "yyyyMMdd-HHmmss")
    Move-Item -Path $knownGoodAbs -Destination $backupPath -Force
    Write-Host "Backed up previous known-good trace to: $backupPath"
}
Move-Item -Path $captureTempAbs -Destination $knownGoodAbs -Force

Write-Host "Known-good trace saved: $knownGoodAbs ($lineCount lines)"

if (Test-Path $diagAbs) {
    try {
        $diag = Get-Content $diagAbs -Raw | ConvertFrom-Json
        if ($diag.capture_all -eq $true) {
            Write-Warning "capture_all=true in this run. 'target' stats below include non-Google hosts."
        }
        if ($diag -and $diag.top_target_user_agents) {
            $top = @($diag.top_target_user_agents | Select-Object -First 6 | ForEach-Object { "$($_.user_agent) ($($_.count))" })
            if ($top.Count -gt 0) {
                Write-Host "Top target user-agents: $($top -join ' | ')"
            }
        }
    } catch {}
}

if (-not $SkipDiff) {
    if (-not (Test-Path $gephyrAbs)) {
        throw "Gephyr capture JSONL missing: $gephyrAbs"
    }
    Write-Host "Running diff against Gephyr capture ..."
    & "$PSScriptRoot\diff-google-traces.ps1" -GephyrPath $gephyrAbs -KnownGoodPath $knownGoodAbs
    Write-Host "Done. See:"
    Write-Host "  output/google_trace_diff_report.txt"
    Write-Host "  output/google_trace_diff_report.json"
}
