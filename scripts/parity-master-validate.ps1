param(
    [string]$KnownGoodPath = "output/known_good.discovery.jsonl",
    [string]$OutGephyrPath = "output/gephyr_google_outbound_headers.latest.jsonl",
    [int]$StartupTimeoutSeconds = 90,
    [string]$AllowlistPath = "scripts/allowlists/antigravity_google_endpoints_default_chat.txt",
    [switch]$RequireOAuthRelink,
    [switch]$AllowMimicTokenRefresh,
    [switch]$IncludeChatProbe,
    [switch]$IncludeAuthEventProbes,
    [switch]$IncludeExtendedFlow,
    [switch]$RefreshInclusive,
    [switch]$AllowMissingAllowlistEndpoints,
    [switch]$SkipAllowlistValidation,
    [switch]$SkipRepoGate,
    [switch]$SkipBaselineGate,
    [switch]$SkipMismatchContract,
    [switch]$PruneOutput,
    [switch]$NoAutoCaptureKnownGood,
    [switch]$SkipLsSniPreflight,
    [int]$KnownGoodCapturePort = 8891,
    [string]$KnownGoodAntigravityExe = "",
    [switch]$KnownGoodCaptureRequireStream,
    [string]$BaselineGephyrPath = "parity/baselines/redacted/windows/default/gephyr.reference.jsonl",
    [string]$BaselineKnownGoodPath = "parity/baselines/redacted/windows/default/known_good.default.jsonl",
    [string]$OutStatusJson = "output/parity/master_validation.status.json",
    [switch]$Json
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $projectRoot

function As-Array {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
        return @($Value)
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return @($Value)
    }
    return @($Value)
}

function Try-LoadJson {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try {
        return (Get-Content $Path -Raw | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Args = @(),
        [switch]$SuppressOutput
    )
    $result = [ordered]@{
        exit_code = 1
        ok = $false
    }
    try {
        if ($SuppressOutput) {
            & $Exe @Args *> $null
        } else {
            & $Exe @Args
        }
        $result.exit_code = $LASTEXITCODE
        $result.ok = ($LASTEXITCODE -eq 0)
    } catch {
        $result.exit_code = 1
        $result.ok = $false
    }
    return [pscustomobject]$result
}

function Exit-Gracefully {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [int]$Code = 1
    )
    Write-Host $Message -ForegroundColor Red
    exit $Code
}

function Remove-IfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
    }
}

function Get-LatestFileByPattern {
    param([string]$Pattern)
    $items = @(Get-ChildItem -Path $Pattern -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending)
    if ($items.Count -gt 0) {
        return $items[0].FullName
    }
    return $null
}

function Resolve-PathSafe {
    param([string]$Path)
    try {
        $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        if ($resolved) { return $resolved.Path }
    } catch {}
    return $null
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

function Prune-OutputArtifacts {
    param(
        [string]$KnownGoodPathToKeep,
        [string]$OutGephyrPathToKeep,
        [string]$DiffJsonPathToKeep,
        [string]$DiffTxtPathToKeep,
        [string]$AllowlistJsonPathToKeep,
        [string]$AllowlistTxtPathToKeep,
        [string]$StatusJsonPathToKeep,
        [string]$BaselineGateOutToKeep,
        [string]$MismatchGateOutToKeep
    )

    $keep = @(
        (Resolve-PathSafe -Path $KnownGoodPathToKeep),
        (Resolve-PathSafe -Path $OutGephyrPathToKeep),
        (Resolve-PathSafe -Path $DiffJsonPathToKeep),
        (Resolve-PathSafe -Path $DiffTxtPathToKeep),
        (Resolve-PathSafe -Path $AllowlistJsonPathToKeep),
        (Resolve-PathSafe -Path $AllowlistTxtPathToKeep),
        (Resolve-PathSafe -Path $StatusJsonPathToKeep),
        (Resolve-PathSafe -Path $BaselineGateOutToKeep),
        (Resolve-PathSafe -Path $MismatchGateOutToKeep)
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $patterns = @(
        "output\*.missing-stream-*.jsonl",
        "output\*.bak-*",
        "output\mitmdump_stderr*.log",
        "output\mitmdump_stdout*.log",
        "output\system_proxy.before_restore.*.json",
        "output\*.pktmon.etl",
        "output\*.pktmon.pcapng",
        "output\*.connections.csv",
        "output\ls_*.csv",
        "output\ls_*.txt",
        "output\ls_*.json",
        "output\known_good_capture_hosts.json",
        "output\known_good.all.live.jsonl",
        "output\known_good.discovery.scoped.jsonl",
        "output\known_good.live.jsonl",
        "output\known_good.source_probe.jsonl",
        "output\parity\raw\*.jsonl",
        "output\parity\redacted\*.jsonl",
        "output\parity\ci\*.json",
        "output\parity\ci\*.jsonl",
        "output\parity\source-audit-smoke.json",
        "output\parity\official\**\*.json",
        "output\parity\official\**\*.txt",
        "output\parity\official\**\*.jsonl",
        "output\parity\official\**\*.csv"
    )

    $deleted = 0
    foreach ($pattern in $patterns) {
        foreach ($file in (Get-ChildItem -Path $pattern -File -Recurse -ErrorAction SilentlyContinue)) {
            if ($keep -contains $file.FullName) { continue }
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
            $deleted++
        }
    }

    foreach ($dir in @(
        "output/parity/raw",
        "output/parity/redacted",
        "output/parity/official",
        "output/parity/official-smoke",
        "output/parity/official-smoke-strict",
        "output/parity/official-test",
        "output/parity/refresh-smoke",
        "output/parity/refresh-metadata-smoke"
    )) {
        if (Test-Path $dir) {
            foreach ($item in (Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue)) {
                if ($keep -contains $item.FullName) { continue }
                Remove-Item -Path $item.FullName -Force -ErrorAction SilentlyContinue
                $deleted++
            }
        }
    }

    return $deleted
}

function Get-LatestRunningAntigravityProcess {
    try {
        return (
            Get-CimInstance Win32_Process -Filter "Name='Antigravity.exe'" -ErrorAction SilentlyContinue |
                Sort-Object CreationDate -Descending |
                Select-Object -First 1
        )
    } catch {
        return $null
    }
}

function Resolve-AntigravityExePath {
    param(
        [string]$PreferredPath,
        $RunningProcess
    )

    if ($PreferredPath) {
        if (Test-Path $PreferredPath) {
            return [pscustomobject]@{
                path = (Resolve-Path $PreferredPath).Path
                source = "explicit"
            }
        }
        throw "Provided Antigravity executable path does not exist: $PreferredPath"
    }

    if ($RunningProcess -and $RunningProcess.ExecutablePath -and (Test-Path $RunningProcess.ExecutablePath)) {
        return [pscustomobject]@{
            path = (Resolve-Path $RunningProcess.ExecutablePath).Path
            source = "running_process"
        }
    }

    $pf86 = ${env:ProgramFiles(x86)}
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Antigravity\Antigravity.exe"),
        (Join-Path $env:ProgramFiles "Antigravity\Antigravity.exe"),
        (if ($pf86) { Join-Path $pf86 "Antigravity\Antigravity.exe" } else { $null })
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return [pscustomobject]@{
                path = (Resolve-Path $candidate).Path
                source = "default_install_path"
            }
        }
    }

    return [pscustomobject]@{
        path = $null
        source = "not_found"
    }
}

function Resolve-MitmdumpForPreflight {
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
    return $null
}

function Resolve-TsharkForPreflight {
    $cmd = Get-Command "tshark" -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        return $cmd.Source
    }
    $candidates = @(
        (Join-Path $env:ProgramFiles "Wireshark\tshark.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Wireshark\tshark.exe")
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) {
            return (Resolve-Path $c).Path
        }
    }
    return $null
}

function Test-IsAdminForPreflight {
    try {
        $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Invoke-NonAdminLsProxyPreflight {
    param(
        [int]$Port,
        [int]$TimeoutSeconds = 10,
        [int]$PollIntervalMs = 500
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $proxyMatches = 0
    $public443Observed = 0
    $lastPid = $null

    while ((Get-Date) -lt $deadline) {
        $ls = Get-Process -Name "language_server_windows_x64" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ls) {
            $lastPid = $ls.Id
            $rows = @(Get-NetTCPConnection -OwningProcess $ls.Id -State Established -ErrorAction SilentlyContinue)
            if ($rows.Count -gt 0) {
                $proxyMatches += @(
                    $rows | Where-Object {
                        $_.RemoteAddress -eq "127.0.0.1" -and [int]$_.RemotePort -eq $Port
                    }
                ).Count
                $public443Observed += @(
                    $rows | Where-Object {
                        $_.RemoteAddress -ne "127.0.0.1" -and [int]$_.RemotePort -eq 443
                    }
                ).Count
                if ($proxyMatches -gt 0) {
                    break
                }
            }
        }
        Start-Sleep -Milliseconds $PollIntervalMs
    }

    $outDir = "output/parity/official"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $reportPath = Join-Path $outDir "preflight.ls_proxy_route.non_admin.json"
    $report = [ordered]@{
        schema_version = "gephyr_ls_sni_preflight_non_admin_v1"
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        capture_port = $Port
        ls_pid = $lastPid
        proxy_matches_127_0_0_1_port = $proxyMatches
        public_443_observed = $public443Observed
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $reportPath -Encoding UTF8

    if ($proxyMatches -gt 0) {
        Write-Host "  preflight(degraded): LS proxy route observed on 127.0.0.1:$Port"
        return [pscustomobject]@{
            mode = "degraded_non_admin_proxy_route"
            report_path = $reportPath
            ls_rows = $proxyMatches
        }
    }

    Write-Warning "LS proxy-route evidence was not observed in non-admin preflight window."
    Write-Warning "Continue with capture, but run as Administrator for strict pktmon+tshark attribution."
    return [pscustomobject]@{
        mode = "degraded_non_admin_no_proxy_evidence"
        report_path = $reportPath
        ls_rows = 0
    }
}

function Write-NonAdminPreflightNotice {
    param([int]$Port)

    Write-Host ""
    Write-Host "Parity Preflight (Non-Admin Mode)" -ForegroundColor Yellow
    Write-Host "----------------------------------" -ForegroundColor Yellow
    Write-Host "Strict LS attribution (pktmon + tshark) requires an elevated PowerShell session." -ForegroundColor Yellow
    Write-Host "This run continues in degraded mode using proxy-route checks only." -ForegroundColor Yellow
    Write-Host ("Degraded check target: language_server_windows_x64 -> 127.0.0.1:{0}" -f $Port) -ForegroundColor Yellow
    Write-Host ""
    Write-Host "For strict mode:" -ForegroundColor Yellow
    Write-Host "1. Open PowerShell as Administrator" -ForegroundColor Yellow
    Write-Host ("2. cd {0}" -f $projectRoot) -ForegroundColor Yellow
    Write-Host "3. .\console.ps1 parity-master" -ForegroundColor Yellow
    Write-Host ""
}
function Invoke-LsSniPreflight {
    param(
        [switch]$Skip
    )

    if ($Skip) {
        Write-Warning "Skipping LS SNI preflight by request (-SkipLsSniPreflight)."
        return [pscustomobject]@{
            mode = "skipped"
            report_path = ""
            ls_rows = 0
        }
    }

    $tsharkPath = Resolve-TsharkForPreflight
    if (-not $tsharkPath) {
        throw "Official capture prerequisite missing: tshark.exe. Install Wireshark (with tshark) and ensure it is in PATH."
    }
    $tsharkProbe = Invoke-External -Exe $tsharkPath -Args @("-v") -SuppressOutput
    if (-not $tsharkProbe.ok) {
        throw "tshark preflight failed (exit=$($tsharkProbe.exit_code)). Verify Wireshark CLI installation."
    }
    Write-Host "  preflight: tshark found -> $tsharkPath"

    $traceScript = Join-Path $PSScriptRoot "trace-antigravity-chat-network.ps1"
    $attributeScript = Join-Path $PSScriptRoot "attribute-ls-sni.ps1"
    if (-not (Test-Path $traceScript)) {
        throw "LS SNI preflight script missing: $traceScript"
    }
    if (-not (Test-Path $attributeScript)) {
        throw "LS SNI attribution script missing: $attributeScript"
    }

    if (-not (Test-IsAdminForPreflight)) {
        Write-NonAdminPreflightNotice -Port $KnownGoodCapturePort
        return Invoke-NonAdminLsProxyPreflight -Port $KnownGoodCapturePort
    }

    $traceBase = "output/parity/official/preflight.ls_sni_probe"
    $attrBase = "output/parity/official/preflight.ls_sni_attribution"
    $traceArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $traceScript,
        "-OutBase", $traceBase,
        "-ProcessName", "language_server_windows_x64",
        "-DurationSeconds", "6"
    )
    Write-Host "Running LS SNI preflight trace (6s) ..."
    $traceRes = Invoke-External -Exe "powershell" -Args $traceArgs
    if (-not $traceRes.ok) {
        throw "LS SNI preflight trace failed (exit=$($traceRes.exit_code))."
    }

    $pcapPath = "$traceBase.pktmon.pcapng"
    $csvPath = "$traceBase.language_server_windows_x64.connections.csv"
    $attrArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $attributeScript,
        "-PcapPath", $pcapPath,
        "-ConnectionsCsvPath", $csvPath,
        "-OutBase", $attrBase,
        "-Top", "20"
    )
    Write-Host "Running LS SNI preflight attribution ..."
    $attrRes = Invoke-External -Exe "powershell" -Args $attrArgs
    if (-not $attrRes.ok) {
        throw "LS SNI preflight attribution failed (exit=$($attrRes.exit_code))."
    }

    $attrJsonPath = "$attrBase.json"
    $attrJson = Try-LoadJson -Path $attrJsonPath
    if ($null -eq $attrJson) {
        throw "LS SNI preflight attribution report missing or invalid: $attrJsonPath"
    }

    $lsRows = 0
    try { $lsRows = [int]$attrJson.totals.ls_connection_rows_scoped } catch {}
    if ($lsRows -le 0) {
        Write-Warning "LS SNI preflight captured no scoped LS :443 rows in 6s. Continue if IDE is idle; run parity-master during active LS traffic for stronger evidence."
    } else {
        Write-Host "  preflight: LS scoped :443 rows observed -> $lsRows"
    }

    return [pscustomobject]@{
        mode = "trace_attribute"
        report_path = $attrJsonPath
        ls_rows = $lsRows
    }
}

function Assert-OfficialCapturePrerequisites {
    $mitmdumpPath = Resolve-MitmdumpForPreflight
    if (-not $mitmdumpPath) {
        throw "Official capture prerequisite missing: mitmdump.exe. Install with: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/setup-mitmproxy.ps1"
    }
    Write-Host "  preflight: mitmdump found -> $mitmdumpPath"

    $caCertPath = Join-Path $env:USERPROFILE ".mitmproxy\mitmproxy-ca-cert.cer"
    if (Test-Path $caCertPath) {
        Write-Host "  preflight: mitm CA cert found -> $caCertPath"
    } else {
        Write-Warning "mitm CA cert not found at $caCertPath. If TLS capture fails, run scripts/setup-mitmproxy.ps1 first."
    }
}

function Build-KnownGoodCaptureFailureMessage {
    param(
        [int]$ExitCode,
        [string]$TargetKnownGoodPath,
        [int]$Port,
        [switch]$RequireStream,
        [string]$CaptureErrorMessage
    )

    $missingStreamPath = Get-LatestFileByPattern -Pattern ("{0}.missing-stream-*.jsonl" -f $TargetKnownGoodPath)
    $stderrPath = Get-LatestFileByPattern -Pattern "output/mitmdump_stderr*.log"
    $stdoutPath = Get-LatestFileByPattern -Pattern "output/mitmdump_stdout*.log"

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("")
    $lines.Add("Auto Official Capture Failed")
    $lines.Add("============================")
    $lines.Add(("Exit code: {0}" -f $ExitCode))
    $lines.Add(("Known-good target: {0}" -f $TargetKnownGoodPath))
    $lines.Add("")
    $lines.Add("Likely Cause")
    $lines.Add("------------")
    if ($missingStreamPath) {
        $lines.Add("- Capture ran, but generation/stream endpoint was not observed from Google chat.")
        $lines.Add(("- Missing-stream artifact: {0}" -f $missingStreamPath))
    } elseif ($CaptureErrorMessage -and $CaptureErrorMessage -match "no known-good trace was produced") {
        $lines.Add("- Proxy saw traffic, but none matched expected Google target routes.")
        $lines.Add("- This usually means the active chat surface was not Google-backed, or traffic bypassed interception.")
    } elseif ($CaptureErrorMessage) {
        $lines.Add("- Capture script reported an error before writing known-good output.")
        $lines.Add(("- Error summary: {0}" -f (($CaptureErrorMessage -replace '\s+', ' ').Trim())))
    } else {
        $lines.Add("- Capture script failed before writing known-good output.")
    }

    $lines.Add("")
    $lines.Add("Artifacts")
    $lines.Add("---------")
    if ($stderrPath) { $lines.Add(("- mitmdump stderr: {0}" -f $stderrPath)) }
    if ($stdoutPath) { $lines.Add(("- mitmdump stdout: {0}" -f $stdoutPath)) }
    if (-not $stderrPath -and -not $stdoutPath -and -not $missingStreamPath) {
        $lines.Add("- No capture artifacts were found in output/.")
    }

    $lines.Add("")
    $lines.Add("What To Do")
    $lines.Add("----------")
    $lines.Add("1. Keep Antigravity open and use the Google-backed chat surface.")
    $lines.Add("2. Re-run parity: .\console.ps1 parity-master")
    if ($RequireStream) {
        $lines.Add("3. Wait for streamed response tokens; capture auto-stops when requirement is met or timeout is reached.")
    } else {
        $lines.Add("3. Send one prompt and wait for response; capture auto-stops when target traffic is observed.")
    }

    $lines.Add("")
    $lines.Add("Manual Capture Fallback")
    $lines.Add("-----------------------")
    $lines.Add(("powershell -NoProfile -ExecutionPolicy Bypass -File scripts/capture-known-good-mitmproxy.ps1 -Port {0} -KnownGoodPath {1} -ManageAntigravityIdeProxy -ManageSystemProxy -ManageWinHttpProxy -SelfTestProxy -UserAgentContains google-api-nodejs-client/10.3.0 -AllowMissingStream -SkipDiff" -f $Port, $TargetKnownGoodPath))
    return ($lines -join [Environment]::NewLine)
}

function Is-AntigravityUserAgent {
    param([string]$UserAgent)
    if (-not $UserAgent) { return $false }
    return ($UserAgent -match '(?i)^antigravity/') -or ($UserAgent -match '(?i)^google-api-nodejs-client/10\.3\.0$')
}

function Get-KnownGoodCaptureQuality {
    param(
        [Parameter(Mandatory = $true)][string]$KnownGoodPath,
        [string]$AllowlistPath = ""
    )

    $allowSet = New-Object System.Collections.Generic.HashSet[string]
    if ($AllowlistPath -and (Test-Path $AllowlistPath)) {
        foreach ($line in Get-Content $AllowlistPath) {
            $trim = $line.Trim()
            if (-not $trim -or $trim.StartsWith("#")) { continue }
            [void]$allowSet.Add((Normalize-Endpoint -Endpoint $trim))
        }
    }

    $uaCounts = @{}
    $hostCounts = @{}
    $summary = [ordered]@{
        total_records = 0
        antigravity_ua_records = 0
        cloudcode_v1internal_records = 0
        allowlist_records = 0
        allowlist_loaded = ($allowSet.Count -gt 0)
        pass = $false
        top_user_agents = @()
        top_hosts = @()
    }

    if (-not (Test-Path $KnownGoodPath)) {
        return [pscustomobject]$summary
    }

    foreach ($line in Get-Content $KnownGoodPath) {
        $trim = $line.Trim()
        if (-not $trim) { continue }
        $obj = $null
        try {
            $obj = $trim | ConvertFrom-Json
        } catch {
            continue
        }

        $endpoint = [string]$obj.endpoint
        if (-not $endpoint) { continue }
        $summary.total_records++

        $normalized = Normalize-Endpoint -Endpoint $endpoint
        if ($normalized -match '(?i)^https?://(daily-)?cloudcode-pa\.googleapis\.com/.*v1internal') {
            $summary.cloudcode_v1internal_records++
        }
        if ($allowSet.Count -gt 0 -and $allowSet.Contains($normalized)) {
            $summary.allowlist_records++
        }

        $ua = ""
        try { $ua = [string]$obj.headers.'user-agent' } catch {}
        if (-not [string]::IsNullOrWhiteSpace($ua)) {
            if ($uaCounts.ContainsKey($ua)) { $uaCounts[$ua]++ } else { $uaCounts[$ua] = 1 }
        }
        if (Is-AntigravityUserAgent -UserAgent $ua) {
            $summary.antigravity_ua_records++
        }

        try {
            $hostName = ([System.Uri]$endpoint).Host.ToLowerInvariant()
            if ($hostName) {
                if ($hostCounts.ContainsKey($hostName)) { $hostCounts[$hostName]++ } else { $hostCounts[$hostName] = 1 }
            }
        } catch {}
    }

    $allowlistOk = ($allowSet.Count -eq 0 -or $summary.allowlist_records -gt 0)
    $summary.pass = (
        $summary.total_records -gt 0 -and
        $summary.antigravity_ua_records -gt 0 -and
        $summary.cloudcode_v1internal_records -gt 0 -and
        $allowlistOk
    )
    $summary.top_user_agents = @(
        $uaCounts.GetEnumerator() |
            Sort-Object Value -Descending |
            Select-Object -First 8 |
            ForEach-Object { "{0} ({1})" -f $_.Key, $_.Value }
    )
    $summary.top_hosts = @(
        $hostCounts.GetEnumerator() |
            Sort-Object Value -Descending |
            Select-Object -First 8 |
            ForEach-Object { "{0} ({1})" -f $_.Key, $_.Value }
    )

    return [pscustomobject]$summary
}

function Build-KnownGoodCaptureQualityFailureMessage {
    param(
        [Parameter(Mandatory = $true)]$Quality,
        [Parameter(Mandatory = $true)][string]$TargetKnownGoodPath,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("")
    $lines.Add("Auto Official Capture Was Not Representative")
    $lines.Add("============================================")
    $lines.Add(("Known-good target: {0}" -f $TargetKnownGoodPath))
    $lines.Add("")
    $lines.Add("Captured Summary")
    $lines.Add("----------------")
    $lines.Add(("- total records: {0}" -f [int]$Quality.total_records))
    $lines.Add(("- Antigravity/LS UA records: {0}" -f [int]$Quality.antigravity_ua_records))
    $lines.Add(("- cloudcode v1internal records: {0}" -f [int]$Quality.cloudcode_v1internal_records))
    if ([bool]$Quality.allowlist_loaded) {
        $lines.Add(("- allowlisted endpoint records: {0}" -f [int]$Quality.allowlist_records))
    }

    $topUas = @($Quality.top_user_agents)
    if ($topUas.Count -gt 0) {
        $lines.Add("")
        $lines.Add("Top User-Agents")
        $lines.Add("---------------")
        foreach ($ua in $topUas) { $lines.Add(("- {0}" -f $ua)) }
    }

    $topHosts = @($Quality.top_hosts)
    if ($topHosts.Count -gt 0) {
        $lines.Add("")
        $lines.Add("Top Hosts")
        $lines.Add("---------")
        foreach ($h in $topHosts) { $lines.Add(("- {0}" -f $h)) }
    }

    $lines.Add("")
    $lines.Add("Why This Fails")
    $lines.Add("--------------")
    $lines.Add("- Parity requires official Antigravity/LS Google traffic fingerprints.")
    $lines.Add("- This capture did not include enough Antigravity/LS cloudcode evidence.")
    $lines.Add("")
    $lines.Add("Next Step")
    $lines.Add("---------")
    $lines.Add("1. Keep Antigravity open in the Google-backed chat surface.")
    $lines.Add("2. Re-run: .\console.ps1 parity-master")
    $lines.Add("3. Send one message in that Google-backed chat and wait for response tokens.")
    $lines.Add("")
    $lines.Add("Manual Fallback")
    $lines.Add("---------------")
    $lines.Add(("powershell -NoProfile -ExecutionPolicy Bypass -File scripts/capture-known-good-mitmproxy.ps1 -Port {0} -KnownGoodPath {1} -ManageAntigravityIdeProxy -ManageSystemProxy -ManageWinHttpProxy -SelfTestProxy -UserAgentContains google-api-nodejs-client/10.3.0 -AllowMissingStream -SkipDiff" -f $Port, $TargetKnownGoodPath))
    return ($lines -join [Environment]::NewLine)
}

function Ensure-RealKnownGoodCapture {
    param(
        [Parameter(Mandatory = $true)][string]$TargetKnownGoodPath,
        [Parameter(Mandatory = $true)][int]$Port,
        [string]$AntigravityExe,
        [switch]$RequireStream
    )

    $captureScript = Join-Path $PSScriptRoot "capture-known-good-mitmproxy.ps1"
    if (-not (Test-Path $captureScript)) {
        throw "Capture script missing: $captureScript"
    }

    $targetDir = Split-Path -Parent $TargetKnownGoodPath
    if ($targetDir) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }

    Assert-OfficialCapturePrerequisites
    $lsSniPreflight = Invoke-LsSniPreflight -Skip:$SkipLsSniPreflight

    $runningAntigravity = Get-LatestRunningAntigravityProcess
    $attachToRunning = ($null -ne $runningAntigravity)
    $resolvedExe = Resolve-AntigravityExePath -PreferredPath $AntigravityExe -RunningProcess $runningAntigravity

    $captureParams = @{
        Port = $Port
        KnownGoodPath = $TargetKnownGoodPath
        SkipDiff = $true
        ManageAntigravityIdeProxy = $true
        ManageSystemProxy = $true
        ManageWinHttpProxy = $true
        SelfTestProxy = $true
        UserAgentContains = @("google-api-nodejs-client/10.3.0")
        AutoCaptureTimeoutSeconds = 75
        AutoStopOnRequirement = $true
    }

    $captureMode = "attach_running_antigravity"
    if ($attachToRunning) {
        Write-Host ("  mode: attach running Antigravity (pid={0})" -f $runningAntigravity.ProcessId)
        Write-Host "  behavior: no forced IDE stop/restart"
    } else {
        if (-not $resolvedExe.path) {
            throw "Antigravity is not running and executable path could not be auto-resolved. Install Antigravity in default location or pass --known-good-antigravity-exe."
        }
        $captureMode = "launch_antigravity_proxied"
        $captureParams.LaunchAntigravityProxied = $true
        $captureParams.AntigravityExe = $resolvedExe.path
        Write-Host ("  mode: launch Antigravity proxied ({0})" -f $resolvedExe.path)
    }
    if ($RequireStream) {
        $captureParams.RequireStream = $true
    } else {
        $captureParams.AllowMissingStream = $true
    }

    Write-Host "Known-good is missing; capturing real official traffic now ..."
    Write-Host "  target: $TargetKnownGoodPath"
    Write-Host "  port: $Port"
    $captureErrorMessage = ""
    $captureExit = 0
    try {
        & $captureScript @captureParams
    } catch {
        $captureExit = 1
        $captureErrorMessage = [string]$_.Exception.Message
    }
    if ($captureExit -ne 0) {
        $failureMessage = Build-KnownGoodCaptureFailureMessage `
            -ExitCode $captureExit `
            -TargetKnownGoodPath $TargetKnownGoodPath `
            -Port $Port `
            -RequireStream:$RequireStream `
            -CaptureErrorMessage $captureErrorMessage
        throw $failureMessage
    }

    if (-not (Test-Path $TargetKnownGoodPath)) {
        throw "Capture completed but known-good file was not produced: $TargetKnownGoodPath"
    }
    $lineCount = (Get-Content $TargetKnownGoodPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
    if ($lineCount -le 0) {
        throw "Capture completed but known-good file is empty: $TargetKnownGoodPath"
    }
    $quality = Get-KnownGoodCaptureQuality -KnownGoodPath $TargetKnownGoodPath -AllowlistPath $AllowlistPath
    if (-not [bool]$quality.pass) {
        $qualityMessage = Build-KnownGoodCaptureQualityFailureMessage -Quality $quality -TargetKnownGoodPath $TargetKnownGoodPath -Port $Port
        throw $qualityMessage
    }
    return [pscustomobject]@{
        line_count = $lineCount
        quality_total_records = [int]$quality.total_records
        quality_antigravity_ua_records = [int]$quality.antigravity_ua_records
        quality_cloudcode_v1internal_records = [int]$quality.cloudcode_v1internal_records
        quality_allowlist_records = [int]$quality.allowlist_records
        capture_mode = $captureMode
        antigravity_exe = $resolvedExe.path
        antigravity_exe_source = $resolvedExe.source
        attached_to_running = [bool]$attachToRunning
        ls_sni_preflight_mode = [string]$lsSniPreflight.mode
        ls_sni_preflight_report = [string]$lsSniPreflight.report_path
        ls_sni_preflight_ls_rows = [int]$lsSniPreflight.ls_rows
    }
}

$statusDir = Split-Path -Parent $OutStatusJson
if ($statusDir) {
    New-Item -ItemType Directory -Path $statusDir -Force | Out-Null
}
New-Item -ItemType Directory -Path "output/parity" -Force | Out-Null

$knownGoodBootstrapMode = "existing"
$knownGoodBootstrapSource = ""
$shouldCaptureKnownGood = (-not (Test-Path $KnownGoodPath))
if (-not $shouldCaptureKnownGood) {
    $existingQuality = Get-KnownGoodCaptureQuality -KnownGoodPath $KnownGoodPath -AllowlistPath $AllowlistPath
    if (-not [bool]$existingQuality.pass) {
        if ($NoAutoCaptureKnownGood) {
            $msg = Build-KnownGoodCaptureQualityFailureMessage -Quality $existingQuality -TargetKnownGoodPath $KnownGoodPath -Port $KnownGoodCapturePort
            Exit-Gracefully -Message "$msg`n`nAuto-refresh is disabled (-NoAutoCaptureKnownGood)."
        }
        Write-Warning "Existing known-good is not representative; auto-refreshing official capture."
        $shouldCaptureKnownGood = $true
        $knownGoodBootstrapMode = "re_captured_due_quality_guard"
    } else {
        $knownGoodBootstrapSource = "existing file passed quality guard"
    }
}
if ($shouldCaptureKnownGood) {
    if ($NoAutoCaptureKnownGood) {
        Exit-Gracefully -Message ([string]::Format(
            "Known-good source is missing at '{0}' and auto-capture is disabled. Run official capture first or remove -NoAutoCaptureKnownGood.",
            $KnownGoodPath
        ))
    }
    try {
        $captureResult = Ensure-RealKnownGoodCapture -TargetKnownGoodPath $KnownGoodPath -Port $KnownGoodCapturePort -AntigravityExe $KnownGoodAntigravityExe -RequireStream:$KnownGoodCaptureRequireStream
    } catch {
        Exit-Gracefully -Message $_.Exception.Message
    }
    $capturedLines = [int]$captureResult.line_count
    if ($knownGoodBootstrapMode -eq "existing") {
        $knownGoodBootstrapMode = "captured_real_official_$($captureResult.capture_mode)"
    }
    $knownGoodBootstrapSource = "capture-known-good-mitmproxy.ps1 ($capturedLines lines, antigravity_ua_rows=$($captureResult.quality_antigravity_ua_records), cloudcode_v1internal_rows=$($captureResult.quality_cloudcode_v1internal_records), exe_source=$($captureResult.antigravity_exe_source), ls_sni_preflight=$($captureResult.ls_sni_preflight_mode), ls_rows=$($captureResult.ls_sni_preflight_ls_rows))"
}

$baselineAssetsPresent = (Test-Path $BaselineGephyrPath) -and (Test-Path $BaselineKnownGoodPath)
$skipRepoGateEffective = [bool]$SkipRepoGate
$skipBaselineGateEffective = [bool]$SkipBaselineGate
$skipMismatchContractEffective = [bool]$SkipMismatchContract
$autoSkips = @()
if (-not $baselineAssetsPresent) {
    if (-not $skipRepoGateEffective) { $skipRepoGateEffective = $true; $autoSkips += "repo_gate_missing_baselines" }
    if (-not $skipBaselineGateEffective) { $skipBaselineGateEffective = $true; $autoSkips += "baseline_gate_missing_baselines" }
    if (-not $skipMismatchContractEffective) { $skipMismatchContractEffective = $true; $autoSkips += "mismatch_contract_missing_baselines" }
}

$liveScript = Join-Path $PSScriptRoot "live-google-parity-verify-antigravity.ps1"
$liveArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $liveScript,
    "-KnownGoodPath", $KnownGoodPath,
    "-OutGephyrPath", $OutGephyrPath,
    "-StartupTimeoutSeconds", "$StartupTimeoutSeconds",
    "-AllowlistPath", $AllowlistPath
)
if ($RequireOAuthRelink) { $liveArgs += "-RequireOAuthRelink" }
if ($AllowMimicTokenRefresh) { $liveArgs += "-AllowMimicTokenRefresh" }
if ($IncludeChatProbe) { $liveArgs += "-IncludeChatProbe" }
if ($IncludeAuthEventProbes) { $liveArgs += "-IncludeAuthEventProbes" }
if ($IncludeExtendedFlow) { $liveArgs += "-IncludeExtendedFlow" }
if ($RefreshInclusive) { $liveArgs += "-RefreshInclusive" }
if ($AllowMissingAllowlistEndpoints) { $liveArgs += "-AllowMissingAllowlistEndpoints" }
if ($SkipAllowlistValidation) { $liveArgs += "-SkipAllowlistValidation" }

Write-Host "Running live Antigravity-scoped parity verification ..."
$live = Invoke-External -Exe "powershell" -Args $liveArgs

$diffJsonPath = "output/google_trace_diff_report.json"
$diffTxtPath = "output/google_trace_diff_report.txt"
$allowlistJsonPath = "output/antigravity_allowed_endpoint_validation.json"
$allowlistTxtPath = "output/antigravity_allowed_endpoint_validation.txt"
$baselineGateOut = "output/parity/master_validation.baseline_gate.report.json"
$mismatchFixturePath = "output/parity/master_validation.known_good.mismatch.jsonl"
$mismatchGateOut = "output/parity/master_validation.mismatch_gate.report.json"

$diff = Try-LoadJson -Path $diffJsonPath
$allowlist = Try-LoadJson -Path $allowlistJsonPath

$diffEndpoints = $null
if ($null -ne $diff) {
    $diffEndpoints = $diff.endpoints
}
$endpointRows = As-Array $diffEndpoints
$classificationIssues = @()
$countIssues = @()
if ($RefreshInclusive) {
    $classificationIssues = @(
        $endpointRows | Where-Object {
            $c = [string]$_.classification
            $c -ne "matched_or_extra_only" -and $c -ne "extra_endpoint_in_gephyr"
        }
    )
    $countIssues = @(
        $endpointRows | Where-Object {
            [int]$_.known_request_count -gt [int]$_.gephyr_request_count
        }
    )
} else {
    $classificationIssues = @($endpointRows | Where-Object { [string]$_.classification -ne "matched_or_extra_only" })
    $countIssues = @($endpointRows | Where-Object { [int]$_.known_request_count -ne [int]$_.gephyr_request_count })
}
$missingHeaderIssues = @($endpointRows | Where-Object { (As-Array $_.missing_in_gephyr).Count -gt 0 })
$extraHeaderIssues = @($endpointRows | Where-Object { (As-Array $_.extra_in_gephyr).Count -gt 0 })

$recordsMatch = $false
if ($null -ne $diff) {
    $recordsMatch = ([int]$diff.gephyr_records -eq [int]$diff.known_good_records)
}
$effectiveRecordsMatch = if ($RefreshInclusive) { $true } else { $recordsMatch }
$diffPass = (
    $null -ne $diff -and
    $classificationIssues.Count -eq 0 -and
    $countIssues.Count -eq 0 -and
    $missingHeaderIssues.Count -eq 0 -and
    $extraHeaderIssues.Count -eq 0 -and
    $effectiveRecordsMatch
)

$allowlistPass = $false
$allowlistUnknown = 0
$allowlistMissing = 0
if ($null -ne $allowlist) {
    $allowlistUnknownList = As-Array $allowlist.unknown_google_endpoints
    if ($RefreshInclusive) {
        $allowlistUnknownList = @($allowlistUnknownList | Where-Object { $_ -ne "https://oauth2.googleapis.com/token" })
    }
    $allowlistUnknown = $allowlistUnknownList.Count
    $allowlistMissing = (As-Array $allowlist.missing_allowed_endpoints).Count
    if ($RefreshInclusive) {
        $requireAll = [bool]$allowlist.require_all_allowed_observed
        $allowlistPass = ($allowlistUnknown -eq 0 -and ((-not $requireAll) -or $allowlistMissing -eq 0))
    } else {
        $allowlistPass = [bool]$allowlist.pass
    }
}

$manifest = [pscustomobject]@{ ok = $true; exit_code = 0 }
$noRaw = [pscustomobject]@{ ok = $true; exit_code = 0 }
if (-not $skipRepoGateEffective) {
    Write-Host "Running repo parity guard checks ..."
    $manifest = Invoke-External -Exe "powershell" -Args @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $PSScriptRoot "validate-parity-baseline-manifests.ps1")
    )
    $noRaw = Invoke-External -Exe "powershell" -Args @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $PSScriptRoot "check-no-raw-parity-artifacts.ps1")
    )
}
$repoGatePass = $skipRepoGateEffective -or ($manifest.ok -and $noRaw.ok)

$baselineGate = [pscustomobject]@{ ok = $true; exit_code = 0 }
if (-not $skipBaselineGateEffective) {
    Write-Host "Running baseline gate check ..."
    $baselineGate = Invoke-External -Exe "cargo" -Args @(
        "run", "--quiet", "--bin", "gephyr-parity", "--",
        "gate",
        "--gephyr", $BaselineGephyrPath,
        "--known-good", $BaselineKnownGoodPath,
        "--out", $baselineGateOut
    )
}
$baselineGatePass = $skipBaselineGateEffective -or $baselineGate.ok

$mismatchContract = [pscustomobject]@{
    skipped = [bool]$skipMismatchContractEffective
    pass = $true
    gate_exit_code = 0
    report_has_gate_pass_false = $true
    fixture_path = $mismatchFixturePath
    report_path = $mismatchGateOut
}
if (-not $skipMismatchContractEffective) {
    Write-Host "Running intentional mismatch gate-fail contract ..."
    try {
        if (-not (Test-Path $BaselineKnownGoodPath)) {
            throw "known-good baseline not found: $BaselineKnownGoodPath"
        }
        if (-not (Test-Path $BaselineGephyrPath)) {
            throw "gephyr baseline not found: $BaselineGephyrPath"
        }

        $rawLines = Get-Content $BaselineKnownGoodPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($rawLines.Count -eq 0) {
            throw "known-good baseline is empty: $BaselineKnownGoodPath"
        }
        $records = @($rawLines | ForEach-Object { $_ | ConvertFrom-Json })
        $mutated = $false
        foreach ($rec in $records) {
            $pairs = @()
            foreach ($pair in (As-Array $rec.headers)) {
                $arr = @($pair)
                if ($arr.Count -ge 2) {
                    $name = [string]$arr[0]
                    if ((-not $mutated) -and $name.Equals("user-agent", [System.StringComparison]::OrdinalIgnoreCase)) {
                        $pairs += ,@($arr[0], "mismatch-agent/0.0")
                        $mutated = $true
                    } else {
                        $pairs += ,@($arr[0], $arr[1])
                    }
                } else {
                    $pairs += ,$arr
                }
            }
            $rec.headers = $pairs
        }
        if (-not $mutated) {
            throw "could not mutate user-agent in known-good baseline"
        }

        New-Item -ItemType Directory -Path (Split-Path -Parent $mismatchFixturePath) -Force | Out-Null
        if (Test-Path $mismatchFixturePath) {
            Remove-Item $mismatchFixturePath -Force
        }
        foreach ($rec in $records) {
            ($rec | ConvertTo-Json -Compress -Depth 50) | Add-Content -Path $mismatchFixturePath
        }
    } catch {
        $mismatchContract.pass = $false
        $mismatchContract.gate_exit_code = 1
        $mismatchContract.report_has_gate_pass_false = $false
    }

    if ($mismatchContract.pass) {
        $mismatchGate = Invoke-External -Exe "cargo" -Args @(
            "run", "--quiet", "--bin", "gephyr-parity", "--",
            "gate",
            "--gephyr", $BaselineGephyrPath,
            "--known-good", $mismatchFixturePath,
            "--out", $mismatchGateOut
        ) -SuppressOutput
        $mismatchReport = Try-LoadJson -Path $mismatchGateOut
        $reportHasGatePassFalse = $false
        if ($null -ne $mismatchReport -and $null -ne $mismatchReport.gate_pass) {
            $reportHasGatePassFalse = (-not [bool]$mismatchReport.gate_pass)
        }
        $mismatchContract.gate_exit_code = $mismatchGate.exit_code
        $mismatchContract.report_has_gate_pass_false = $reportHasGatePassFalse
        $mismatchContract.pass = ((-not $mismatchGate.ok) -and $reportHasGatePassFalse)
    }
}

# The mismatch fixture is always disposable.
Remove-IfExists -Path $mismatchFixturePath

$prunedArtifacts = 0
if ($PruneOutput) {
    $prunedArtifacts = Prune-OutputArtifacts `
        -KnownGoodPathToKeep $KnownGoodPath `
        -OutGephyrPathToKeep $OutGephyrPath `
        -DiffJsonPathToKeep $diffJsonPath `
        -DiffTxtPathToKeep $diffTxtPath `
        -AllowlistJsonPathToKeep $allowlistJsonPath `
        -AllowlistTxtPathToKeep $allowlistTxtPath `
        -StatusJsonPathToKeep $OutStatusJson `
        -BaselineGateOutToKeep $baselineGateOut `
        -MismatchGateOutToKeep $mismatchGateOut
}

$overallPass = ($live.ok -and $diffPass -and $allowlistPass -and $repoGatePass -and $baselineGatePass -and $mismatchContract.pass)

$status = [ordered]@{
    generated_at = (Get-Date).ToString("o")
    one_to_one_pass = $overallPass
    one_to_one_status = if ($overallPass) { "PASS" } else { "FAIL" }
    lane = if ($RefreshInclusive) { "refresh-inclusive" } else { "strict-default" }
    inputs = [ordered]@{
        known_good_path = $KnownGoodPath
        known_good_bootstrap_mode = $knownGoodBootstrapMode
        known_good_bootstrap_source = $knownGoodBootstrapSource
        out_gephyr_path = $OutGephyrPath
        allowlist_path = $AllowlistPath
        baseline_gephyr_path = $BaselineGephyrPath
        baseline_known_good_path = $BaselineKnownGoodPath
        baseline_assets_present = [bool]$baselineAssetsPresent
        auto_skips = @($autoSkips)
    }
    steps = [ordered]@{
        live_verify = [ordered]@{
            pass = $live.ok
            exit_code = $live.exit_code
        }
        diff = [ordered]@{
            pass = $diffPass
            report_path = $diffJsonPath
            gephyr_records = if ($null -ne $diff) { [int]$diff.gephyr_records } else { 0 }
            known_good_records = if ($null -ne $diff) { [int]$diff.known_good_records } else { 0 }
            records_match_required = (-not [bool]$RefreshInclusive)
            classification_issues = $classificationIssues.Count
            request_count_issues = $countIssues.Count
            missing_header_issues = $missingHeaderIssues.Count
            extra_header_issues = $extraHeaderIssues.Count
        }
        allowlist = [ordered]@{
            pass = $allowlistPass
            report_path = $allowlistJsonPath
            unknown_google_endpoints = $allowlistUnknown
            missing_allowed_endpoints = $allowlistMissing
        }
        repo_gate = [ordered]@{
            skipped = [bool]$skipRepoGateEffective
            pass = $repoGatePass
            manifest_pass = $manifest.ok
            no_raw_artifacts_pass = $noRaw.ok
        }
        baseline_gate = [ordered]@{
            skipped = [bool]$skipBaselineGateEffective
            pass = $baselineGatePass
            exit_code = $baselineGate.exit_code
            report_path = $baselineGateOut
        }
        mismatch_contract = [ordered]@{
            skipped = [bool]$skipMismatchContractEffective
            pass = [bool]$mismatchContract.pass
            gate_exit_code = [int]$mismatchContract.gate_exit_code
            report_has_gate_pass_false = [bool]$mismatchContract.report_has_gate_pass_false
            fixture_path = [string]$mismatchContract.fixture_path
            report_path = [string]$mismatchContract.report_path
        }
        cleanup = [ordered]@{
            enabled = [bool]$PruneOutput
            pruned_artifacts = [int]$prunedArtifacts
        }
    }
}

$status | ConvertTo-Json -Depth 20 | Set-Content -Path $OutStatusJson -Encoding UTF8

if ($Json) {
    $status | ConvertTo-Json -Depth 20
} else {
    Write-Host ""
    Write-Host "Parity Master Validation"
    Write-Host "  lane: $($status.lane)"
    Write-Host "  1:1 status: $($status.one_to_one_status)"
    Write-Host "  live verify: $([bool]$status.steps.live_verify.pass)"
    Write-Host "  diff strict: $([bool]$status.steps.diff.pass)"
    Write-Host "  allowlist: $([bool]$status.steps.allowlist.pass)"
    Write-Host "  repo gate: $([bool]$status.steps.repo_gate.pass) (skipped=$([bool]$status.steps.repo_gate.skipped))"
    Write-Host "  baseline gate: $([bool]$status.steps.baseline_gate.pass) (skipped=$([bool]$status.steps.baseline_gate.skipped))"
    Write-Host "  mismatch contract: $([bool]$status.steps.mismatch_contract.pass) (skipped=$([bool]$status.steps.mismatch_contract.skipped))"
    if ($PruneOutput) {
        Write-Host "  cleanup: pruned $($status.steps.cleanup.pruned_artifacts) artifact(s)"
    }
    Write-Host "  status json: $OutStatusJson"
}

if (-not $overallPass) {
    exit 1
}
exit 0

