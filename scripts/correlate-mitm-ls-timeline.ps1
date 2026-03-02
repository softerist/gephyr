<#
.SYNOPSIS
Correlates MITM capture JSONL with language-server TCP connection traces.

.DESCRIPTION
Builds a machine-readable timeline report that aligns:
- MITM request captures (endpoint/method/headers/timestamp)
- OS-level language server connection polls (remote IP/port/timestamp)

This helps distinguish:
1) "No generation happened" vs
2) "Generation happened but bypassed the MITM proxy" vs
3) "Prompt activity went to non-Google chat surfaces."
#>
param(
    [string]$MitmPath = "output/known_good.discovery.jsonl",
    [string]$ConnectionsCsvPath = "output/ls_generation_probe.language_server_windows_x64.connections.csv",
    [string]$OutBase = "output/parity/official/live.timeline_correlation",
    [int]$BucketSeconds = 1,
    [int]$Top = 20,
    [int]$ProxyPort = 8891,
    [switch]$IncludeLoopback,
    [switch]$ResolvePtr
)

$ErrorActionPreference = "Stop"

if ($BucketSeconds -lt 1) {
    throw "BucketSeconds must be >= 1."
}
if ($Top -lt 1) {
    throw "Top must be >= 1."
}

function Resolve-RepoRoot {
    try {
        $gitRoot = (& git rev-parse --show-toplevel 2>$null | Select-Object -First 1)
        if ($gitRoot) {
            return (Resolve-Path $gitRoot.Trim()).Path
        }
    } catch {}
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Resolve-InputFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )

    $candidate = $Path
    if (-not [IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $RepoRoot $candidate
    }

    if (Test-Path $candidate -PathType Leaf) {
        return (Resolve-Path $candidate).Path
    }

    $matches = @(
        Get-ChildItem -Path $candidate -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending
    )
    if ($matches.Count -gt 0) {
        return $matches[0].FullName
    }

    throw "$Label not found: $Path"
}

function Resolve-OutBase {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )
    if ([IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $RepoRoot $Path)
}

function Test-LoopbackAddress {
    param([string]$Address)
    if (-not $Address) { return $false }
    $a = $Address.Trim().ToLowerInvariant()
    return ($a -eq "127.0.0.1" -or $a -eq "::1" -or $a -eq "localhost")
}

function Test-GoogleHost {
    param([string]$EndpointHost)
    if (-not $EndpointHost) { return $false }
    $h = $EndpointHost.Trim().ToLowerInvariant()
    return ($h -eq "google.com" -or
        $h -eq "www.google.com" -or
        $h.EndsWith(".google.com") -or
        $h.EndsWith(".googleapis.com"))
}

function Test-CloudCodeHost {
    param([string]$EndpointHost)
    if (-not $EndpointHost) { return $false }
    $h = $EndpointHost.Trim().ToLowerInvariant()
    return ($h.Contains("cloudcode") -or $h.Contains("daily-cloudcode"))
}

function Test-OpenAiChatHost {
    param([string]$EndpointHost)
    if (-not $EndpointHost) { return $false }
    $h = $EndpointHost.Trim().ToLowerInvariant()
    return ($h -eq "chatgpt.com" -or $h -eq "chat.openai.com" -or $h -eq "ab.chatgpt.com")
}

function Test-GenerationEndpoint {
    param(
        [string]$EndpointHost,
        [string]$Path
    )
    $h = ([string]$EndpointHost).ToLowerInvariant()
    $p = ([string]$Path).ToLowerInvariant()
    if (-not $p) { return $false }
    if (-not (Test-GoogleHost -Host $h)) { return $false }

    return $p -match "(?i)(streamgeneratecontent|streamgeneratechat|generatecontent|generatechat|generatecode|completecode|internalatomicagenticchat|tabchat)"
}

function Get-BucketEpoch {
    param(
        [Parameter(Mandatory = $true)][DateTimeOffset]$Timestamp,
        [Parameter(Mandatory = $true)][int]$SizeSeconds
    )
    $epoch = $Timestamp.ToUnixTimeSeconds()
    $start = [int64]([math]::Floor($epoch / $SizeSeconds) * $SizeSeconds)
    return $start
}

function Get-OrCreateBucket {
    param(
        [Parameter(Mandatory = $true)]$Buckets,
        [Parameter(Mandatory = $true)][int64]$Epoch
    )
    if (-not $Buckets.ContainsKey($Epoch)) {
        $Buckets[$Epoch] = [ordered]@{
            bucket_start_epoch = $Epoch
            bucket_start_utc = [DateTimeOffset]::FromUnixTimeSeconds($Epoch).ToUniversalTime().ToString("o")
            mitm_total = 0
            mitm_google = 0
            mitm_cloudcode = 0
            mitm_oauth = 0
            mitm_generation = 0
            mitm_openai_chat = 0
            mitm_other = 0
            mitm_hosts = @{}
            mitm_generation_endpoints = (New-Object 'System.Collections.Generic.HashSet[string]')
            ls_rows = 0
            ls_remote_endpoints = (New-Object 'System.Collections.Generic.HashSet[string]')
            ls_public_remote_endpoints = (New-Object 'System.Collections.Generic.HashSet[string]')
            ls_proxy_remote_endpoints = (New-Object 'System.Collections.Generic.HashSet[string]')
        }
    }
    return $Buckets[$Epoch]
}

function Add-Count {
    param(
        [Parameter(Mandatory = $true)]$Map,
        [Parameter(Mandatory = $true)][string]$Key,
        [int]$By = 1
    )
    if (-not $Map.ContainsKey($Key)) {
        $Map[$Key] = 0
    }
    $Map[$Key] += $By
}

function Convert-TopMap {
    param(
        [Parameter(Mandatory = $true)]$Map,
        [int]$Limit = 20
    )
    return @(
        $Map.GetEnumerator() |
        Sort-Object Value -Descending |
        Select-Object -First $Limit |
        ForEach-Object {
            [ordered]@{
                name = $_.Key
                count = $_.Value
            }
        }
    )
}

function Get-OptionalPtrHost {
    param(
        [Parameter(Mandatory = $true)][string]$Ip,
        [Parameter(Mandatory = $true)]$Cache
    )
    if ($Cache.ContainsKey($Ip)) {
        return $Cache[$Ip]
    }
    $result = $null
    try {
        $entry = [System.Net.Dns]::GetHostEntry($Ip)
        if ($entry -and $entry.HostName) {
            $result = [string]$entry.HostName
        }
    } catch {}
    $Cache[$Ip] = $result
    return $result
}

function To-IsoOrNull {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [DateTimeOffset]) {
            return $Value.ToUniversalTime().ToString("o")
        }
        return ([DateTimeOffset]::Parse([string]$Value)).ToUniversalTime().ToString("o")
    } catch {
        return $null
    }
}

$repoRoot = Resolve-RepoRoot
$mitmAbs = Resolve-InputFile -Path $MitmPath -Label "MITM JSONL" -RepoRoot $repoRoot
$connAbs = Resolve-InputFile -Path $ConnectionsCsvPath -Label "Connections CSV" -RepoRoot $repoRoot
$outBaseAbs = Resolve-OutBase -Path $OutBase -RepoRoot $repoRoot

$outDir = Split-Path -Parent $outBaseAbs
if ($outDir) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

$buckets = @{}
$mitmHostCounts = @{}
$mitmEndpointCounts = @{}
$mitmUACounts = @{}
$lsRemoteIpCounts = @{}
$lsRemoteEndpointCounts = @{}

$mitmCount = 0
$mitmGoogleCount = 0
$mitmCloudCodeCount = 0
$mitmOauthCount = 0
$mitmGenerationCount = 0
$mitmOpenAiCount = 0
$mitmOtherCount = 0
$mitmParseErrors = 0

$lsRowsRaw = 0
$lsRowsScoped = 0
$lsProxyRows = 0
$lsParseErrors = 0

$mitmMinTs = $null
$mitmMaxTs = $null
$lsMinTs = $null
$lsMaxTs = $null

$generationSamples = New-Object System.Collections.Generic.List[string]

Write-Host "Reading MITM JSONL: $mitmAbs"
foreach ($line in (Get-Content -Path $mitmAbs)) {
    if (-not [string]::IsNullOrWhiteSpace($line)) {
        $obj = $null
        try {
            $obj = $line | ConvertFrom-Json
        } catch {
            $mitmParseErrors += 1
            continue
        }
        if (-not $obj) {
            $mitmParseErrors += 1
            continue
        }

        $tsRaw = [string]$obj.timestamp
        $ts = $null
        try {
            $ts = [DateTimeOffset]::Parse($tsRaw).ToUniversalTime()
        } catch {
            $mitmParseErrors += 1
            continue
        }

        if ($null -eq $mitmMinTs -or $ts -lt $mitmMinTs) { $mitmMinTs = $ts }
        if ($null -eq $mitmMaxTs -or $ts -gt $mitmMaxTs) { $mitmMaxTs = $ts }

        $endpoint = [string]$obj.endpoint
        $method = [string]$obj.method
        $ua = ""
        try { $ua = [string]$obj.headers.'user-agent' } catch {}
        if (-not $ua) { $ua = "<missing-user-agent>" }

        $endpointHost = ""
        $pathAndQuery = ""
        try {
            $uri = [Uri]$endpoint
            $endpointHost = ([string]$uri.Host).ToLowerInvariant()
            $pathAndQuery = [string]$uri.PathAndQuery
        } catch {}

        $isGoogle = Test-GoogleHost -EndpointHost $endpointHost
        $isCloudCode = Test-CloudCodeHost -EndpointHost $endpointHost
        $isOauth = ($endpointHost -eq "oauth2.googleapis.com" -or ($endpointHost -eq "www.googleapis.com" -and $pathAndQuery -match "(?i)/oauth2/"))
        $isGeneration = Test-GenerationEndpoint -EndpointHost $endpointHost -Path $pathAndQuery
        $isOpenAiChat = Test-OpenAiChatHost -EndpointHost $endpointHost

        $mitmCount += 1
        if ($isGoogle) { $mitmGoogleCount += 1 }
        if ($isCloudCode) { $mitmCloudCodeCount += 1 }
        if ($isOauth) { $mitmOauthCount += 1 }
        if ($isGeneration) { $mitmGenerationCount += 1 }
        if ($isOpenAiChat) { $mitmOpenAiCount += 1 }
        if (-not ($isGoogle -or $isOpenAiChat)) { $mitmOtherCount += 1 }

        Add-Count -Map $mitmHostCounts -Key ($(if ($endpointHost) { $endpointHost } else { "<unknown-host>" }))
        Add-Count -Map $mitmEndpointCounts -Key ($(if ($endpoint) { $endpoint } else { "<unknown-endpoint>" }))
        Add-Count -Map $mitmUACounts -Key $ua

        $bucketEpoch = Get-BucketEpoch -Timestamp $ts -SizeSeconds $BucketSeconds
        $bucket = Get-OrCreateBucket -Buckets $buckets -Epoch $bucketEpoch
        $bucket.mitm_total += 1
        if ($isGoogle) { $bucket.mitm_google += 1 }
        if ($isCloudCode) { $bucket.mitm_cloudcode += 1 }
        if ($isOauth) { $bucket.mitm_oauth += 1 }
        if ($isGeneration) {
            $bucket.mitm_generation += 1
            [void]$bucket.mitm_generation_endpoints.Add("$method $pathAndQuery")
        }
        if ($isOpenAiChat) { $bucket.mitm_openai_chat += 1 }
        if (-not ($isGoogle -or $isOpenAiChat)) { $bucket.mitm_other += 1 }

        $hostKey = if ($endpointHost) { $endpointHost } else { "<unknown-host>" }
        if (-not $bucket.mitm_hosts.ContainsKey($hostKey)) {
            $bucket.mitm_hosts[$hostKey] = 0
        }
        $bucket.mitm_hosts[$hostKey] += 1

        if ($isGeneration -and $generationSamples.Count -lt 20) {
            $generationSamples.Add("$($ts.ToString("o")) $method $endpoint")
        }
    }
}

Write-Host "Reading LS connections CSV: $connAbs"
$connRows = Import-Csv -Path $connAbs
foreach ($row in $connRows) {
    $lsRowsRaw += 1

    $tsRaw = [string]$row.timestamp_utc
    $ts = $null
    try {
        $ts = [DateTimeOffset]::Parse($tsRaw).ToUniversalTime()
    } catch {
        $lsParseErrors += 1
        continue
    }

    $remoteAddress = [string]$row.remote_address
    $remotePort = 0
    try { $remotePort = [int]$row.remote_port } catch { $remotePort = 0 }

    $isLoopback = Test-LoopbackAddress -Address $remoteAddress
    $isProxy = ($isLoopback -and $remotePort -eq $ProxyPort)
    if (-not $IncludeLoopback -and $isLoopback -and -not $isProxy) {
        continue
    }

    $lsRowsScoped += 1
    if ($isProxy) {
        $lsProxyRows += 1
    }

    if ($null -eq $lsMinTs -or $ts -lt $lsMinTs) { $lsMinTs = $ts }
    if ($null -eq $lsMaxTs -or $ts -gt $lsMaxTs) { $lsMaxTs = $ts }

    $remoteIpKey = if ($remoteAddress) { $remoteAddress } else { "<unknown-ip>" }
    Add-Count -Map $lsRemoteIpCounts -Key $remoteIpKey

    $remoteEndpointKey = "{0}:{1}" -f $remoteIpKey, $remotePort
    Add-Count -Map $lsRemoteEndpointCounts -Key $remoteEndpointKey

    $bucketEpoch = Get-BucketEpoch -Timestamp $ts -SizeSeconds $BucketSeconds
    $bucket = Get-OrCreateBucket -Buckets $buckets -Epoch $bucketEpoch
    $bucket.ls_rows += 1
    [void]$bucket.ls_remote_endpoints.Add($remoteEndpointKey)
    if (-not $isLoopback) {
        [void]$bucket.ls_public_remote_endpoints.Add($remoteEndpointKey)
    }
    if ($isProxy) {
        [void]$bucket.ls_proxy_remote_endpoints.Add($remoteEndpointKey)
    }
}

$allEpochs = @($buckets.Keys | Sort-Object)
$timeline = New-Object System.Collections.Generic.List[object]
foreach ($epoch in $allEpochs) {
    $b = $buckets[$epoch]
    $topHosts = Convert-TopMap -Map $b.mitm_hosts -Limit 5
    $timeline.Add([ordered]@{
            bucket_start_utc = $b.bucket_start_utc
            mitm_total = $b.mitm_total
            mitm_google = $b.mitm_google
            mitm_cloudcode = $b.mitm_cloudcode
            mitm_oauth = $b.mitm_oauth
            mitm_generation = $b.mitm_generation
            mitm_openai_chat = $b.mitm_openai_chat
            mitm_other = $b.mitm_other
            mitm_top_hosts = $topHosts
            mitm_generation_endpoints = @($b.mitm_generation_endpoints)
            ls_rows = $b.ls_rows
            ls_unique_remote_endpoints = $b.ls_remote_endpoints.Count
            ls_unique_public_remote_endpoints = $b.ls_public_remote_endpoints.Count
            ls_unique_proxy_remote_endpoints = $b.ls_proxy_remote_endpoints.Count
            signals = [ordered]@{
                ls_public_without_any_mitm = ($b.ls_public_remote_endpoints.Count -gt 0 -and $b.mitm_total -eq 0)
                ls_public_without_google_mitm = ($b.ls_public_remote_endpoints.Count -gt 0 -and $b.mitm_google -eq 0)
                ls_public_with_openai_chat_only = ($b.ls_public_remote_endpoints.Count -gt 0 -and $b.mitm_openai_chat -gt 0 -and $b.mitm_google -eq 0)
            }
        })
}

$overlapStart = $null
$overlapEnd = $null
$overlapSeconds = 0.0
if ($mitmMinTs -and $mitmMaxTs -and $lsMinTs -and $lsMaxTs) {
    if ($mitmMinTs -gt $lsMinTs) { $overlapStart = $mitmMinTs } else { $overlapStart = $lsMinTs }
    if ($mitmMaxTs -lt $lsMaxTs) { $overlapEnd = $mitmMaxTs } else { $overlapEnd = $lsMaxTs }
    if ($overlapEnd -gt $overlapStart) {
        $overlapSeconds = [math]::Round((($overlapEnd - $overlapStart).TotalSeconds), 3)
    }
}

$overlapBuckets = @()
if ($overlapSeconds -gt 0) {
    $overlapBuckets = @($timeline | Where-Object {
            $t = [DateTimeOffset]::Parse($_.bucket_start_utc)
            $t -ge $overlapStart -and $t -le $overlapEnd
        })
}

$lsPublicBuckets = @($overlapBuckets | Where-Object { $_.ls_unique_public_remote_endpoints -gt 0 })
$lsProxyBuckets = @($overlapBuckets | Where-Object { $_.ls_unique_proxy_remote_endpoints -gt 0 })
$lsPublicWithAnyMitmBuckets = @($lsPublicBuckets | Where-Object { $_.mitm_total -gt 0 })
$lsPublicWithGoogleMitmBuckets = @($lsPublicBuckets | Where-Object { $_.mitm_google -gt 0 })
$lsPublicWithGenerationBuckets = @($lsPublicBuckets | Where-Object { $_.mitm_generation -gt 0 })
$lsPublicWithoutMitmBuckets = @($lsPublicBuckets | Where-Object { $_.signals.ls_public_without_any_mitm })
$lsPublicWithoutGoogleMitmBuckets = @($lsPublicBuckets | Where-Object { $_.signals.ls_public_without_google_mitm })

$coverageAny = $null
$coverageGoogle = $null
$coverageGeneration = $null
if ($lsPublicBuckets.Count -gt 0) {
    $coverageAny = [math]::Round(($lsPublicWithAnyMitmBuckets.Count / [double]$lsPublicBuckets.Count), 3)
    $coverageGoogle = [math]::Round(($lsPublicWithGoogleMitmBuckets.Count / [double]$lsPublicBuckets.Count), 3)
    $coverageGeneration = [math]::Round(($lsPublicWithGenerationBuckets.Count / [double]$lsPublicBuckets.Count), 3)
}

$findings = New-Object System.Collections.Generic.List[object]
if ($mitmGenerationCount -eq 0) {
    $findings.Add([ordered]@{
            code = "NO_GENERATION_ENDPOINT"
            severity = "warning"
            message = "No generation endpoint was observed in MITM capture."
        })
}
if ($mitmOpenAiCount -gt 0 -and $mitmGenerationCount -eq 0) {
    $findings.Add([ordered]@{
            code = "OPENAI_SURFACE_ACTIVE_DURING_CAPTURE"
            severity = "warning"
            message = "OpenAI chat hosts were active while Google generation was absent. This usually indicates prompts were sent in Open Agent Manager/Codex surface."
        })
}
if ($lsProxyRows -gt 0) {
    $findings.Add([ordered]@{
            code = "LS_PROXY_LOOPBACK_OBSERVED"
            severity = "info"
            message = "language_server_windows_x64 established loopback connections to proxy port."
        })
}
if ($lsRowsScoped -gt 0 -and $lsProxyRows -eq 0) {
    $findings.Add([ordered]@{
            code = "LS_NO_PROXY_PORT_ACTIVITY"
            severity = "warning"
            message = "No language_server_windows_x64 loopback traffic to the configured proxy port was observed in this trace window."
        })
}
if ($lsPublicBuckets.Count -gt 0 -and $lsPublicWithoutGoogleMitmBuckets.Count -gt 0) {
    $findings.Add([ordered]@{
            code = "LS_PUBLIC_ACTIVITY_WITHOUT_GOOGLE_MITM"
            severity = "warning"
            message = "In overlap windows, language server had public remote activity without matching Google MITM events."
            details = [ordered]@{
                ls_public_buckets = $lsPublicBuckets.Count
                ls_public_without_google_mitm_buckets = $lsPublicWithoutGoogleMitmBuckets.Count
                coverage_google_ratio = $coverageGoogle
            }
        })
}
if ($overlapSeconds -le 0) {
    $findings.Add([ordered]@{
            code = "NO_TIME_OVERLAP"
            severity = "warning"
            message = "MITM capture and LS connection trace do not overlap in time; correlation confidence is low."
        })
}

$ptrCache = @{}
$topRemoteIps = Convert-TopMap -Map $lsRemoteIpCounts -Limit $Top
if ($ResolvePtr) {
    foreach ($item in $topRemoteIps) {
        $ip = [string]$item.name
        if ($ip -and $ip -ne "<unknown-ip>") {
            $ptr = Get-OptionalPtrHost -Ip $ip -Cache $ptrCache
            if ($ptr) { $item.ptr = $ptr }
        }
    }
}

$mitmStartIso = To-IsoOrNull -Value $mitmMinTs
$mitmEndIso = To-IsoOrNull -Value $mitmMaxTs
$lsStartIso = To-IsoOrNull -Value $lsMinTs
$lsEndIso = To-IsoOrNull -Value $lsMaxTs
$overlapStartIso = To-IsoOrNull -Value $overlapStart
$overlapEndIso = To-IsoOrNull -Value $overlapEnd

$report = [ordered]@{}
$report.schema_version = "gephyr_mitm_ls_timeline_correlation_v1"
$report.generated_at = (Get-Date).ToUniversalTime().ToString("o")

$report.inputs = [ordered]@{}
$report.inputs.mitm_path = $mitmAbs
$report.inputs.connections_csv_path = $connAbs
$report.inputs.bucket_seconds = $BucketSeconds
$report.inputs.include_loopback = $IncludeLoopback.IsPresent
$report.inputs.proxy_port = $ProxyPort
$report.inputs.resolve_ptr = $ResolvePtr.IsPresent

$report.ranges = [ordered]@{}
$report.ranges.mitm_start_utc = $mitmStartIso
$report.ranges.mitm_end_utc = $mitmEndIso
$report.ranges.ls_start_utc = $lsStartIso
$report.ranges.ls_end_utc = $lsEndIso
$report.ranges.overlap_start_utc = $overlapStartIso
$report.ranges.overlap_end_utc = $overlapEndIso
$report.ranges.overlap_seconds = $overlapSeconds

$report.totals = [ordered]@{}
$report.totals.mitm_records_total = $mitmCount
$report.totals.mitm_parse_errors = $mitmParseErrors
$report.totals.mitm_google_records = $mitmGoogleCount
$report.totals.mitm_cloudcode_records = $mitmCloudCodeCount
$report.totals.mitm_oauth_records = $mitmOauthCount
$report.totals.mitm_generation_records = $mitmGenerationCount
$report.totals.mitm_openai_chat_records = $mitmOpenAiCount
$report.totals.mitm_other_records = $mitmOtherCount
$report.totals.ls_rows_total_raw = $lsRowsRaw
$report.totals.ls_rows_scoped = $lsRowsScoped
$report.totals.ls_parse_errors = $lsParseErrors
$report.totals.ls_proxy_rows = $lsProxyRows

$report.overlap_metrics = [ordered]@{}
$report.overlap_metrics.overlap_bucket_count = $overlapBuckets.Count
$report.overlap_metrics.ls_public_bucket_count = $lsPublicBuckets.Count
$report.overlap_metrics.ls_proxy_bucket_count = $lsProxyBuckets.Count
$report.overlap_metrics.ls_public_with_any_mitm_bucket_count = $lsPublicWithAnyMitmBuckets.Count
$report.overlap_metrics.ls_public_with_google_mitm_bucket_count = $lsPublicWithGoogleMitmBuckets.Count
$report.overlap_metrics.ls_public_with_generation_bucket_count = $lsPublicWithGenerationBuckets.Count
$report.overlap_metrics.ls_public_without_any_mitm_bucket_count = $lsPublicWithoutMitmBuckets.Count
$report.overlap_metrics.ls_public_without_google_mitm_bucket_count = $lsPublicWithoutGoogleMitmBuckets.Count
$report.overlap_metrics.coverage_any_mitm = $coverageAny
$report.overlap_metrics.coverage_google_mitm = $coverageGoogle
$report.overlap_metrics.coverage_generation_mitm = $coverageGeneration

$report.top = [ordered]@{}
$report.top.mitm_hosts = (Convert-TopMap -Map $mitmHostCounts -Limit $Top)
$report.top.mitm_endpoints = (Convert-TopMap -Map $mitmEndpointCounts -Limit $Top)
$report.top.mitm_user_agents = (Convert-TopMap -Map $mitmUACounts -Limit $Top)
$report.top.ls_remote_ips = $topRemoteIps
$report.top.ls_remote_endpoints = (Convert-TopMap -Map $lsRemoteEndpointCounts -Limit $Top)

$report.generation_samples = @($generationSamples.ToArray())
$report.findings = @($findings.ToArray())
$report.timeline_buckets = @($timeline.ToArray())

$outJson = "$outBaseAbs.json"
$outText = "$outBaseAbs.txt"

$report | ConvertTo-Json -Depth 12 | Set-Content -Path $outJson -Encoding UTF8

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("MITM + Language Server Timeline Correlation")
$lines.Add("Generated: $($report.generated_at)")
$lines.Add("MITM JSONL: $mitmAbs")
$lines.Add("Connections CSV: $connAbs")
$lines.Add("")
$lines.Add("Totals:")
$lines.Add("  MITM records: $mitmCount (google=$mitmGoogleCount cloudcode=$mitmCloudCodeCount oauth=$mitmOauthCount generation=$mitmGenerationCount openai_chat=$mitmOpenAiCount)")
$lines.Add("  LS rows: raw=$lsRowsRaw scoped=$lsRowsScoped proxy_rows=$lsProxyRows")
$lines.Add("")
$lines.Add("Time ranges:")
$lines.Add("  MITM: $($report.ranges.mitm_start_utc) .. $($report.ranges.mitm_end_utc)")
$lines.Add("  LS  : $($report.ranges.ls_start_utc) .. $($report.ranges.ls_end_utc)")
$lines.Add("  Overlap seconds: $overlapSeconds")
$lines.Add("")
$lines.Add("Overlap metrics:")
$lines.Add("  ls_public_bucket_count=$($report.overlap_metrics.ls_public_bucket_count)")
$lines.Add("  ls_public_with_google_mitm_bucket_count=$($report.overlap_metrics.ls_public_with_google_mitm_bucket_count)")
$lines.Add("  ls_public_with_generation_bucket_count=$($report.overlap_metrics.ls_public_with_generation_bucket_count)")
$lines.Add("  coverage_google_mitm=$($report.overlap_metrics.coverage_google_mitm)")
$lines.Add("  coverage_generation_mitm=$($report.overlap_metrics.coverage_generation_mitm)")
$lines.Add("")
$lines.Add("Top MITM hosts:")
foreach ($h in $report.top.mitm_hosts) {
    $lines.Add("  $($h.name) ($($h.count))")
}
$lines.Add("")
$lines.Add("Top LS remote IPs:")
foreach ($ip in $report.top.ls_remote_ips) {
    if ($ip.ptr) {
        $lines.Add("  $($ip.name) ($($ip.count)) ptr=$($ip.ptr)")
    } else {
        $lines.Add("  $($ip.name) ($($ip.count))")
    }
}
$lines.Add("")
$lines.Add("Findings:")
if ($report.findings.Count -eq 0) {
    $lines.Add("  (none)")
} else {
    foreach ($f in $report.findings) {
        $lines.Add("  [$($f.severity)] $($f.code): $($f.message)")
    }
}

$lines | Set-Content -Path $outText -Encoding UTF8

Write-Host "Correlation report written:"
Write-Host "  $outJson"
Write-Host "  $outText"
