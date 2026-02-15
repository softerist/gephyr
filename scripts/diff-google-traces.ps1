param(
    [string]$GephyrPath = "output/gephyr_google_outbound_headers.jsonl",
    [Parameter(Mandatory = $true)]
    [string]$KnownGoodPath,
    [string]$OutJson = "output/google_trace_diff_report.json",
    [string]$OutText = "output/google_trace_diff_report.txt",
    [string[]]$IgnoreHeaders = @("content-length"),
    [switch]$IgnoreConnectionHeader
    ,
    [switch]$IgnoreDeviceHeaders
)

$ErrorActionPreference = "Stop"

function Get-JsonlRecords {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "File not found: $Path"
    }

    $records = @()
    foreach ($line in Get-Content -Path $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        $records += ($trimmed | ConvertFrom-Json)
    }
    return $records
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

function Is-NoiseEndpoint {
    param([string]$Endpoint)
    if (-not $Endpoint) { return $false }
    return $Endpoint -match '(?i)^https?://oauth2\.googleapis\.com/tokeninfo(?:\?|$)'
}

function Get-HarRecords {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "File not found: $Path"
    }

    $har = Get-Content -Path $Path -Raw | ConvertFrom-Json
    $records = @()
    foreach ($entry in $har.log.entries) {
        if (-not $entry.request.url) { continue }
        $headers = @{}
        foreach ($h in $entry.request.headers) {
            if (-not $h.name) { continue }
            $name = [string]$h.name
            $value = [string]$h.value
            $headers[$name.ToLowerInvariant()] = $value
        }

        $record = [pscustomobject]@{
            timestamp = $entry.startedDateTime
            endpoint  = [string]$entry.request.url
            mode      = "known_good"
            headers   = $headers
        }
        if (Is-GoogleEndpoint -Endpoint $record.endpoint) {
            $records += $record
        }
    }
    return $records
}

function Get-SazRecords {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "File not found: $Path"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $Path))
    try {
        $records = @()
        $requestEntries = $zip.Entries | Where-Object { $_.FullName -like "raw/*_c.txt" }
        foreach ($entry in $requestEntries) {
            $stream = $entry.Open()
            try {
                $reader = [System.IO.StreamReader]::new($stream)
                $text = $reader.ReadToEnd()
                $reader.Dispose()
            } finally {
                $stream.Dispose()
            }

            $lines = $text -split "`r?`n"
            if ($lines.Count -eq 0) { continue }
            $first = $lines[0].Trim()
            if (-not $first) { continue }

            $m = [regex]::Match($first, '^(?<method>[A-Z]+)\s+(?<target>\S+)\s+HTTP/\d+\.\d+$')
            if (-not $m.Success) { continue }
            $method = $m.Groups["method"].Value
            $target = $m.Groups["target"].Value

            if ($method -eq "CONNECT") {
                continue
            }

            $headers = @{}
            for ($i = 1; $i -lt $lines.Count; $i++) {
                $line = $lines[$i]
                if ([string]::IsNullOrWhiteSpace($line)) {
                    break
                }
                $hm = [regex]::Match($line, '^(?<name>[^:]+):\s*(?<value>.*)$')
                if ($hm.Success) {
                    $name = $hm.Groups["name"].Value.Trim().ToLowerInvariant()
                    $value = $hm.Groups["value"].Value.Trim()
                    $headers[$name] = $value
                }
            }

            $endpoint = $target
            if (-not ($endpoint -match '^https?://')) {
                $host = $headers["host"]
                if ($host -and $endpoint.StartsWith("/")) {
                    $scheme = if ($host -match ':\s*443$') { "https" } else { "http" }
                    $endpoint = "${scheme}://$host$endpoint"
                }
            }

            if (-not (Is-GoogleEndpoint -Endpoint $endpoint)) {
                continue
            }

            $records += [pscustomobject]@{
                timestamp = $null
                endpoint  = $endpoint
                mode      = "known_good"
                headers   = $headers
            }
        }

        return $records
    } finally {
        $zip.Dispose()
    }
}

function Load-TraceRecords {
    param([string]$Path)
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -eq ".har") {
        return Get-HarRecords -Path $Path
    }
    if ($ext -eq ".saz") {
        return Get-SazRecords -Path $Path
    }
    return Get-JsonlRecords -Path $Path
}

function New-NormalizedHeaderIgnoreSet {
    param(
        [string[]]$IgnoreHeaders,
        [bool]$IncludeConnection,
        [bool]$IncludeDevice
    )
    $set = New-Object System.Collections.Generic.HashSet[string]
    foreach ($h in $IgnoreHeaders) {
        if (-not $h) { continue }
        [void]$set.Add($h.Trim().ToLowerInvariant())
    }
    if ($IncludeConnection) {
        [void]$set.Add("connection")
    }
    if ($IncludeDevice) {
        foreach ($h in @("x-machine-id","x-mac-machine-id","x-dev-device-id","x-sqm-id")) {
            [void]$set.Add($h)
        }
    }
    return $set
}

function Get-EndpointStats {
    param([object[]]$Records)
    $byEndpoint = @{}
    foreach ($r in $Records) {
        $endpoint = Normalize-Endpoint -Endpoint ([string]$r.endpoint)
        if (-not $endpoint) { continue }
        if (Is-NoiseEndpoint -Endpoint $endpoint) { continue }
        if (-not $byEndpoint.ContainsKey($endpoint)) {
            $byEndpoint[$endpoint] = [pscustomobject]@{
                count = 0
                headers = (New-Object System.Collections.Generic.HashSet[string])
            }
        }
        $byEndpoint[$endpoint].count += 1

        $headers = $r.headers
        if ($headers -is [System.Collections.IDictionary]) {
            foreach ($k in $headers.Keys) {
                [void]$byEndpoint[$endpoint].headers.Add(([string]$k).ToLowerInvariant())
            }
        } else {
            foreach ($prop in $headers.PSObject.Properties.Name) {
                [void]$byEndpoint[$endpoint].headers.Add(([string]$prop).ToLowerInvariant())
            }
        }
    }
    return $byEndpoint
}

function Get-BlockedHeaders {
    param([string[]]$HeaderNames)
    $blocked = @()
    foreach ($h in $HeaderNames) {
        if (
            $h -like "sec-*" -or
            $h -eq "origin" -or
            $h -eq "referer" -or
            $h -eq "cookie" -or
            $h -like "x-forwarded-*" -or
            $h -eq "x-real-ip" -or
            $h -eq "connection" -or
            $h -eq "transfer-encoding" -or
            $h -eq "upgrade" -or
            $h -eq "keep-alive" -or
            $h -eq "proxy-authenticate" -or
            $h -eq "proxy-authorization" -or
            $h -eq "te" -or
            $h -eq "trailers"
        ) {
            $blocked += $h
        }
    }
    return ($blocked | Sort-Object -Unique)
}

$gephyr = Load-TraceRecords -Path $GephyrPath
$known = Load-TraceRecords -Path $KnownGoodPath
$knownIsEmpty = ($known.Count -eq 0)
if ($knownIsEmpty) {
    Write-Warning "No Google HTTP requests were parsed from '$KnownGoodPath'. If this is a Fiddler SAZ, enable HTTPS decryption so requests are captured beyond CONNECT tunnels."
}

$ignoreSet = New-NormalizedHeaderIgnoreSet -IgnoreHeaders $IgnoreHeaders -IncludeConnection:$IgnoreConnectionHeader -IncludeDevice:$IgnoreDeviceHeaders

$gephyrByEndpoint = Get-EndpointStats -Records $gephyr
$knownByEndpoint = Get-EndpointStats -Records $known

$allEndpoints = @($gephyrByEndpoint.Keys + $knownByEndpoint.Keys | Sort-Object -Unique)
$endpointComparisons = @()

foreach ($endpoint in $allEndpoints) {
    $gephyrHeaders = @()
    $knownHeaders = @()
    $gephyrCount = 0
    $knownCount = 0
    if ($gephyrByEndpoint.ContainsKey($endpoint)) {
        $gephyrCount = [int]$gephyrByEndpoint[$endpoint].count
        $gephyrHeaders = @($gephyrByEndpoint[$endpoint].headers | Sort-Object)
    }
    if ($knownByEndpoint.ContainsKey($endpoint)) {
        $knownCount = [int]$knownByEndpoint[$endpoint].count
        $knownHeaders = @($knownByEndpoint[$endpoint].headers | Sort-Object)
    }

    $knownHeadersCompared = @($knownHeaders | Where-Object { -not $ignoreSet.Contains($_) } | Sort-Object)
    $gephyrHeadersCompared = @($gephyrHeaders | Where-Object { -not $ignoreSet.Contains($_) } | Sort-Object)

    $missingInGephyr = @($knownHeadersCompared | Where-Object { $_ -notin $gephyrHeadersCompared } | Sort-Object)
    $extraInGephyr = @($gephyrHeadersCompared | Where-Object { $_ -notin $knownHeadersCompared } | Sort-Object)
    $blockedInGephyr = Get-BlockedHeaders -HeaderNames $gephyrHeaders

    $classification = "matched_or_extra_only"
    if ($knownCount -gt 0 -and $gephyrCount -eq 0) {
        $classification = "missing_endpoint_not_exercised"
    } elseif ($knownCount -gt 0 -and $gephyrCount -gt 0 -and $missingInGephyr.Count -gt 0) {
        $classification = "missing_headers_on_exercised_endpoint"
    } elseif ($knownCount -eq 0 -and $gephyrCount -gt 0) {
        $classification = "extra_endpoint_in_gephyr"
    }

    # If the endpoint was not present in known-good, listing "extra" headers is misleading noise
    # (it just reflects that there was no baseline). Keep header inventories in JSON, but
    # suppress the derived extra/missing lists for clarity.
    if ($classification -eq "extra_endpoint_in_gephyr") {
        $missingInGephyr = @()
        $extraInGephyr = @()
    }

    $endpointComparisons += [pscustomobject]@{
        endpoint           = $endpoint
        classification     = $classification
        known_request_count = $knownCount
        gephyr_request_count = $gephyrCount
        known_header_names = $knownHeaders
        gephyr_header_names = $gephyrHeaders
        missing_in_gephyr  = $missingInGephyr
        extra_in_gephyr    = $extraInGephyr
        blocked_in_gephyr  = $blockedInGephyr
    }
}

$classificationSummary = $endpointComparisons |
    Group-Object classification |
    Sort-Object Name |
    ForEach-Object {
        [pscustomobject]@{
            classification = $_.Name
            count = $_.Count
        }
    }

$report = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    gephyr_path = $GephyrPath
    known_good_path = $KnownGoodPath
    gephyr_records = $gephyr.Count
    known_good_records = $known.Count
    endpoint_count = $allEndpoints.Count
    ignored_headers = @($ignoreSet | Sort-Object)
    classification_summary = $classificationSummary
    endpoints = $endpointComparisons
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutJson

$lines = @()
$lines += "Google Trace Diff Report"
$lines += "Generated: $($report.generated_at)"
$lines += "Gephyr records: $($report.gephyr_records)"
$lines += "Known-good records: $($report.known_good_records)"
$lines += "Endpoints compared: $($report.endpoint_count)"
$lines += "Ignored headers in diff: $((@($report.ignored_headers) -join ', '))"
$lines += "Classification summary:"
foreach ($c in $classificationSummary) {
    $lines += "  $($c.classification): $($c.count)"
}
$lines += ""
if ($knownIsEmpty) {
    $lines += "WARNING: No known-good Google HTTP requests were parsed."
    $lines += "For Fiddler SAZ captures, enable HTTPS decryption and re-capture."
    $lines += ""
}
$lines += ""
foreach ($e in $endpointComparisons) {
    $lines += "Endpoint: $($e.endpoint)"
    $lines += "  classification: $($e.classification)"
    $lines += "  exercised_known_good: $($e.known_request_count)"
    $lines += "  exercised_gephyr: $($e.gephyr_request_count)"
    if ($e.classification -eq "extra_endpoint_in_gephyr") {
        $lines += "  missing_in_gephyr: "
        $lines += "  extra_in_gephyr: "
        $lines += "  note: endpoint not present in known-good capture; recapture known-good to diff headers."
    } else {
        $lines += "  missing_in_gephyr: $((@($e.missing_in_gephyr) -join ', '))"
        $lines += "  extra_in_gephyr: $((@($e.extra_in_gephyr) -join ', '))"
    }
    $lines += "  blocked_in_gephyr: $((@($e.blocked_in_gephyr) -join ', '))"
    $lines += ""
}
$lines | Set-Content -Path $OutText

Write-Output "Saved JSON report: $OutJson"
Write-Output "Saved text report: $OutText"
