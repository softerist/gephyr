param(
    [Parameter(Mandatory = $true)]
    [string]$TracePath,
    [string]$AllowlistPath = "scripts/allowlists/antigravity_google_endpoints_default_chat.txt",
    [string]$OutJson = "output/antigravity_allowed_endpoint_validation.json",
    [string]$OutText = "output/antigravity_allowed_endpoint_validation.txt",
    [switch]$NoThrow
)

$ErrorActionPreference = "Stop"

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

if (-not (Test-Path $TracePath)) {
    throw "Trace file not found: $TracePath"
}
if (-not (Test-Path $AllowlistPath)) {
    throw "Allowlist file not found: $AllowlistPath"
}

$allowedRaw = Get-Content $AllowlistPath |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith("#") }

$allowed = New-Object System.Collections.Generic.HashSet[string]
foreach ($e in $allowedRaw) {
    [void]$allowed.Add((Normalize-Endpoint -Endpoint $e))
}

$observedAll = New-Object System.Collections.Generic.HashSet[string]
$observedGoogle = New-Object System.Collections.Generic.HashSet[string]

foreach ($line in Get-Content $TracePath) {
    $trim = $line.Trim()
    if (-not $trim) { continue }
    $obj = $null
    try {
        $obj = $trim | ConvertFrom-Json
    } catch {
        continue
    }
    $ep = [string]$obj.endpoint
    if (-not $ep) { continue }
    $norm = Normalize-Endpoint -Endpoint $ep
    [void]$observedAll.Add($norm)
    if (Is-GoogleEndpoint -Endpoint $norm) {
        [void]$observedGoogle.Add($norm)
    }
}

# Ignore capture self-test noise if present.
[void]$observedGoogle.Remove((Normalize-Endpoint -Endpoint "https://oauth2.googleapis.com/tokeninfo?access_token=%3Credacted%3E"))

$unknown = @($observedGoogle | Where-Object { -not $allowed.Contains($_) } | Sort-Object)
$missing = @($allowed | Where-Object { $_ -notin $observedGoogle } | Sort-Object)
$observedAllowed = @($observedGoogle | Where-Object { $allowed.Contains($_) } | Sort-Object)

$result = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    trace_path = $TracePath
    allowlist_path = $AllowlistPath
    allowed_count = $allowed.Count
    observed_google_count = $observedGoogle.Count
    observed_allowed_count = $observedAllowed.Count
    unknown_google_endpoints = $unknown
    missing_allowed_endpoints = $missing
    observed_allowed_endpoints = $observedAllowed
    pass = ($unknown.Count -eq 0)
}

$result | ConvertTo-Json -Depth 8 | Set-Content -Path $OutJson

$lines = @()
$lines += "Antigravity Allowed Google Endpoint Validation"
$lines += "Generated: $($result.generated_at)"
$lines += "Trace: $TracePath"
$lines += "Allowlist: $AllowlistPath"
$lines += "Allowed endpoints: $($result.allowed_count)"
$lines += "Observed Google endpoints: $($result.observed_google_count)"
$lines += "Observed allowed endpoints: $($result.observed_allowed_count)"
$lines += "Pass: $($result.pass)"
$lines += ""
$lines += "Unknown Google endpoints:"
if ($unknown.Count -eq 0) {
    $lines += "  (none)"
} else {
    $unknown | ForEach-Object { $lines += "  $_" }
}
$lines += ""
$lines += "Missing allowlist endpoints (informational):"
if ($missing.Count -eq 0) {
    $lines += "  (none)"
} else {
    $missing | ForEach-Object { $lines += "  $_" }
}

$lines | Set-Content -Path $OutText

Write-Host "Validation report written:"
Write-Host "  $OutText"
Write-Host "  $OutJson"
Write-Host "Pass: $($result.pass)"

if (-not $NoThrow -and -not $result.pass) {
    throw "Unexpected Google endpoints detected. See: $OutText"
}
