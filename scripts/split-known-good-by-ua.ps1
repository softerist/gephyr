param(
    [string]$InPath = "output/known_good.jsonl",
    [string]$OutDir = "output/known_good_by_ua",
    [switch]$OnlyGoogle,
    [switch]$PrintSummaryOnly,
    [int]$MaxFiles = 50
)

$ErrorActionPreference = "Stop"

function Is-GoogleEndpoint {
    param([string]$Endpoint)
    if (-not $Endpoint) { return $false }
    return $Endpoint -match '(?i)^https?://[^/]*(googleapis\.com|google\.com)(?::\d+)?/'
}

function Sanitize-FileName {
    param([string]$Name)
    if (-not $Name) { return "unknown" }
    $s = $Name.Trim()
    if ($s.Length -gt 120) { $s = $s.Substring(0, 120) }
    # Replace characters that are illegal or annoying on Windows paths.
    $s = ($s -replace '[\\\\/:*?\"<>|]', '_')
    $s = ($s -replace '\\s+', ' ').Trim()
    if (-not $s) { return "unknown" }
    return $s
}

if (-not (Test-Path $InPath)) {
    throw "Input JSONL not found: $InPath"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$counts = @{}
$linesByUa = @{}

foreach ($line in Get-Content -Path $InPath) {
    $trimmed = [string]$line
    if (-not $trimmed.Trim()) { continue }
    $obj = $null
    try { $obj = $trimmed | ConvertFrom-Json } catch { continue }
    if (-not $obj) { continue }

    $endpoint = [string]$obj.endpoint
    if ($OnlyGoogle -and -not (Is-GoogleEndpoint -Endpoint $endpoint)) {
        continue
    }

    $ua = $null
    try { $ua = [string]$obj.headers.'user-agent' } catch {}
    if (-not $ua) { $ua = "<missing-user-agent>" }

    if (-not $counts.ContainsKey($ua)) { $counts[$ua] = 0 }
    $counts[$ua] += 1

    if (-not $linesByUa.ContainsKey($ua)) { $linesByUa[$ua] = New-Object System.Collections.Generic.List[string] }
    $linesByUa[$ua].Add($trimmed)
}

$summary = $counts.GetEnumerator() |
    Sort-Object Value -Descending |
    Select-Object -First $MaxFiles |
    ForEach-Object {
        [pscustomobject]@{
            count = $_.Value
            user_agent = $_.Key
        }
    }

if ($PrintSummaryOnly) {
    $summary | Format-Table -AutoSize | Out-String | Write-Host
    return
}

$written = 0
foreach ($row in $summary) {
    $ua = [string]$row.user_agent
    $safe = Sanitize-FileName -Name $ua
    $out = Join-Path $OutDir ("known_good.ua.{0}.jsonl" -f $safe)
    $linesByUa[$ua] | Set-Content -Path $out -Encoding UTF8
    $written += 1
}

Write-Host "Wrote $written file(s) under: $OutDir"
Write-Host "Top user-agents:"
$summary | Format-Table -AutoSize | Out-String | Write-Host

