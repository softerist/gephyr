<#
.SYNOPSIS
Attributes TLS SNI values to language_server_windows_x64 remote IPs.

.DESCRIPTION
Combines:
- Packet capture (.pcapng) containing TLS ClientHello SNI fields
- LS connection poll CSV (from trace-antigravity-chat-network.ps1)

Outputs a JSON and text report with:
- LS remote IP frequencies (:443, non-loopback)
- SNI counts observed on those IPs
- IP+SNI pair counts
- LS IPs with no observed SNI in capture
#>
param(
    [Parameter(Mandatory = $true)][string]$PcapPath,
    [Parameter(Mandatory = $true)][string]$ConnectionsCsvPath,
    [string]$OutBase = "output/parity/official/ls_sni_attribution",
    [int]$Top = 50,
    [switch]$ResolvePtr
)

$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    try {
        $gitRoot = (& git rev-parse --show-toplevel 2>$null | Select-Object -First 1)
        if ($gitRoot) { return (Resolve-Path $gitRoot.Trim()).Path }
    } catch {}
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Resolve-InputPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )
    $candidate = $Path
    if (-not [IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $RepoRoot $candidate
    }
    if (Test-Path -LiteralPath $candidate) {
        return (Resolve-Path -LiteralPath $candidate).Path
    }
    if ($candidate -match '[*?\[]') {
        $matches = @(Get-ChildItem -Path $candidate -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending)
        if ($matches.Count -gt 0) { return $matches[0].FullName }
    }
    throw "Input not found: $Path"
}

function Resolve-TsharkPath {
    $cmd = Get-Command tshark -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }
    $candidates = @(
        (Join-Path $env:ProgramFiles "Wireshark\tshark.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Wireshark\tshark.exe")
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return (Resolve-Path $c).Path }
    }
    return $null
}

function Resolve-OutBase {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )
    if ([IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $RepoRoot $Path)
}

function Group-Top {
    param(
        $Items,
        [int]$Limit = 50
    )
    if ($null -eq $Items) { return @() }
    return @(
        $Items |
        Group-Object |
        Sort-Object Count -Descending |
        Select-Object -First $Limit |
        ForEach-Object {
            [ordered]@{
                count = $_.Count
                name = $_.Name
            }
        }
    )
}

function Resolve-PtrHost {
    param([string]$Ip)
    if (-not $Ip) { return $null }
    try {
        $entry = [System.Net.Dns]::GetHostEntry($Ip)
        if ($entry -and $entry.HostName) { return [string]$entry.HostName }
    } catch {}
    return $null
}

$repoRoot = Resolve-RepoRoot
$pcapAbs = Resolve-InputPath -Path $PcapPath -RepoRoot $repoRoot
$csvAbs = Resolve-InputPath -Path $ConnectionsCsvPath -RepoRoot $repoRoot
$outBaseAbs = Resolve-OutBase -Path $OutBase -RepoRoot $repoRoot
$outDir = Split-Path -Parent $outBaseAbs
if ($outDir) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

$tshark = Resolve-TsharkPath
if (-not $tshark) {
    throw "tshark not found. Install Wireshark/tshark first."
}

Write-Host "Using tshark: $tshark"
Write-Host "PCAP: $pcapAbs"
Write-Host "CSV:  $csvAbs"

$lsRows = Import-Csv -Path $csvAbs | Where-Object {
    $_.remote_address -ne "127.0.0.1" -and [int]$_.remote_port -eq 443
}
$lsIpGroups = @($lsRows | Group-Object remote_address | Sort-Object Count -Descending)
$lsIpSet = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($g in $lsIpGroups) { [void]$lsIpSet.Add([string]$g.Name) }

$tlsLines = & $tshark -r $pcapAbs -Y "tls.handshake.extensions_server_name" -T fields -E "separator=," -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>$null
$rows = New-Object System.Collections.Generic.List[object]
foreach ($line in $tlsLines) {
    if (-not $line) { continue }
    $parts = $line.Split(",", 4)
    if ($parts.Count -lt 4) { continue }
    $dstIp = [string]$parts[2]
    $sni = [string]$parts[3]
    if (-not $sni) { continue }
    if (-not $lsIpSet.Contains($dstIp)) { continue }
    $rows.Add([pscustomobject]@{
            dst_ip = $dstIp
            sni = $sni
        })
}

$sniTop = Group-Top -Items ($rows | ForEach-Object { $_.sni }) -Limit $Top
$ipTop = @(
    $lsIpGroups | Select-Object -First $Top | ForEach-Object {
        [ordered]@{
            count = $_.Count
            ip = $_.Name
        }
    }
)
$ipSniTop = Group-Top -Items ($rows | ForEach-Object { "{0}, {1}" -f $_.dst_ip, $_.sni }) -Limit $Top

$sniIps = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($r in $rows) { [void]$sniIps.Add([string]$r.dst_ip) }
$ipsWithoutSni = @($lsIpGroups | Where-Object { -not $sniIps.Contains([string]$_.Name) } | ForEach-Object { $_.Name })

$report = [ordered]@{
    schema_version = "gephyr_ls_sni_attribution_v1"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    inputs = [ordered]@{
        pcap_path = $pcapAbs
        connections_csv_path = $csvAbs
    }
    totals = [ordered]@{
        ls_connection_rows_scoped = $lsRows.Count
        ls_unique_remote_ips = $lsIpGroups.Count
        tls_clienthello_sni_rows_on_ls_ips = $rows.Count
        ls_ips_without_observed_sni = $ipsWithoutSni.Count
    }
    top = [ordered]@{
        ls_remote_ips = $ipTop
        sni = $sniTop
        ip_sni_pairs = $ipSniTop
    }
    ls_ips_without_sni = $ipsWithoutSni
}

if ($ResolvePtr) {
    $ptrRows = @()
    foreach ($ipEntry in $ipTop) {
        $ptrRows += [ordered]@{
            ip = $ipEntry.ip
            ptr = Resolve-PtrHost -Ip $ipEntry.ip
        }
    }
    $report.ptr = $ptrRows
}

$outJson = "$outBaseAbs.json"
$outText = "$outBaseAbs.txt"

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $outJson -Encoding UTF8

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("LS SNI Attribution")
$lines.Add("Generated: $($report.generated_at)")
$lines.Add("PCAP: $pcapAbs")
$lines.Add("CSV:  $csvAbs")
$lines.Add("")
$lines.Add("Totals:")
$lines.Add("  ls_connection_rows_scoped=$($report.totals.ls_connection_rows_scoped)")
$lines.Add("  ls_unique_remote_ips=$($report.totals.ls_unique_remote_ips)")
$lines.Add("  tls_clienthello_sni_rows_on_ls_ips=$($report.totals.tls_clienthello_sni_rows_on_ls_ips)")
$lines.Add("  ls_ips_without_observed_sni=$($report.totals.ls_ips_without_observed_sni)")
$lines.Add("")
$lines.Add("Top LS remote IPs:")
foreach ($x in $report.top.ls_remote_ips) {
    $lines.Add("  $($x.count)  $($x.ip)")
}
$lines.Add("")
$lines.Add("Top SNI on LS IPs:")
foreach ($x in $report.top.sni) {
    $lines.Add("  $($x.count)  $($x.name)")
}
$lines.Add("")
$lines.Add("Top IP+SNI pairs:")
foreach ($x in $report.top.ip_sni_pairs) {
    $lines.Add("  $($x.count)  $($x.name)")
}
$lines.Add("")
$lines.Add("LS IPs without observed SNI:")
if ($report.ls_ips_without_sni.Count -eq 0) {
    $lines.Add("  (none)")
} else {
    foreach ($ip in $report.ls_ips_without_sni) {
        $lines.Add("  $ip")
    }
}

$lines | Set-Content -Path $outText -Encoding UTF8

Write-Host "Attribution report written:"
Write-Host "  $outJson"
Write-Host "  $outText"
