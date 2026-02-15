param(
    [Parameter(Mandatory = $true)]
    [string]$PcapPath,
    [int]$Top = 50
)

$ErrorActionPreference = "Stop"

function Resolve-TsharkPath {
    $cmd = Get-Command tshark -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidates = @(
        (Join-Path $env:ProgramFiles "Wireshark\\tshark.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Wireshark\\tshark.exe")
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) {
            # Normalize accidental double-backslashes in the constructed path.
            return ($c -replace "\\\\+", "\\")
        }
    }
    return $null
}

function Resolve-Pcaps {
    param([string]$PathOrGlob)

    # Expand wildcards ourselves so downstream tools always get concrete file paths.
    if ($PathOrGlob -match '[\\/]?[*?\\[]') {
        $items = Get-ChildItem -Path $PathOrGlob -File -ErrorAction Stop
        if (-not $items.Count) { throw "No files matched: $PathOrGlob" }
        return $items | Select-Object -ExpandProperty FullName
    }

    if (-not (Test-Path -LiteralPath $PathOrGlob)) {
        throw "PCAP not found: $PathOrGlob"
    }
    return @((Resolve-Path -LiteralPath $PathOrGlob).Path)
}

$pcaps = Resolve-Pcaps -PathOrGlob $PcapPath
$tshark = Resolve-TsharkPath

Write-Host "PCAP input: $PcapPath"
Write-Host ("Resolved files: {0}" -f $pcaps.Count)
foreach ($p in $pcaps) { Write-Host "  $p" }

if ($tshark) {
    Write-Host "Using tshark: $tshark"

    $all = @()
    foreach ($pcap in $pcaps) {
        Write-Host ""
        Write-Host "=== $pcap ==="

        # TLS SNI is in ClientHello (plaintext). QUIC Initial can also be decoded by tshark.
        $lines = & $tshark -r $pcap -Y "tls.handshake.extensions_server_name" -T fields -E "separator=," -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>$null

        $sn = @()
        foreach ($l in $lines) {
            if (-not $l) { continue }
            $parts = $l.Split(",", 3)
            if ($parts.Count -lt 3) { continue }
            $sni = $parts[2].Trim()
            if ($sni) { $sn += $sni }
        }

        if (-not $sn.Count) {
            Write-Warning "No SNI extracted for this file. Possible reasons: no TLS ClientHello captured, QUIC not decoded, or ECH in use."
            continue
        }

        Write-Host "Top SNI (this file):"
        $sn | Group-Object | Sort-Object Count -Descending | Select-Object -First $Top |
            ForEach-Object { "{0,6}  {1}" -f $_.Count, $_.Name }

        $all += $sn
    }

    if ($pcaps.Count -gt 1 -and $all.Count) {
        Write-Host ""
        Write-Host "=== Aggregated Top SNI (all files) ==="
        $all | Group-Object | Sort-Object Count -Descending | Select-Object -First $Top |
            ForEach-Object { "{0,6}  {1}" -f $_.Count, $_.Name }
    }

    exit 0
}

Write-Warning "tshark not found. Install Wireshark (include tshark) or add it to PATH."
Write-Host "Fallback: scanning binary for hostname-like strings (best-effort)."
Write-Host ""

$patterns = @(
    "[a-z0-9][a-z0-9.-]{1,253}\\.googleapis\\.com",
    "[a-z0-9][a-z0-9.-]{1,253}\\.google\\.com",
    "[a-z0-9][a-z0-9.-]{1,253}\\.gstatic\\.com",
    "[a-z0-9][a-z0-9.-]{1,253}\\.goog",
    "[a-z0-9][a-z0-9.-]{1,253}\\.openai\\.com",
    "[a-z0-9][a-z0-9.-]{1,253}\\.chatgpt\\.com",
    "[a-z0-9][a-z0-9.-]{1,253}\\.anthropic\\.com"
)

$hits = @()
foreach ($pcap in $pcaps) {
    foreach ($pat in $patterns) {
        $hits += (& rg -a -o -i $pat $pcap -S 2>$null)
    }
}

if (-not $hits.Count) {
    Write-Warning "No hostname-like strings found in fallback scan."
    exit 0
}

Write-Host "Top host-like strings:"
$hits | Group-Object | Sort-Object Count -Descending | Select-Object -First $Top |
    ForEach-Object { "{0,6}  {1}" -f $_.Count, $_.Name }

