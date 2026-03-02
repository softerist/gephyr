param(
    [string]$KnownGoodPath = "output/known_good.discovery.jsonl",
    [string]$KnownGoodScopedPath = "output/known_good.antigravity_scope.latest.jsonl",
    [string]$OutGephyrPath = "output/gephyr_google_outbound_headers.latest.jsonl",
    [string]$DiffJsonPath = "output/google_trace_diff_report.json",
    [string]$DiffTxtPath = "output/google_trace_diff_report.txt",
    [string]$AllowlistJsonPath = "output/antigravity_allowed_endpoint_validation.json",
    [string]$AllowlistTxtPath = "output/antigravity_allowed_endpoint_validation.txt",
    [string]$StatusJsonPath = "output/parity/master_validation.status.json",
    [string]$BaselineGateOut = "output/parity/master_validation.baseline_gate.report.json",
    [string]$MismatchGateOut = "output/parity/master_validation.mismatch_gate.report.json"
)

$ErrorActionPreference = "Stop"

function Remove-FileViaCmd {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $quoted = '"' + $Path + '"'
    cmd /c del /f /q $quoted > $null 2>&1
    return (-not (Test-Path -LiteralPath $Path))
}

function Resolve-PathSafe {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        if ($resolved) { return $resolved.Path }
    } catch {}
    return $null
}

$keep = @(
    (Resolve-PathSafe -Path $KnownGoodPath),
    (Resolve-PathSafe -Path $KnownGoodScopedPath),
    (Resolve-PathSafe -Path $OutGephyrPath),
    (Resolve-PathSafe -Path $DiffJsonPath),
    (Resolve-PathSafe -Path $DiffTxtPath),
    (Resolve-PathSafe -Path $AllowlistJsonPath),
    (Resolve-PathSafe -Path $AllowlistTxtPath),
    (Resolve-PathSafe -Path $StatusJsonPath),
    (Resolve-PathSafe -Path $BaselineGateOut),
    (Resolve-PathSafe -Path $MismatchGateOut)
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
    "output\parity\official\**\*.csv",
    "output\parity\master_validation.known_good.mismatch.jsonl"
)

$targets = New-Object System.Collections.Generic.List[string]
foreach ($pattern in $patterns) {
    foreach ($file in (Get-ChildItem -Path $pattern -File -Recurse -ErrorAction SilentlyContinue)) {
        if ($keep -contains $file.FullName) { continue }
        $targets.Add($file.FullName)
    }
}

$deleted = 0
foreach ($path in ($targets | Sort-Object -Unique)) {
    if (Remove-FileViaCmd -Path $path) {
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
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($file in (Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue)) {
        if ($keep -contains $file.FullName) { continue }
        if (Remove-FileViaCmd -Path $file.FullName) {
            $deleted++
        }
    }
}

Write-Output "Pruned artifacts: $deleted"
