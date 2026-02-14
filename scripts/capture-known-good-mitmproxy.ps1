param(
    [int]$Port = 8877,
    [string]$HarPath = "output/known_good.har",
    [string]$GephyrPath = "output/gephyr_google_outbound_headers.jsonl",
    [string]$MitmdumpPath = "",
    [switch]$TrustCert,
    [switch]$SkipDiff
)

$ErrorActionPreference = "Stop"

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

    throw "Could not find mitmdump.exe. Install mitmproxy first: py -3.12 -m pip install --user mitmproxy"
}

$mitmdumpExe = Resolve-Mitmdump -OverridePath $MitmdumpPath

if (-not (Test-Path "output")) {
    New-Item -ItemType Directory -Path "output" | Out-Null
}

$harAbs = if ([System.IO.Path]::IsPathRooted($HarPath)) { $HarPath } else { Join-Path (Get-Location) $HarPath }
$harDir = Split-Path -Parent $harAbs
if ($harDir -and -not (Test-Path $harDir)) {
    New-Item -ItemType Directory -Path $harDir | Out-Null
}

if (Test-Path $harAbs) {
    Remove-Item $harAbs -Force
}

$filter = "~d (oauth2\\.googleapis\\.com|cloudcode-pa\\.googleapis\\.com)"
$args = @(
    "--listen-host", "127.0.0.1",
    "--listen-port", "$Port",
    "--set", "hardump=$harAbs",
    "--set", "save_stream_filter=$filter",
    "--set", "block_global=false",
    "--quiet"
)

Write-Host "Starting mitmdump on 127.0.0.1:$Port ..."
$proc = Start-Process -FilePath $mitmdumpExe -ArgumentList $args -PassThru

try {
    Start-Sleep -Milliseconds 700
    if ($proc.HasExited) {
        throw "mitmdump exited early. Check mitmdump availability/version."
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
    Write-Host "3) Trigger baseline flows: login/refresh + loadCodeAssist + fetch models + generate/stream"
    Write-Host ""
    Read-Host "Press Enter when capture is complete"
}
finally {
    if ($proc -and -not $proc.HasExited) {
        Write-Host "Stopping mitmdump ..."
        Stop-Process -Id $proc.Id -Force
    }
}

if (-not (Test-Path $harAbs)) {
    throw "HAR was not produced at: $harAbs"
}

Write-Host "HAR saved: $harAbs"

if (-not $SkipDiff) {
    if (-not (Test-Path $GephyrPath)) {
        throw "Gephyr capture JSONL missing: $GephyrPath"
    }
    Write-Host "Running diff against Gephyr capture ..."
    & "$PSScriptRoot\diff-google-traces.ps1" -GephyrPath $GephyrPath -KnownGoodPath $harAbs
    Write-Host "Done. See:"
    Write-Host "  output/google_trace_diff_report.txt"
    Write-Host "  output/google_trace_diff_report.json"
}
