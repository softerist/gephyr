param(
    [int]$Port = 8879,
    [string]$OutBase = "",
    [string]$ProcessName = "language_server_windows_x64",
    [int]$PollIntervalMs = 500,
    [int]$PktSize = 0,
    [int]$MaxFileSizeMb = 512,
    [switch]$NoPktmon,
    [switch]$NoConnectionPoll
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-TimestampTag {
    return (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
}

function Safe-StopPktmon {
    try { & pktmon stop | Out-Null } catch { }
}

function Start-PktmonCapture {
    param(
        [string]$EtlPath,
        [int]$PktSize,
        [int]$MaxFileSizeMb
    )

    # Capture 443 for both TCP (TLS) and UDP (QUIC/HTTP3). Many Google endpoints prefer QUIC.
    & pktmon filter remove | Out-Null
    & pktmon filter add "tcp443" -t TCP -p 443 | Out-Null
    & pktmon filter add "udp443" -t UDP -p 443 | Out-Null

    & pktmon start --capture --pkt-size $PktSize --flags 0x032 --file-name $EtlPath --file-size $MaxFileSizeMb --log-mode circular | Out-Null
}

function Convert-EtlToPcapng {
    param(
        [string]$EtlPath,
        [string]$PcapngPath
    )
    & pktmon etl2pcap $EtlPath -o $PcapngPath | Out-Null
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

        "timestamp_utc,owning_process,local_address,local_port,remote_address,remote_port,state" | Out-File -FilePath $OutCsv -Encoding ascii
        while ($true) {
            $ts = (Get-Date).ToUniversalTime().ToString("o")
            Get-NetTCPConnection -OwningProcess $ProcId -State Established |
                Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State |
                ForEach-Object {
                    "$ts,$($_.OwningProcess),$($_.LocalAddress),$($_.LocalPort),$($_.RemoteAddress),$($_.RemotePort),$($_.State)"
                } | Out-File -FilePath $OutCsv -Append -Encoding ascii
            Start-Sleep -Milliseconds $PollIntervalMs
        }
    }

    return Start-Job -ScriptBlock $script -ArgumentList @($ProcId, $OutCsv, $PollIntervalMs)
}

Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Test-IsAdmin)) {
    throw "This script must be run from an elevated PowerShell (Run as Administrator). pktmon requires admin."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $repoRoot "output"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

if (-not $OutBase) {
    $OutBase = Join-Path $outputDir ("antigravity_chat_nettrace_" + (Get-TimestampTag))
} elseif (-not [IO.Path]::IsPathRooted($OutBase)) {
    # Make OutBase stable across background jobs whose working directory may differ.
    $OutBase = Join-Path $repoRoot $OutBase
}

$etl = "$OutBase.pktmon.etl"
$pcapng = "$OutBase.pktmon.pcapng"
$connCsv = "$OutBase.$ProcessName.connections.csv"

$lsPid = $null
try {
    $p = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p) { $lsPid = $p.Id }
} catch { }

Write-Host "Tracing Antigravity Agent chat network traffic (OS-level)."
Write-Host "Process to correlate: $ProcessName" + ($(if ($lsPid) { " (pid=$lsPid)" } else { " (not running yet)" }))
Write-Host "Outputs:"
Write-Host "  $etl"
Write-Host "  $pcapng"
Write-Host "  $connCsv"
Write-Host ""
Write-Host "Steps:"
Write-Host "1) Script will start pktmon capture (TCP/443)."
Write-Host "2) Trigger Antigravity Agent chat activity (send a message, wait for response)."
Write-Host "3) Press Enter here to stop capture and write outputs."
Write-Host ""

$pollJob = $null

try {
    if (-not $NoPktmon) {
        Safe-StopPktmon
        Start-PktmonCapture -EtlPath $etl -PktSize $PktSize -MaxFileSizeMb $MaxFileSizeMb
        Write-Host "pktmon capture started."
    } else {
        Write-Warning "Skipping pktmon capture (-NoPktmon)."
    }

    if (-not $NoConnectionPoll) {
        if (-not $lsPid) {
            Write-Host "Waiting for $ProcessName to start..."
            $deadline = (Get-Date).AddSeconds(30)
            while (-not $lsPid -and (Get-Date) -lt $deadline) {
                $p = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($p) { $lsPid = $p.Id; break }
                Start-Sleep -Milliseconds 500
            }
        }

        if ($lsPid) {
            $pollJob = Start-ConnectionPollerJob -ProcId $lsPid -OutCsv $connCsv -PollIntervalMs $PollIntervalMs
            Write-Host "Connection poller started for pid=$lsPid."
        } else {
            Write-Warning "Could not find $ProcessName to poll connections. (Start Antigravity, then re-run.)"
        }
    } else {
        Write-Warning "Skipping connection poll (-NoConnectionPoll)."
    }

    [void](Read-Host "Press Enter when done")
}
finally {
    if ($pollJob) {
        try { Stop-Job $pollJob -Force | Out-Null } catch { }
        try { Remove-Job $pollJob -Force | Out-Null } catch { }
        Write-Host "Connection poller stopped."
    }

    if (-not $NoPktmon) {
        Safe-StopPktmon
        Write-Host "pktmon stopped."
        try {
            Convert-EtlToPcapng -EtlPath $etl -PcapngPath $pcapng
            Write-Host "Converted to pcapng: $pcapng"
        } catch {
            Write-Warning "Failed to convert ETL to PCAPNG: $($_.Exception.Message)"
        }
    }
}

Write-Host ""
Write-Host "Next:"
Write-Host "- Open the .pcapng in Wireshark and filter for TLS ClientHello to extract SNI (server names)."
Write-Host "  Example Wireshark display filter: tls.handshake.type == 1"
Write-Host "- Use the connections CSV to correlate which remote IPs belong to $ProcessName."
