param(
    [string]$PythonSpec = "3.12",
    [switch]$SkipInstall,
    [switch]$NoPathPersist
)

$ErrorActionPreference = "Stop"

function Require-PyLauncher {
    if (-not (Get-Command "py" -ErrorAction SilentlyContinue)) {
        throw "Python launcher 'py' was not found. Install Python for Windows first."
    }
}

function Invoke-Python {
    param(
        [Parameter(Mandatory = $true)][string[]]$Args
    )
    $output = & py @Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        $joined = $Args -join " "
        throw "Command failed: py $joined`n$output"
    }
    return $output
}

function Get-UserScriptsPath {
    param([string]$Version)

    $script = "import sysconfig; print(sysconfig.get_path('scripts', scheme='nt_user'))"
    $out = Invoke-Python -Args @("-$Version", "-c", $script)
    $path = ($out | Select-Object -Last 1).Trim()
    if (-not $path) {
        throw "Could not resolve user Scripts path for Python $Version."
    }
    return $path
}

function Add-PathSegment {
    param(
        [string]$Current,
        [string]$Segment
    )

    $parts = @()
    if ($Current) {
        $parts = $Current.Split(";") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }

    $exists = $false
    foreach ($p in $parts) {
        if ($p.TrimEnd("\") -ieq $Segment.TrimEnd("\")) {
            $exists = $true
            break
        }
    }

    if (-not $exists) {
        $parts += $Segment
    }

    return ($parts -join ";")
}

Require-PyLauncher

$pyVersionOut = Invoke-Python -Args @("-$PythonSpec", "-c", "import sys; print(sys.version)")
$pyVersion = ($pyVersionOut | Select-Object -Last 1).Trim()
Write-Host "Using Python $PythonSpec => $pyVersion"

if (-not $SkipInstall) {
    Write-Host "Installing/upgrading mitmproxy for Python $PythonSpec ..."
    Invoke-Python -Args @("-$PythonSpec", "-m", "pip", "install", "--user", "--upgrade", "mitmproxy") | Out-Null
}

$scriptsPath = Get-UserScriptsPath -Version $PythonSpec
$mitmdumpPath = Join-Path $scriptsPath "mitmdump.exe"
if (-not (Test-Path $mitmdumpPath)) {
    throw "mitmdump.exe not found at '$mitmdumpPath'. Re-run without -SkipInstall or verify pip install output."
}

$userPathBefore = [Environment]::GetEnvironmentVariable("Path", "User")
$userPathAfter = Add-PathSegment -Current $userPathBefore -Segment $scriptsPath
$sessionPathAfter = Add-PathSegment -Current $env:Path -Segment $scriptsPath

if (-not $NoPathPersist) {
    if ($userPathAfter -ne $userPathBefore) {
        [Environment]::SetEnvironmentVariable("Path", $userPathAfter, "User")
        Write-Host "Updated user PATH with: $scriptsPath"
    } else {
        Write-Host "User PATH already contains: $scriptsPath"
    }
} else {
    Write-Host "Skipped persistent PATH update (NoPathPersist)."
}

$env:Path = $sessionPathAfter
Write-Host "Updated current session PATH."

& $mitmdumpPath --version

Write-Host ""
Write-Host "Setup complete."
Write-Host "You can now run:"
Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/capture-known-good-mitmproxy.ps1 -TrustCert"
