<#
.SYNOPSIS
Verifies prompt-generation routes are disabled in a running Gephyr instance.

.DESCRIPTION
Sends authenticated POST requests to routes that should be disabled when
GEPHYR_DISABLE_PROMPT_ROUTES=true was set at startup. The script expects each
route to return 404/405 (not found / method not allowed).

Optionally scans a capture JSONL for upstream prompt-generation endpoints as
supplemental evidence.
#>
param(
    [string]$BaseUrl = "http://127.0.0.1:8045",
    [string]$ApiKey,
    [string]$Model = "gemini-3-flash",
    [string]$TracePath
)

$ErrorActionPreference = "Stop"

function Load-EnvLocal {
    param([string]$RepoRoot)
    $envFile = Join-Path $RepoRoot ".env.local"
    if (-not (Test-Path $envFile)) { return }
    foreach ($raw in Get-Content $envFile) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) { continue }
        $parts = $line.Split("=", 2)
        $name = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"').Trim("'")
        if ($name -and $value -and -not (Get-Item "Env:$name" -ErrorAction SilentlyContinue)) {
            Set-Item -Path "Env:$name" -Value $value
        }
    }
}

function Resolve-ApiKey {
    param([string]$Provided)
    if ($Provided) { return $Provided }
    if ($env:API_KEY) { return $env:API_KEY }
    if ($env:GEPHYR_API_KEY) { return $env:GEPHYR_API_KEY }

    $dataDir = if ($env:DATA_DIR -and $env:DATA_DIR.Trim()) {
        $env:DATA_DIR
    } else {
        Join-Path $env:USERPROFILE ".gephyr"
    }
    $configPath = Join-Path $dataDir "config.json"
    if (Test-Path $configPath) {
        try {
            $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
            if ($cfg.proxy.api_key) { return [string]$cfg.proxy.api_key }
        } catch {
        }
    }

    throw "API key not found. Pass -ApiKey or set API_KEY/GEPHYR_API_KEY."
}

function Invoke-PostJson {
    param(
        [string]$Url,
        [hashtable]$Headers,
        [hashtable]$Body
    )
    $json = $Body | ConvertTo-Json -Depth 20
    try {
        $resp = Invoke-WebRequest -Uri $Url -Method Post -Headers $Headers -Body $json -ContentType "application/json" -UseBasicParsing -TimeoutSec 30
        return @{
            StatusCode = [int]$resp.StatusCode
            Body = [string]$resp.Content
        }
    } catch {
        $code = 0
        $respBody = ""
        if ($_.Exception.Response) {
            try { $code = [int]$_.Exception.Response.StatusCode.value__ } catch {}
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $respBody = $reader.ReadToEnd()
            } catch {}
        }
        return @{
            StatusCode = $code
            Body = $respBody
        }
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Load-EnvLocal -RepoRoot $repoRoot
$resolvedApiKey = Resolve-ApiKey -Provided $ApiKey
$headers = @{ Authorization = "Bearer $resolvedApiKey" }

$geminiBody = @{
    contents = @(
        @{
            role = "user"
            parts = @(
                @{ text = "ping" }
            )
        }
    )
}

$tests = @(
    @{
        Name = "/v1/chat/completions"
        Url = "$BaseUrl/v1/chat/completions"
        Body = @{
            model = $Model
            messages = @(@{ role = "user"; content = "ping" })
            stream = $false
        }
    },
    @{
        Name = "/v1/completions"
        Url = "$BaseUrl/v1/completions"
        Body = @{
            model = $Model
            prompt = "ping"
            max_tokens = 1
        }
    },
    @{
        Name = "/v1/responses"
        Url = "$BaseUrl/v1/responses"
        Body = @{
            model = $Model
            input = "ping"
        }
    },
    @{
        Name = "/v1beta/models/:model:generateContent"
        Url = "$BaseUrl/v1beta/models/$Model`:generateContent"
        Body = $geminiBody
    },
    @{
        Name = "/v1beta/models/:model:streamGenerateContent"
        Url = "$BaseUrl/v1beta/models/$Model`:streamGenerateContent?alt=sse"
        Body = $geminiBody
    }
)

$allowedDisabledStatuses = @(404, 405)
$rows = @()
$failed = $false

Write-Host "Probing disabled prompt routes at $BaseUrl ..." -ForegroundColor Cyan
foreach ($t in $tests) {
    $res = Invoke-PostJson -Url $t.Url -Headers $headers -Body $t.Body
    $ok = $allowedDisabledStatuses -contains $res.StatusCode
    if (-not $ok) { $failed = $true }
    $rows += [pscustomobject]@{
        Route = $t.Name
        Status = $res.StatusCode
        DisabledOK = $ok
    }
}

$rows | Format-Table -AutoSize

if ($TracePath) {
    if (-not (Test-Path $TracePath)) {
        throw "Trace file not found: $TracePath"
    }
    $patterns = @(
        "v1internal:generateContent",
        "v1internal:streamGenerateContent",
        "generativelanguage.googleapis.com/.+:generateContent",
        "generativelanguage.googleapis.com/.+:streamGenerateContent"
    )
    $hits = Select-String -Path $TracePath -Pattern $patterns -SimpleMatch
    Write-Host ""
    if ($hits) {
        Write-Host "Supplemental trace check: FOUND prompt upstream signatures ($($hits.Count) hits)." -ForegroundColor Yellow
        $hits | Select-Object -First 10 | ForEach-Object { Write-Host ("  {0}:{1}" -f $_.LineNumber, $_.Line) }
    } else {
        Write-Host "Supplemental trace check: no prompt upstream signatures found." -ForegroundColor Green
    }
}

Write-Host ""
if ($failed) {
    throw "One or more prompt routes still responded as active (expected only 404/405). Ensure Gephyr was started with GEPHYR_DISABLE_PROMPT_ROUTES=true."
}

Write-Host "PASS: Prompt routes are disabled at HTTP surface (404/405 for all probes)." -ForegroundColor Green
