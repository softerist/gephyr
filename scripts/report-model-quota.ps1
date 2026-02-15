param(
    [string]$Model = "gemini-2.5-pro",
    [string]$BaseUrl = "http://127.0.0.1:8045",
    [string]$ApiKey,
    [switch]$Refresh,
    [switch]$Probe,
    [string]$Prompt = "quota check"
)

$ErrorActionPreference = "Stop"

function Get-DefaultApiKey {
    $configPath = Join-Path $HOME ".gephyr\config.json"
    if (-not (Test-Path $configPath)) {
        throw "Config not found at $configPath. Provide -ApiKey explicitly."
    }
    $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
    if (-not $cfg.proxy.api_key) {
        throw "proxy.api_key not found in $configPath. Provide -ApiKey explicitly."
    }
    return [string]$cfg.proxy.api_key
}

function Normalize-Model([string]$name) {
    if (-not $name) { return "" }
    return $name.Trim().ToLowerInvariant().Replace("models/", "")
}

function Parse-ResetSeconds([string]$resetTime) {
    if (-not $resetTime) { return $null }
    try {
        $dt = [DateTimeOffset]::Parse($resetTime)
        $sec = [int][Math]::Floor(($dt.UtcDateTime - [DateTime]::UtcNow).TotalSeconds)
        if ($sec -lt 0) { return 0 }
        return $sec
    } catch {
        return $null
    }
}

function New-AuthHeaders([string]$key) {
    return @{ Authorization = "Bearer $key" }
}

function Invoke-JsonGet([string]$url, [hashtable]$headers) {
    return (Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $url -TimeoutSec 30).Content | ConvertFrom-Json
}

function Get-HeaderValue($headers, [string]$name) {
    if (-not $headers) { return $null }
    try {
        if ($headers[$name]) { return [string]$headers[$name] }
    } catch {}
    try {
        foreach ($k in $headers.Keys) {
            if ([string]::Equals([string]$k, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return [string]$headers[$k]
            }
        }
    } catch {}
    return $null
}

if (-not $ApiKey) {
    $ApiKey = Get-DefaultApiKey
}

$headers = New-AuthHeaders -key $ApiKey
$target = Normalize-Model $Model

Write-Host "Fetching accounts from $BaseUrl ..." -ForegroundColor Cyan
$accountResp = Invoke-JsonGet -url "$BaseUrl/api/accounts" -headers $headers
$accounts = @($accountResp.accounts)

if ($Refresh) {
    Write-Host "Refreshing quota per account ..." -ForegroundColor Cyan
    foreach ($acc in $accounts) {
        try {
            $null = Invoke-JsonGet -url "$BaseUrl/api/accounts/$($acc.id)/quota" -headers $headers
        } catch {
            Write-Warning "Quota refresh failed for $($acc.email) ($($acc.id)): $($_.Exception.Message)"
        }
    }
    $accountResp = Invoke-JsonGet -url "$BaseUrl/api/accounts" -headers $headers
    $accounts = @($accountResp.accounts)
}

$rows = @()
foreach ($acc in $accounts) {
    $quotaModels = @()
    if ($acc.quota -and $acc.quota.models) {
        $quotaModels = @($acc.quota.models)
    }

    $matched = $quotaModels | Where-Object {
        (Normalize-Model $_.name) -eq $target
    } | Select-Object -First 1

    $alternatives = $quotaModels |
        Where-Object { $_.percentage -gt 0 -and ((Normalize-Model $_.name) -ne $target) } |
        Sort-Object -Property percentage -Descending |
        Select-Object -First 3

    $rows += [pscustomobject]@{
        account_id = [string]$acc.id
        email = [string]$acc.email
        disabled = [bool]$acc.disabled
        proxy_disabled = [bool]$acc.proxy_disabled
        target_model = $target
        target_present = [bool]($null -ne $matched)
        target_percentage = if ($matched) { [int]$matched.percentage } else { $null }
        target_reset_time = if ($matched) { [string]$matched.reset_time } else { $null }
        target_reset_seconds = if ($matched) { Parse-ResetSeconds $matched.reset_time } else { $null }
        alternatives = @($alternatives | ForEach-Object { "$($_.name):$($_.percentage)%" })
        protected_models = @($acc.protected_models)
        quota_last_updated = if ($acc.quota) { [int64]$acc.quota.last_updated } else { $null }
        subscription_tier = if ($acc.quota) { [string]$acc.quota.subscription_tier } else { $null }
    }
}

$eligibleTarget = @($rows | Where-Object {
    -not $_.disabled -and -not $_.proxy_disabled -and $_.target_percentage -gt 0
})

$summary = [pscustomobject]@{
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    base_url = $BaseUrl
    target_model = $target
    accounts_total = $rows.Count
    accounts_with_target_quota = @($rows | Where-Object { $_.target_present -and $_.target_percentage -gt 0 }).Count
    eligible_accounts_with_target_quota = $eligibleTarget.Count
    all_target_zero_or_missing = ($eligibleTarget.Count -eq 0)
}

$probeResult = $null
if ($Probe) {
    Write-Host "Running one probe request for $target ..." -ForegroundColor Cyan
    $body = @{
        model = $target
        messages = @(@{ role = "user"; content = $Prompt })
    } | ConvertTo-Json -Depth 10

    $status = $null
    $content = ""
    $respHeaders = $null
    try {
        $resp = Invoke-WebRequest -UseBasicParsing -Method POST `
            -Headers @{ Authorization = "Bearer $ApiKey"; "Content-Type" = "application/json" } `
            -Body $body -Uri "$BaseUrl/v1/chat/completions" -TimeoutSec 120
        $status = [int]$resp.StatusCode
        $content = [string]$resp.Content
        $respHeaders = $resp.Headers
    } catch {
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode.value__
            $respHeaders = $_.Exception.Response.Headers
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $content = $reader.ReadToEnd()
            } catch {
                $content = $_.Exception.Message
            }
        } else {
            $status = -1
            $content = $_.Exception.Message
        }
    }
    $snippet = if ($content.Length -gt 600) { $content.Substring(0, 600) } else { $content }
    $mappedModel = Get-HeaderValue $respHeaders "X-Mapped-Model"
    $accountEmail = Get-HeaderValue $respHeaders "X-Account-Email"
    $responseModel = $null
    try {
        $parsed = $content | ConvertFrom-Json
        if ($parsed.model) {
            $responseModel = [string]$parsed.model
        }
    } catch {}
    $fallbackDetected = $false
    if ($mappedModel -and $mappedModel -ne $target) {
        $fallbackDetected = $true
    }
    $probeResult = [pscustomobject]@{
        status = $status
        request_model = $target
        response_model = $responseModel
        mapped_model_header = $mappedModel
        account_email_header = $accountEmail
        fallback_detected = $fallbackDetected
        body_snippet = $snippet
    }
}

$report = [pscustomobject]@{
    summary = $summary
    accounts = $rows
    probe = $probeResult
}

$stamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$outJson = Join-Path "output" ("model_quota_report_{0}.json" -f $stamp)
New-Item -ItemType Directory -Force -Path "output" | Out-Null
$report | ConvertTo-Json -Depth 10 | Set-Content -Path $outJson -Encoding UTF8

Write-Host ""
Write-Host "Target model report:" -ForegroundColor Green
$rows | Select-Object email, target_percentage, target_reset_time, target_reset_seconds, disabled, proxy_disabled | Format-Table -AutoSize
Write-Host ""
Write-Host "Summary: $($summary | ConvertTo-Json -Compress)"
if ($probeResult) {
    Write-Host "Probe:   $($probeResult | ConvertTo-Json -Compress)"
}
Write-Host "Saved:   $outJson"
