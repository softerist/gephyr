<#
.SYNOPSIS
Validates static guardrails for Google generation route/caller mapping.

.DESCRIPTION
This script enforces two code-level invariants:
1) Only allowlisted non-test files may call UpstreamClient `call_v1_internal*`.
2) Expected generation ingress route paths and handler symbols are present in
   `src/proxy/routes/mod.rs`.

Use this as a strict regression guard when refactoring routing or handlers.
#>
param(
    [string]$CallerAllowlistPath = "scripts/allowlists/google_generation_upstream_callers.txt",
    [string]$RouteAllowlistPath = "scripts/allowlists/google_generation_ingress_routes.txt",
    [string]$RoutesFilePath = "src/proxy/routes/mod.rs",
    [string]$OutJson = "output/google_generation_mapping_validation.json",
    [string]$OutText = "output/google_generation_mapping_validation.txt",
    [switch]$NoThrow
)

$ErrorActionPreference = "Stop"

function Load-Allowlist {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Allowlist file not found: $Path"
    }
    return @(Get-Content $Path |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith("#") })
}

function Normalize-RepoPath {
    param([string]$Path)
    if (-not $Path) { return $Path }
    return ($Path -replace '\\', '/')
}

if (-not (Get-Command rg -ErrorAction SilentlyContinue)) {
    throw "ripgrep (rg) is required for this validator."
}

if (-not (Test-Path $RoutesFilePath)) {
    throw "Routes file not found: $RoutesFilePath"
}

$callerAllow = Load-Allowlist -Path $CallerAllowlistPath
$routeAllow = Load-Allowlist -Path $RouteAllowlistPath

$callerAllowSet = New-Object System.Collections.Generic.HashSet[string]
foreach ($p in $callerAllow) { [void]$callerAllowSet.Add((Normalize-RepoPath -Path $p)) }

$callerMatches = & rg -n "call_v1_internal_with_headers\(|call_v1_internal\(" src/proxy src/modules -S

$observedCallers = New-Object System.Collections.Generic.HashSet[string]
foreach ($line in $callerMatches) {
    if ($line -notmatch '^(?<path>[^:]+):(?<line>\d+):(?<text>.*)$') {
        continue
    }
    $path = Normalize-RepoPath -Path $Matches.path
    # Exclude upstream client implementation and tests; we only care about production call paths.
    if ($path -eq "src/proxy/upstream/client.rs") { continue }
    if ($path -match '[/\\]tests[/\\]') { continue }
    [void]$observedCallers.Add($path)
}

$unknownCallers = @($observedCallers | Where-Object { -not $callerAllowSet.Contains($_) } | Sort-Object)
$missingAllowedCallers = @($callerAllow | Where-Object { $_ -notin $observedCallers } | Sort-Object)
$observedAllowedCallers = @($observedCallers | Where-Object { $callerAllowSet.Contains($_) } | Sort-Object)

$routesText = Get-Content $RoutesFilePath -Raw
$missingRoutes = @()
foreach ($route in $routeAllow) {
    if ($routesText -notmatch [regex]::Escape($route)) {
        $missingRoutes += $route
    }
}

$requiredSymbols = @(
    "handlers::openai::handle_chat_completions",
    "handlers::openai::handle_completions",
    "handlers::claude::handle_messages",
    "handlers::gemini::handle_generate"
)
$missingSymbols = @()
foreach ($sym in $requiredSymbols) {
    if ($routesText -notmatch [regex]::Escape($sym)) {
        $missingSymbols += $sym
    }
}

$pass = ($unknownCallers.Count -eq 0 -and $missingRoutes.Count -eq 0 -and $missingSymbols.Count -eq 0)

$result = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    caller_allowlist_path = $CallerAllowlistPath
    route_allowlist_path = $RouteAllowlistPath
    routes_file_path = $RoutesFilePath
    caller_allow_count = $callerAllow.Count
    observed_non_test_callers_count = $observedCallers.Count
    observed_allowed_callers = $observedAllowedCallers
    unknown_callers = $unknownCallers
    missing_allowed_callers = $missingAllowedCallers
    required_route_paths_missing = $missingRoutes
    required_handler_symbols_missing = $missingSymbols
    pass = $pass
}

$outDirJson = Split-Path -Parent $OutJson
$outDirText = Split-Path -Parent $OutText
if ($outDirJson) { New-Item -ItemType Directory -Force -Path $outDirJson | Out-Null }
if ($outDirText) { New-Item -ItemType Directory -Force -Path $outDirText | Out-Null }

$result | ConvertTo-Json -Depth 8 | Set-Content -Path $OutJson

$lines = @()
$lines += "Google Generation Mapping Validation"
$lines += "Generated: $($result.generated_at)"
$lines += "Routes file: $RoutesFilePath"
$lines += "Caller allowlist: $CallerAllowlistPath"
$lines += "Route allowlist: $RouteAllowlistPath"
$lines += "Pass: $($result.pass)"
$lines += ""
$lines += "Unknown non-test call_v1_internal* callers:"
if ($unknownCallers.Count -eq 0) { $lines += "  (none)" } else { $unknownCallers | ForEach-Object { $lines += "  $_" } }
$lines += ""
$lines += "Missing allowlisted callers (informational):"
if ($missingAllowedCallers.Count -eq 0) { $lines += "  (none)" } else { $missingAllowedCallers | ForEach-Object { $lines += "  $_" } }
$lines += ""
$lines += "Missing required route paths:"
if ($missingRoutes.Count -eq 0) { $lines += "  (none)" } else { $missingRoutes | ForEach-Object { $lines += "  $_" } }
$lines += ""
$lines += "Missing required route handler symbols:"
if ($missingSymbols.Count -eq 0) { $lines += "  (none)" } else { $missingSymbols | ForEach-Object { $lines += "  $_" } }

$lines | Set-Content -Path $OutText

Write-Host "Validation report written:"
Write-Host "  $OutText"
Write-Host "  $OutJson"
Write-Host "Pass: $($result.pass)"

if (-not $NoThrow -and -not $result.pass) {
    throw "Google generation mapping validation failed. See: $OutText"
}
