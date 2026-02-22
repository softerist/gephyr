param(
  [string]$Bump = 'patch',
  [string]$ReleaseType = '',
  [switch]$SkipTests,
  [switch]$Help,
  [switch]$NoPush
)

if ($Help) {
  Write-Host ''
  Write-Host 'Usage:'
  Write-Host '  ./publish.ps1 [-Bump patch|minor|major|prerelease|x.y.z] [-ReleaseType fix|feat|chore] [-SkipTests] [-NoPush]'
  Write-Host ''
  Write-Host 'Notes:'
  Write-Host '- Requires clean git working tree.'
  Write-Host '- If -Bump is omitted, prompts interactively for release intent (fix/feat/chore/etc).'
  Write-Host '- Bumps version in Cargo.toml and updates Cargo.lock.'
  Write-Host '- Runs cargo build --release and cargo test as preflight checks.'
  Write-Host '- Commits Cargo.toml and Cargo.lock, creates git tag.'
  Write-Host '- Publishes to crates.io via cargo publish.'
  Write-Host '- Publishes Docker image to GitHub Container Registry (ghcr.io) when pushing.'
  Write-Host '- Pushes git commit and tags (unless -NoPush).'
  Write-Host '- Use -SkipTests to skip the cargo test preflight step.'
  Write-Host ''
  exit 0
}

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $repoRoot

$newVersion = $null
$script:GhcrPackageStatusSummary = 'not checked (GHCR publish not attempted).'

function Get-CargoVersion {
  $cargoToml = Join-Path $repoRoot 'Cargo.toml'
  if (-not (Test-Path $cargoToml)) { return $null }
  $content = Get-Content -Path $cargoToml -Raw
  if ($content -match '(?m)^\s*version\s*=\s*"([^"]+)"') {
    return $Matches[1]
  }
  return $null
}

function Set-CargoVersion {
  param([string]$Version)
  $cargoToml = Join-Path $repoRoot 'Cargo.toml'
  $content = Get-Content -Path $cargoToml -Raw
  $updated = $content -replace '(?m)^(\s*version\s*=\s*")[^"]+"', "`${1}$Version`""
  Set-Content -Path $cargoToml -Value $updated -NoNewline -Encoding utf8
}

function Bump-SemVer {
  param(
    [string]$CurrentVersion,
    [string]$BumpType
  )

  # If BumpType looks like a full semver string (x.y.z), use it directly
  if ($BumpType -match '^\d+\.\d+\.\d+') {
    return $BumpType
  }

  # Parse current version (supports optional -prerelease suffix)
  if ($CurrentVersion -notmatch '^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$') {
    return $null
  }
  $major = [int]$Matches[1]
  $minor = [int]$Matches[2]
  $patch = [int]$Matches[3]
  $prerelease = $Matches[4]

  switch ($BumpType.ToLowerInvariant()) {
    'major' {
      $major++; $minor = 0; $patch = 0
      return "$major.$minor.$patch"
    }
    'minor' {
      $minor++; $patch = 0
      return "$major.$minor.$patch"
    }
    'patch' {
      $patch++
      return "$major.$minor.$patch"
    }
    'prerelease' {
      if ($prerelease -and $prerelease -match '^(.+?)\.(\d+)$') {
        $preTag = $Matches[1]
        $preNum = [int]$Matches[2] + 1
        return "$major.$minor.$patch-$preTag.$preNum"
      } elseif ($prerelease) {
        return "$major.$minor.$patch-$prerelease.1"
      } else {
        $patch++
        return "$major.$minor.$patch-rc.0"
      }
    }
    default {
      return $null
    }
  }
}

function Get-DefaultReleaseTypeFromBump {
  param([string]$BumpValue)
  switch ($BumpValue.ToLowerInvariant()) {
    'minor' { return 'feat' }
    'major' { return 'feat' }
    'patch' { return 'fix' }
    default { return 'chore' }
  }
}

function Select-ReleasePlanInteractive {
  param(
    [string]$CurrentBump,
    [string]$CurrentReleaseType
  )

  while ($true) {
    Write-Host ''
    Write-Host '[release] Choose release intent:'
    Write-Host '  1) fix   -> patch (bug fix)'
    Write-Host '  2) feat  -> minor (new feature)'
    Write-Host '  3) chore -> patch (maintenance)'
    Write-Host '  4) major -> major (breaking change)'
    Write-Host '  5) prerelease -> prerelease'
    Write-Host '  6) Custom bump + custom type'
    Write-Host '  7) Cancel release'
    $choice = (Read-Host '[release] Select 1-7').Trim()

    switch ($choice) {
      '1' { return @{ Bump = 'patch'; ReleaseType = 'fix' } }
      '2' { return @{ Bump = 'minor'; ReleaseType = 'feat' } }
      '3' { return @{ Bump = 'patch'; ReleaseType = 'chore' } }
      '4' { return @{ Bump = 'major'; ReleaseType = 'feat' } }
      '5' { return @{ Bump = 'prerelease'; ReleaseType = $CurrentReleaseType } }
      '6' {
        $customBump = (Read-Host '[release] Enter bump (patch|minor|major|prerelease|x.y.z)').Trim()
        if ([string]::IsNullOrWhiteSpace($customBump)) {
          Write-Host '[release] Bump cannot be empty.'
          continue
        }

        $customType = (Read-Host "[release] Enter release type (current: $CurrentReleaseType)").Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($customType)) { $customType = $CurrentReleaseType }
        if ([string]::IsNullOrWhiteSpace($customType)) { $customType = 'chore' }
        if ($customType -notmatch '^[a-z][a-z0-9-]*$') {
          Write-Host '[release] Invalid type. Use lowercase letters/numbers/hyphen (example: fix, feat, chore).'
          continue
        }

        return @{ Bump = $customBump; ReleaseType = $customType }
      }
      '7' { return $null }
      default {
        Write-Host '[release] Invalid selection. Enter 1-7.'
      }
    }
  }
}

function Rollback-VersionFiles {
  if (-not $newVersion) { return }
  Write-Host '[release] INFO: Rolling back local version files...' -ForegroundColor DarkCyan
  git checkout -- Cargo.toml *> $null
  if (Test-Path 'Cargo.lock') { git checkout -- Cargo.lock *> $null }
}

function Info {
  param([string]$Message)
  Write-Host "[release] INFO: $Message" -ForegroundColor Cyan
}

function Warn {
  param([string]$Message)
  Write-Host "[release] WARN: $Message" -ForegroundColor Yellow
}

function Assert-CommandAvailable {
  param([string]$CommandName)
  return [bool](Get-Command $CommandName -ErrorAction SilentlyContinue)
}

function Assert-RequiredTools {
  param(
    [switch]$RequireDocker,
    [switch]$RequireGhForAuth
  )

  $missing = @()

  foreach ($tool in @('git', 'cargo')) {
    if (-not (Assert-CommandAvailable -CommandName $tool)) {
      $missing += $tool
    }
  }

  if ($RequireDocker -and -not (Assert-CommandAvailable -CommandName 'docker')) {
    $missing += 'docker'
  }

  if ($RequireGhForAuth -and -not (Assert-CommandAvailable -CommandName 'gh')) {
    $missing += 'gh'
  }

  if ($missing.Count -gt 0) {
    $hints = @(
      'Install the missing tools and ensure they are available in PATH for this PowerShell session.'
    )
    if ($RequireGhForAuth) {
      $hints += 'Or set GHCR_TOKEN/GITHUB_TOKEN to skip interactive gh authentication for GHCR publish.'
    }

    Fail "Missing required tools in PATH: $($missing -join ', ')." -Hints $hints
  }

  if (-not $NoPush -and -not (Assert-CommandAvailable -CommandName 'gh')) {
    Warn 'gh CLI is not available; GitHub Release creation and package metadata checks will be skipped.'
  }
}

function Get-CargoHomePath {
  if (-not [string]::IsNullOrWhiteSpace($env:CARGO_HOME)) {
    return $env:CARGO_HOME
  }
  if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    return (Join-Path $env:USERPROFILE '.cargo')
  }
  return (Join-Path $HOME '.cargo')
}

function Test-CargoRegistryTokenConfigured {
  if (-not [string]::IsNullOrWhiteSpace($env:CARGO_REGISTRY_TOKEN)) {
    return $true
  }

  $cargoHome = Get-CargoHomePath
  foreach ($fileName in @('credentials.toml', 'credentials')) {
    $credentialsPath = Join-Path $cargoHome $fileName
    if (-not (Test-Path $credentialsPath)) {
      continue
    }

    $raw = Get-Content -Path $credentialsPath -Raw -ErrorAction SilentlyContinue
    if ($raw -match '(?m)^\s*token\s*=\s*".+?"\s*$') {
      return $true
    }
  }

  return $false
}

function Ensure-CargoRegistryToken {
  if (Test-CargoRegistryTokenConfigured) {
    return
  }

  Warn 'No crates.io publish token found (cargo login credentials or CARGO_REGISTRY_TOKEN).'

  if (-not [Environment]::UserInteractive) {
    Fail 'Missing crates.io token for cargo publish.' -Hints @(
      'Set CARGO_REGISTRY_TOKEN in your environment, or run cargo login <token>.',
      'Re-run ./publish.ps1 after token is configured.'
    )
  }

  $secureToken = Read-Host '[release] Enter crates.io token (input hidden)' -AsSecureString
  if (-not $secureToken -or $secureToken.Length -eq 0) {
    Fail 'crates.io token cannot be empty.' -Hints @(
      'Run cargo login <token>, or rerun this script and provide a valid token when prompted.'
    )
  }

  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
  try {
    $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }

  if ([string]::IsNullOrWhiteSpace($plainToken)) {
    Fail 'Failed to read crates.io token from prompt.'
  }

  $env:CARGO_REGISTRY_TOKEN = $plainToken
  Info 'Using CARGO_REGISTRY_TOKEN from this process only (not saved).'
  Info 'Running cargo login to persist token for future publishes...'
  $plainToken | cargo login *> $null
  if ($LASTEXITCODE -ne 0) {
    Warn 'cargo login failed; continuing with in-memory token for this run only.'
  } else {
    Info 'cargo login succeeded; token saved to cargo credentials.'
  }
}

function Ensure-GhCliAuthWithScopes {
  if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Fail 'gh CLI is required for interactive GHCR authentication when GHCR_TOKEN is not set.' -Hints @(
      'Install gh from https://cli.github.com, or set GHCR_TOKEN/GITHUB_TOKEN with packages:write scope.',
      'Re-run ./publish.ps1 after auth prerequisites are available.'
    )
  }

  gh auth status -h github.com *> $null
  if ($LASTEXITCODE -ne 0) {
    if (-not [Environment]::UserInteractive) {
      Fail 'GitHub authentication is required for GHCR publish, but this session is non-interactive.' -Hints @(
        'Set GHCR_TOKEN/GITHUB_TOKEN with packages:write scope for non-interactive usage.',
        'Or run this script in an interactive terminal.'
      )
    }

    Warn 'No active GitHub CLI auth found. Starting interactive gh auth login...'
    gh auth login -h github.com -s repo -s write:packages -s read:packages
    if ($LASTEXITCODE -ne 0) {
      Fail 'gh auth login failed.' -Hints @(
        'Retry: gh auth login -h github.com -s repo -s write:packages -s read:packages',
        'Or set GHCR_TOKEN/GITHUB_TOKEN with packages:write scope.'
      )
    }
  }

  $statusText = (gh auth status -h github.com -t 2>&1 | Out-String)
  if (-not ($statusText -match 'write:packages')) {
    if (-not [Environment]::UserInteractive) {
      Fail 'GitHub token is missing write:packages scope for GHCR publish.' -Hints @(
        'Refresh scopes interactively: gh auth refresh -h github.com -s write:packages -s read:packages -s repo',
        'Or set GHCR_TOKEN/GITHUB_TOKEN with packages:write scope.'
      )
    }

    Warn 'GitHub token is missing write:packages scope. Refreshing gh auth scopes interactively...'
    gh auth refresh -h github.com -s write:packages -s read:packages -s repo
    if ($LASTEXITCODE -ne 0) {
      Fail 'gh auth refresh failed; required scopes not granted.' -Hints @(
        'Run: gh auth refresh -h github.com -s write:packages -s read:packages -s repo',
        'Then rerun ./publish.ps1.'
      )
    }
  }
}

function Resolve-GhcrImage {
  if (-not [string]::IsNullOrWhiteSpace($env:GEPHYR_GHCR_IMAGE)) {
    return $env:GEPHYR_GHCR_IMAGE.ToLowerInvariant()
  }

  $origin = (git config --get remote.origin.url 2>$null)
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($origin)) {
    return $null
  }

  $origin = $origin.Trim()
  if ($origin -match 'github\.com[:/](?<owner>[^/]+)/(?<repo>[^/]+?)(?:\.git)?$') {
    $owner = $Matches['owner'].ToLowerInvariant()
    $repo = $Matches['repo'].ToLowerInvariant()
    return "ghcr.io/$owner/$repo"
  }

  return $null
}

function Resolve-GhcrAuthMaterial {
  param(
    [string]$DefaultUser
  )

  $token = $null
  if (-not [string]::IsNullOrWhiteSpace($env:GHCR_TOKEN)) {
    $token = $env:GHCR_TOKEN
  } elseif (-not [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
    $token = $env:GITHUB_TOKEN
  } else {
    Ensure-GhCliAuthWithScopes
    $ghToken = (gh auth token 2>$null)
    if (-not [string]::IsNullOrWhiteSpace($ghToken)) {
      $token = $ghToken.Trim()
    }
  }

  $user = $null
  if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_ACTOR)) {
    $user = $env:GITHUB_ACTOR
  } elseif (Get-Command gh -ErrorAction SilentlyContinue) {
    gh auth status -h github.com *> $null
    if ($LASTEXITCODE -eq 0) {
      $ghUser = (gh api user -q .login 2>$null)
      if (-not [string]::IsNullOrWhiteSpace($ghUser)) {
        $user = $ghUser.Trim()
      }
    }
  }

  if ([string]::IsNullOrWhiteSpace($user)) {
    $user = $DefaultUser
  }

  if ([string]::IsNullOrWhiteSpace($token)) {
    Fail 'Missing GHCR auth token for docker publish.' -Hints @(
      'Set GHCR_TOKEN (or GITHUB_TOKEN) with packages:write scope, or run gh auth login/refresh.',
      'Re-run ./publish.ps1 after token is configured.'
    )
  }

  if ([string]::IsNullOrWhiteSpace($user)) {
    Fail 'Could not resolve GitHub username for GHCR login.' -Hints @(
      'Set GITHUB_ACTOR, or authenticate gh CLI with gh auth login.',
      'Re-run ./publish.ps1 after username is available.'
    )
  }

  return @{
    User = $user
    Token = $token
  }
}

function Get-GitHubRepoSlug {
  $origin = (git config --get remote.origin.url 2>$null)
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($origin)) {
    return $null
  }

  $origin = $origin.Trim()
  if ($origin -match 'github\.com[:/](?<owner>[^/]+)/(?<repo>[^/]+?)(?:\.git)?$') {
    return ("{0}/{1}" -f $Matches['owner'], $Matches['repo'])
  }

  return $null
}

function Confirm-GhcrPackageDiscoverability {
  param(
    [string]$GhcrImage
  )

  if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    $script:GhcrPackageStatusSummary = 'not checked (gh CLI unavailable).'
    return
  }

  gh auth status -h github.com *> $null
  if ($LASTEXITCODE -ne 0) {
    $script:GhcrPackageStatusSummary = 'not checked (gh auth unavailable).'
    return
  }

  if ($GhcrImage -notmatch '^ghcr\.io/(?<owner>[^/]+)/(?<package>.+)$') {
    $script:GhcrPackageStatusSummary = 'not checked (unable to parse GHCR image name).'
    return
  }

  $owner = $Matches['owner']
  $packageName = $Matches['package']
  $encodedPackageName = [uri]::EscapeDataString($packageName)
  $endpoint = "/users/$owner/packages/container/$encodedPackageName"

  $pkgRaw = gh api $endpoint 2>$null
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pkgRaw)) {
    Warn "Unable to inspect GHCR package metadata for $GhcrImage."
    $script:GhcrPackageStatusSummary = "unknown (failed reading package metadata for $GhcrImage)."
    return
  }

  $pkg = $pkgRaw | ConvertFrom-Json
  $packageVisibility = "$($pkg.visibility)"
  $packageUrl = "$($pkg.html_url)"
  if ([string]::IsNullOrWhiteSpace($packageUrl)) {
    $packageUrl = "https://github.com/users/$owner/packages/container/package/$packageName"
  }

  if ($packageVisibility -ieq 'private') {
    Warn "GHCR package is private: $GhcrImage"
    Warn 'Private package visibility can hide it from repo sidebar package listings.'
    Warn "Set visibility in GitHub UI: $packageUrl/settings"
  }

  $repoSlug = Get-GitHubRepoSlug
  $hasRepositoryLink = ($pkg.PSObject.Properties.Name -contains 'repository') -and $pkg.repository
  $repositoryLink = $null
  if ($hasRepositoryLink) {
    if ($pkg.repository.PSObject.Properties.Name -contains 'full_name' -and -not [string]::IsNullOrWhiteSpace("$($pkg.repository.full_name)")) {
      $repositoryLink = "$($pkg.repository.full_name)"
    } elseif ($pkg.repository.PSObject.Properties.Name -contains 'nameWithOwner' -and -not [string]::IsNullOrWhiteSpace("$($pkg.repository.nameWithOwner)")) {
      $repositoryLink = "$($pkg.repository.nameWithOwner)"
    }
  }

  if (-not $hasRepositoryLink -and -not [string]::IsNullOrWhiteSpace($repoSlug)) {
    Warn "If repo sidebar still shows 'No packages published', connect this package to repository $repoSlug."
    Warn "Package settings: $packageUrl/settings"
    $script:GhcrPackageStatusSummary = "visibility=$packageVisibility, repository_link=missing (expected $repoSlug; configure: $packageUrl/settings)"
  } elseif (-not $hasRepositoryLink) {
    Warn "If repo sidebar still shows 'No packages published', open package settings: $packageUrl/settings"
    $script:GhcrPackageStatusSummary = "visibility=$packageVisibility, repository_link=missing (configure: $packageUrl/settings)"
  } elseif ($packageVisibility -ieq 'public') {
    Info "GHCR package is public and linked for discoverability: $GhcrImage"
    $script:GhcrPackageStatusSummary = "visibility=$packageVisibility, repository_link=$repositoryLink"
  } else {
    $script:GhcrPackageStatusSummary = "visibility=$packageVisibility, repository_link=$repositoryLink"
  }
}

function Publish-DockerImageToGhcr {
  param([string]$Version)

  $ghcrImage = Resolve-GhcrImage
  if ([string]::IsNullOrWhiteSpace($ghcrImage)) {
    Fail 'Could not resolve GHCR image name from git remote.' -Hints @(
      'Ensure origin points to GitHub, or set GEPHYR_GHCR_IMAGE (example: ghcr.io/owner/gephyr).',
      'Re-run ./publish.ps1 after GHCR image is configured.'
    )
  }

  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail 'docker is required to publish container package to GHCR.' -Hints @(
      'Install Docker Desktop and ensure docker is in PATH.',
      'Re-run ./publish.ps1 after Docker is available.'
    )
  }

  docker info *> $null
  if ($LASTEXITCODE -ne 0) {
    Fail 'Docker daemon is not available; cannot publish container package.' -Hints @(
      'Start Docker Desktop and wait for engine startup to complete.',
      'Re-run ./publish.ps1 after docker info succeeds.'
    )
  }

  $imagePath = $ghcrImage -replace '^ghcr\.io/', ''
  $defaultUser = ($imagePath -split '/')[0]
  $auth = Resolve-GhcrAuthMaterial -DefaultUser $defaultUser

  Info "Logging in to GHCR as $($auth.User)..."
  $auth.Token | docker login ghcr.io -u $auth.User --password-stdin *> $null
  if ($LASTEXITCODE -ne 0) {
    Fail 'GHCR docker login failed.' -Hints @(
      'Verify GHCR token scope includes write:packages (and read:packages).',
      'Try: gh auth refresh -h github.com -s write:packages -s read:packages -s repo',
      'Try: echo $env:GHCR_TOKEN | docker login ghcr.io -u <username> --password-stdin'
    )
  }

  $tags = @("v$Version", $Version, "latest")
  $buildTagArgs = @()
  foreach ($tag in $tags) {
    $buildTagArgs += @('-t', "${ghcrImage}:$tag")
  }

  Info "Building Docker image for GHCR: $ghcrImage (platform linux/amd64, provenance disabled)"
  & docker build --platform linux/amd64 --provenance=false --sbom=false -f docker/Dockerfile @buildTagArgs .
  if ($LASTEXITCODE -ne 0) {
    Fail 'Docker build failed for GHCR publish.' -Hints @(
      'Fix Docker build errors above.',
      'Then rerun ./publish.ps1 to continue release publish.'
    )
  }

  foreach ($tag in $tags) {
    Info "Pushing GHCR image tag: ${ghcrImage}:$tag"
    docker push "${ghcrImage}:$tag"
    if ($LASTEXITCODE -ne 0) {
      Fail "Failed pushing GHCR image tag ${ghcrImage}:$tag." -Hints @(
        'Verify repository permissions and token scope (packages:write).',
        'Retry with: docker push ' + "${ghcrImage}:$tag"
      )
    }
  }

  Info "GHCR publish complete: $ghcrImage (tags: $($tags -join ', '))"
  Confirm-GhcrPackageDiscoverability -GhcrImage $ghcrImage
}

function Fail {
  param(
    [string]$Message,
    [string[]]$Hints = @(),
    [switch]$Rollback
  )
  if ($Rollback) { Rollback-VersionFiles }
  Write-Host ''
  Write-Host "[release] ERROR: $Message" -ForegroundColor Red
  if ($Hints.Count -gt 0) {
    Write-Host '[release] Next steps:' -ForegroundColor Yellow
    foreach ($hint in $Hints) {
      Write-Host "  - $hint"
    }
  }
  Pop-Location
  exit 1
}

# --- Main flow ---

if ([string]::IsNullOrWhiteSpace($ReleaseType)) {
  $ReleaseType = Get-DefaultReleaseTypeFromBump -BumpValue $Bump
}

if (-not $PSBoundParameters.ContainsKey('Bump')) {
  $selection = Select-ReleasePlanInteractive -CurrentBump $Bump -CurrentReleaseType $ReleaseType
  if (-not $selection) { Fail 'Release selection canceled.' }
  $Bump = $selection.Bump
  $ReleaseType = $selection.ReleaseType
}

if ($ReleaseType -notmatch '^[a-z][a-z0-9-]*$') {
  Fail "Invalid -ReleaseType '$ReleaseType'. Use lowercase letters/numbers/hyphen."
}

Write-Host "[release] Repository: $repoRoot"
Write-Host "[release] Version bump: $Bump"
Write-Host "[release] Release type: $ReleaseType"

# Check prerequisites
$requireGhForAuth = (-not $NoPush) -and [string]::IsNullOrWhiteSpace($env:GHCR_TOKEN) -and [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)
Assert-RequiredTools -RequireDocker:(-not $NoPush) -RequireGhForAuth:$requireGhForAuth

git rev-parse --is-inside-work-tree *> $null
if ($LASTEXITCODE -ne 0) { Fail 'Current directory is not a git repository.' }

$dirty = git status --porcelain
if ($dirty) {
  Warn 'Working tree is not clean. Commit or stash changes first.'
  git status --short
  Pop-Location
  exit 1
}

# Read current version from Cargo.toml
$oldVersion = Get-CargoVersion
if ([string]::IsNullOrWhiteSpace($oldVersion)) {
  Fail 'Could not read version from Cargo.toml.'
}
Write-Host "[release] Current version: $oldVersion"

# Bump version
$newVersion = Bump-SemVer -CurrentVersion $oldVersion -BumpType $Bump
if ([string]::IsNullOrWhiteSpace($newVersion)) {
  Fail "Failed to compute new version from '$oldVersion' with bump '$Bump'."
}

Set-CargoVersion -Version $newVersion
Write-Host "[release] New version: $newVersion"

# Update Cargo.lock to reflect the new version
Info 'Updating Cargo.lock...'
cargo update --workspace *> $null
if ($LASTEXITCODE -ne 0) {
  Warn 'cargo update --workspace failed; Cargo.lock may be stale.'
}

# Preflight: build
Info 'Running preflight build: cargo build --release'
cargo build --release
if ($LASTEXITCODE -ne 0) {
  Fail 'Preflight build failed (cargo build --release).' -Rollback -Hints @(
    'Review the build errors above and fix compile issues.',
    'Re-run this script after the build passes.'
  )
}

# Preflight: tests
if (-not $SkipTests) {
  Info 'Running preflight tests: cargo test'
  cargo test
  if ($LASTEXITCODE -ne 0) {
    Fail 'Preflight tests failed (cargo test). Release stopped to keep the publish safe.' -Rollback -Hints @(
      'Re-run with extra output: cargo test -- --nocapture',
      'Fix failing tests, then run ./publish.ps1 again.',
      'If you intentionally want to skip tests (not recommended), run ./publish.ps1 -SkipTests'
    )
  }
} else {
  Warn 'Skipping tests due to -SkipTests.'
}

# Git commit
git add Cargo.toml
if (Test-Path 'Cargo.lock') { git add Cargo.lock }

git commit -m "$ReleaseType(release): v$newVersion"
if ($LASTEXITCODE -ne 0) { Fail 'git commit failed.' -Rollback }

# Git tag
Write-Host "[release] Creating git tag v$newVersion..."
git tag -a "v$newVersion" -m "$ReleaseType(release): v$newVersion"
if ($LASTEXITCODE -ne 0) { Fail 'git tag failed.' }

# Publish to crates.io
Ensure-CargoRegistryToken
Info 'Publishing to crates.io...'
$publishOutput = & cargo publish 2>&1
$publishExit = $LASTEXITCODE
$publishOutput | ForEach-Object { Write-Host $_ }
if ($publishExit -ne 0) {
  $hints = @(
    'Ensure crates.io token is valid: cargo login <token> or set CARGO_REGISTRY_TOKEN.',
    'After publish succeeds, run: git push --follow-tags'
  )

  $publishText = ($publishOutput | Out-String)
  if ($publishText -match 'verified email address is required') {
    $hints = @(
      'Verify your crates.io email at https://crates.io/settings/profile, then retry cargo publish.',
      'After publish succeeds, run: git push --follow-tags'
    )
  }

  Fail 'cargo publish failed. Commit and tag exist locally; push was skipped.' -Hints $hints
}

if (-not $NoPush) {
  Publish-DockerImageToGhcr -Version $newVersion
} else {
  Warn 'Skipping GHCR Docker publish due to -NoPush.'
  $script:GhcrPackageStatusSummary = 'skipped (-NoPush).'
}

# Push
if (-not $NoPush) {
  Info 'Pushing commit and tags to git remote...'
  git push --follow-tags
  if ($LASTEXITCODE -ne 0) {
    Warn 'git push failed. Commit exists locally; push manually.'
    Pop-Location
    exit 1
  }

  # Create GitHub Release
  if (Get-Command gh -ErrorAction SilentlyContinue) {
    Info 'Creating GitHub Release...'
    gh release create "v$newVersion" --title "v$newVersion" --generate-notes
    if ($LASTEXITCODE -ne 0) {
      Warn 'GitHub Release creation failed. Create it manually at:'
      Write-Host '  https://github.com/softerist/gephyr/releases/new'
    } else {
      Write-Host "[release] GitHub Release v$newVersion created."
    }
  } else {
    Warn 'gh CLI not found. Skipping GitHub Release creation.'
    Info 'Install gh from https://cli.github.com to enable this feature.'
  }

  Write-Host "[release] SUCCESS: v$newVersion committed, tagged, crate published, GHCR image published, and git pushed."
  Write-Host "[release] Package visibility/link status: $script:GhcrPackageStatusSummary"
} else {
  Write-Host '[release] Skipping git push due to -NoPush.'
  Write-Host "[release] SUCCESS: v$newVersion committed, tagged, and crate published. Push + GHCR publish skipped."
  Write-Host "[release] Package visibility/link status: $script:GhcrPackageStatusSummary"
}

Pop-Location
exit 0
