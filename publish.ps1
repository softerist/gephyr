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
  Write-Host '- Pushes git commit and tags (unless -NoPush).'
  Write-Host '- Use -SkipTests to skip the cargo test preflight step.'
  Write-Host ''
  exit 0
}

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $repoRoot

$newVersion = $null

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
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Fail 'git is not available in PATH.' }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Fail 'cargo is not available in PATH.' }

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
Info 'Publishing to crates.io...'
cargo publish
if ($LASTEXITCODE -ne 0) {
  Warn 'cargo publish failed. Commit and tag exist locally; push was skipped.'
  Warn 'Fix the issue and run: cargo publish && git push --follow-tags'
  Pop-Location
  exit 1
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

  Write-Host "[release] SUCCESS: v$newVersion committed, tagged, published, and pushed."
} else {
  Write-Host '[release] Skipping git push due to -NoPush.'
  Write-Host "[release] SUCCESS: v$newVersion committed, tagged, and published. Push skipped."
}

Pop-Location
exit 0
