#!/usr/bin/env bash
set -e

BUMP="patch"
RELEASE_TYPE=""
SKIP_TESTS=false
HELP=false
NO_PUSH=false
NEW_VERSION=""

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -Bump|--bump) BUMP="$2"; shift ;;
    -ReleaseType|--release-type) RELEASE_TYPE="$2"; shift ;;
    -SkipTests|--skip-tests) SKIP_TESTS=true ;;
    -Help|--help|-h) HELP=true ;;
    -NoPush|--no-push) NO_PUSH=true ;;
    *) echo "Unknown parameter passed: $1"; exit 1 ;;
  esac
  shift
done

if [ "$HELP" = true ]; then
  echo ""
  echo "Usage:"
  echo "  ./publish.sh [-Bump patch|minor|major|prerelease|x.y.z] [-ReleaseType fix|feat|chore] [-SkipTests] [-NoPush]"
  echo ""
  echo "Notes:"
  echo "- Requires clean git working tree."
  echo "- If -Bump is omitted, prompts interactively for release intent."
  echo "- Bumps version in Cargo.toml and updates Cargo.lock."
  echo "- Runs cargo build --release and cargo test as preflight checks."
  echo "- Commits Cargo.toml and Cargo.lock, creates git tag."
  echo "- Pushes git commit and tags (unless -NoPush) and creates GitHub Release."
  echo "- Use -SkipTests to skip the cargo test preflight step."
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pushd "$REPO_ROOT" > /dev/null

info() {
  echo "[release] INFO: $1"
}

warn() {
  echo "[release] WARN: $1"
}

fail() {
  local message="$1"
  shift || true

  local rollback=false
  local hints=()
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "-Rollback" ]; then
      rollback=true
    else
      hints+=("$1")
    fi
    shift
  done

  if [ "$rollback" = true ]; then
    rollback_version_files
  fi

  echo ""
  echo "[release] ERROR: $message"
  if [ "${#hints[@]}" -gt 0 ]; then
    echo "[release] Next steps:"
    for hint in "${hints[@]}"; do
      echo "  - $hint"
    done
  fi

  popd > /dev/null
  exit 1
}

get_cargo_version() {
  local cargo_toml="$REPO_ROOT/Cargo.toml"
  if [ ! -f "$cargo_toml" ]; then
    return
  fi
  grep -m 1 -E '^\s*version\s*=\s*' "$cargo_toml" | sed -E 's/.*"([^"]+)".*/\1/'
}

set_cargo_version() {
  local new_version="$1"
  local cargo_toml="$REPO_ROOT/Cargo.toml"
  # Support both GNU and BSD sed
  sed -i.bak -E 's/^( *version *= *)"[^"]+"/\1"'"$new_version"'"/' "$cargo_toml"
  rm -f "$cargo_toml.bak"
}

bump_semver() {
  local current="$1"
  local bump_type="$2"
  
  if [[ "$bump_type" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "$bump_type"
    return
  fi

  local base="${current%-*}"
  local prerelease=""
  if [[ "$current" == *-* ]]; then
    prerelease="${current#*-}"
  fi

  IFS='.' read -r major minor patch <<< "$base"

  case "$bump_type" in
    major)
      major=$((major + 1))
      minor=0
      patch=0
      prerelease=""
      ;;
    minor)
      minor=$((minor + 1))
      patch=0
      prerelease=""
      ;;
    patch)
      patch=$((patch + 1))
      prerelease=""
      ;;
    prerelease)
      if [ -z "$prerelease" ]; then
        patch=$((patch + 1))
        prerelease="0"
      else
        local pre_id="${prerelease%%.*}"
        local pre_num="${prerelease##*.}"
        if [[ "$pre_id" == "$pre_num" ]]; then
          if [[ "$prerelease" =~ ^[0-9]+$ ]]; then
             prerelease=$((prerelease + 1))
          else
             prerelease="${prerelease}.0"
          fi
        else
          pre_num=$((pre_num + 1))
          prerelease="${pre_id}.${pre_num}"
        fi
      fi
      ;;
    *)
      fail "Unknown bump type: $bump_type"
      ;;
  esac

  local next_version="${major}.${minor}.${patch}"
  if [ -n "$prerelease" ]; then
    next_version="${next_version}-${prerelease}"
  fi
  echo "$next_version"
}

get_default_release_type() {
  case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
    minor|major) echo "feat" ;;
    patch) echo "fix" ;;
    *) echo "chore" ;;
  esac
}

select_release_plan_interactive() {
  local current_bump="$1"
  local current_type="$2"

  while true; do
    echo ""
    echo "[release] Choose release intent:"
    echo "  1) fix   -> patch (bug fix)"
    echo "  2) feat  -> minor (new feature)"
    echo "  3) chore -> patch (maintenance)"
    echo "  4) major -> major (breaking change)"
    echo "  5) prerelease -> prerelease"
    echo "  6) Custom bump + custom type"
    echo "  7) Cancel release"
    read -p "[release] Select 1-7: " choice </dev/tty

    case "$choice" in
      1) BUMP="patch"; RELEASE_TYPE="fix"; return 0 ;;
      2) BUMP="minor"; RELEASE_TYPE="feat"; return 0 ;;
      3) BUMP="patch"; RELEASE_TYPE="chore"; return 0 ;;
      4) BUMP="major"; RELEASE_TYPE="feat"; return 0 ;;
      5)
        BUMP="prerelease"
        if [ -n "$current_type" ]; then
          RELEASE_TYPE="$current_type"
        else
          RELEASE_TYPE="chore"
        fi
        return 0
        ;;
      6)
        read -p "Enter bump (patch/minor/major/prerelease/x.y.z): " custom_bump </dev/tty
        if [ -z "$custom_bump" ]; then continue; fi
        read -p "Enter release type (feat/fix/chore/etc): " custom_type </dev/tty
        if [ -z "$custom_type" ]; then continue; fi
        BUMP="$custom_bump"
        RELEASE_TYPE="$custom_type"
        return 0
        ;;
      7) return 1 ;;
      *) echo "[release] Invalid selection. Enter 1-7." ;;
    esac
  done
}

rollback_version_files() {
  if [ -z "$NEW_VERSION" ]; then return; fi
  info "Rolling back local version files..."
  git checkout -- Cargo.toml >/dev/null 2>&1 || true
  if [ -f "Cargo.lock" ]; then git checkout -- Cargo.lock >/dev/null 2>&1 || true; fi
}

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  fail "Current directory is not a git repository."
fi

if ! git diff-index --quiet HEAD --; then
  warn "Working tree is not clean. Commit or stash changes first."
  git status --short
  popd > /dev/null
  exit 1
fi

OLD_VERSION=$(get_cargo_version)
if [ -z "$OLD_VERSION" ]; then
  fail "Could not determine local package version from Cargo.toml."
fi

echo "[release] Current local version: $OLD_VERSION"

if [ "$BUMP" = "patch" ] && [ -z "$RELEASE_TYPE" ]; then
  if ! select_release_plan_interactive "$BUMP" "$RELEASE_TYPE"; then
    info "Release cancelled."
    popd > /dev/null
    exit 0
  fi
fi

if [ -z "$RELEASE_TYPE" ]; then
  RELEASE_TYPE=$(get_default_release_type "$BUMP")
fi

NEW_VERSION=$(bump_semver "$OLD_VERSION" "$BUMP")
echo "[release] Planning $RELEASE_TYPE release, bumping $BUMP: $OLD_VERSION -> $NEW_VERSION"

set_cargo_version "$NEW_VERSION"
if [ -f "Cargo.lock" ]; then
  info "Updating Cargo.lock..."
  if ! cargo update --workspace >/dev/null 2>&1; then
    warn "cargo update --workspace failed; Cargo.lock may be stale."
  fi
fi

info "Running preflight build: cargo build --release"
if ! cargo build --release; then
  fail "Preflight build failed (cargo build --release)." "-Rollback" \
    "Review the build errors above and fix compile issues." \
    "Re-run this script after the build passes."
fi

if [ "$SKIP_TESTS" = false ]; then
  info "Running preflight tests: cargo test"
  if ! cargo test; then
    fail "Preflight tests failed (cargo test). Release stopped to keep the publish safe." "-Rollback" \
      "Re-run with extra output: cargo test -- --nocapture" \
      "Fix failing tests, then run ./publish.sh again." \
      "If you intentionally want to skip tests (not recommended), run ./publish.sh -SkipTests"
  fi
else
  warn "Skipping tests due to -SkipTests."
fi

git add Cargo.toml
if [ -f "Cargo.lock" ]; then git add Cargo.lock; fi

if ! git commit -m "$RELEASE_TYPE(release): v$NEW_VERSION"; then
  fail "git commit failed." "-Rollback"
fi

echo "[release] Creating git tag v$NEW_VERSION..."
if ! git tag -a "v$NEW_VERSION" -m "$RELEASE_TYPE(release): v$NEW_VERSION"; then
  fail "git tag failed."
fi

info "Publishing to crates.io..."
if ! cargo publish; then
  warn "cargo publish failed. Commit and tag exist locally; push was skipped."
  warn "Fix the issue and run: cargo publish && git push --follow-tags"
  popd > /dev/null
  exit 1
fi

if [ "$NO_PUSH" = false ]; then
  info "Pushing commit and tags to git remote..."
  if ! git push --follow-tags; then
    warn "git push failed. Commit exists locally; push manually."
    popd > /dev/null
    exit 1
  fi

  if command -v gh >/dev/null 2>&1; then
    info "Creating GitHub Release..."
    if ! gh release create "v$NEW_VERSION" --title "v$NEW_VERSION" --generate-notes; then
      warn "GitHub Release creation failed. Create it manually at:"
      echo "  https://github.com/softerist/gephyr/releases/new"
    else
      echo "[release] GitHub Release v$NEW_VERSION created."
    fi
  else
    warn "gh CLI not found. Skipping GitHub Release creation."
    info "Install gh from https://cli.github.com to enable this feature."
  fi

  echo "[release] SUCCESS: v$NEW_VERSION committed, tagged, published, and pushed."
else
  warn "Skipping git push due to -NoPush."
  echo "[release] SUCCESS: v$NEW_VERSION committed, tagged, and published. Push skipped."
fi

popd > /dev/null
exit 0
