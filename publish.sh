#!/usr/bin/env bash
set -euo pipefail

# Defaults
BUMP="patch"
RELEASE_TYPE=""
SKIP_TESTS=false
NO_PUSH=false
usage() {
  echo ""
  echo "Usage:"
  echo "  ./publish.sh [-b patch|minor|major|prerelease|x.y.z] [-t fix|feat|chore] [--skip-tests] [--no-push]"
  echo ""
  echo "Options:"
  echo "  -b, --bump          Version bump type (default: patch)"
  echo "  -t, --type          Release type for commit message (default: derived from bump)"
  echo "  --skip-tests        Skip cargo test preflight step"
  echo "  --no-push           Skip git push after commit and tag"
  echo "  -h, --help          Show this help message"
  echo ""
  echo "Notes:"
  echo "- Requires clean git working tree."
  echo "- If --bump is omitted, prompts interactively for release intent (fix/feat/chore/etc)."
  echo "- Bumps version in Cargo.toml and updates Cargo.lock."
  echo "- Runs cargo build --release and cargo test as preflight checks."
  echo "- Commits Cargo.toml and Cargo.lock, creates git tag."
  echo "- Publishes to crates.io via cargo publish."
  echo "- Pushes git commit and tags (unless --no-push)."
  echo ""
  exit 0
}

BUMP_PROVIDED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--bump)
      BUMP="$2"
      BUMP_PROVIDED=true
      shift 2
      ;;
    -t|--type)
      RELEASE_TYPE="$2"
      shift 2
      ;;
    --skip-tests)
      SKIP_TESTS=true
      shift
      ;;
    --no-push)
      NO_PUSH=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "[release] Unknown option: $1"
      usage
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

NEW_VERSION=""

get_cargo_version() {
  grep -m1 '^version\s*=' Cargo.toml | sed 's/^version\s*=\s*"\([^"]*\)".*/\1/'
}

set_cargo_version() {
  local version="$1"
  sed -i.bak "0,/^version\s*=\s*\"[^\"]*\"/s/^version\s*=\s*\"[^\"]*\"/version = \"$version\"/" Cargo.toml
  rm -f Cargo.toml.bak
}

bump_semver() {
  local current="$1"
  local bump_type="$2"

  # If bump_type looks like a full semver (x.y.z), use it directly
  if [[ "$bump_type" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "$bump_type"
    return
  fi

  # Parse current version
  if [[ ! "$current" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-(.+))?$ ]]; then
    echo ""
    return
  fi

  local major="${BASH_REMATCH[1]}"
  local minor="${BASH_REMATCH[2]}"
  local patch="${BASH_REMATCH[3]}"
  local prerelease="${BASH_REMATCH[5]}"

  case "${bump_type,,}" in
    major)
      echo "$(( major + 1 )).0.0"
      ;;
    minor)
      echo "$major.$(( minor + 1 )).0"
      ;;
    patch)
      echo "$major.$minor.$(( patch + 1 ))"
      ;;
    prerelease)
      if [[ -n "$prerelease" ]] && [[ "$prerelease" =~ ^(.+)\.([0-9]+)$ ]]; then
        local pre_tag="${BASH_REMATCH[1]}"
        local pre_num=$(( BASH_REMATCH[2] + 1 ))
        echo "$major.$minor.$patch-$pre_tag.$pre_num"
      elif [[ -n "$prerelease" ]]; then
        echo "$major.$minor.$patch-$prerelease.1"
      else
        echo "$major.$minor.$(( patch + 1 ))-rc.0"
      fi
      ;;
    *)
      echo ""
      ;;
  esac
}

get_default_release_type() {
  local bump_val="${1,,}"
  case "$bump_val" in
    minor|major) echo "feat" ;;
    patch)       echo "fix" ;;
    *)           echo "chore" ;;
  esac
}

select_release_plan_interactive() {
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
    read -rp "[release] Select 1-7: " choice

    case "$choice" in
      1) BUMP="patch";      RELEASE_TYPE="fix";   return 0 ;;
      2) BUMP="minor";      RELEASE_TYPE="feat";  return 0 ;;
      3) BUMP="patch";      RELEASE_TYPE="chore"; return 0 ;;
      4) BUMP="major";      RELEASE_TYPE="feat";  return 0 ;;
      5) BUMP="prerelease";                       return 0 ;;
      6)
        read -rp "[release] Enter bump (patch|minor|major|prerelease|x.y.z): " custom_bump
        if [[ -z "$custom_bump" ]]; then
          echo "[release] Bump cannot be empty."
          continue
        fi

        read -rp "[release] Enter release type (current: $RELEASE_TYPE): " custom_type
        custom_type="${custom_type,,}"
        [[ -z "$custom_type" ]] && custom_type="$RELEASE_TYPE"
        [[ -z "$custom_type" ]] && custom_type="chore"
        if [[ ! "$custom_type" =~ ^[a-z][a-z0-9-]*$ ]]; then
          echo "[release] Invalid type. Use lowercase letters/numbers/hyphen (example: fix, feat, chore)."
          continue
        fi

        BUMP="$custom_bump"
        RELEASE_TYPE="$custom_type"
        return 0
        ;;
      7) return 1 ;;
      *)
        echo "[release] Invalid selection. Enter 1-7."
        ;;
    esac
  done
}

rollback_version_files() {
  if [[ -z "$NEW_VERSION" ]]; then return; fi
  echo "[release] Rolling back local version files..."
  git checkout -- Cargo.toml 2>/dev/null || true
  if [[ -f "Cargo.lock" ]]; then
    git checkout -- Cargo.lock 2>/dev/null || true
  fi
}

fail() {
  local message="$1"
  local rollback="${2:-false}"
  if [[ "$rollback" == "true" ]]; then
    rollback_version_files
  fi
  echo "[release] ERROR: $message" >&2
  exit 1
}

# --- Main flow ---

if [[ -z "$RELEASE_TYPE" ]]; then
  RELEASE_TYPE="$(get_default_release_type "$BUMP")"
fi

if [[ "$BUMP_PROVIDED" == "false" ]]; then
  if ! select_release_plan_interactive; then
    fail "Release selection canceled."
  fi
fi

if [[ ! "$RELEASE_TYPE" =~ ^[a-z][a-z0-9-]*$ ]]; then
  fail "Invalid --type '$RELEASE_TYPE'. Use lowercase letters/numbers/hyphen."
fi

echo "[release] Repository: $REPO_ROOT"
echo "[release] Version bump: $BUMP"
echo "[release] Release type: $RELEASE_TYPE"

# Check prerequisites
command -v git   >/dev/null 2>&1 || fail "git is not available in PATH."
command -v cargo >/dev/null 2>&1 || fail "cargo is not available in PATH."

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "Current directory is not a git repository."

dirty="$(git status --porcelain)"
if [[ -n "$dirty" ]]; then
  echo "[release] ERROR: Working tree is not clean. Commit or stash changes first."
  git status --short
  exit 1
fi

# Read current version from Cargo.toml
old_version="$(get_cargo_version)"
if [[ -z "$old_version" ]]; then
  fail "Could not read version from Cargo.toml."
fi
echo "[release] Current version: $old_version"

# Bump version
NEW_VERSION="$(bump_semver "$old_version" "$BUMP")"
if [[ -z "$NEW_VERSION" ]]; then
  fail "Failed to compute new version from '$old_version' with bump '$BUMP'."
fi

set_cargo_version "$NEW_VERSION"
echo "[release] New version: $NEW_VERSION"

# Update Cargo.lock
echo "[release] Updating Cargo.lock..."
cargo update --workspace >/dev/null 2>&1 || echo "[release] Warning: cargo update --workspace failed; Cargo.lock may be stale."

# Preflight: build
echo "[release] Running cargo build --release..."
if ! cargo build --release; then
  fail "cargo build --release failed." "true"
fi

# Preflight: tests
if [[ "$SKIP_TESTS" == "false" ]]; then
  echo "[release] Running cargo test..."
  if ! cargo test; then
    fail "cargo test failed." "true"
  fi
else
  echo "[release] Skipping tests due to --skip-tests."
fi

# Git commit
git add Cargo.toml
if [[ -f "Cargo.lock" ]]; then git add Cargo.lock; fi

if ! git commit -m "$RELEASE_TYPE(release): v$NEW_VERSION"; then
  fail "git commit failed." "true"
fi

# Git tag
echo "[release] Creating git tag v$NEW_VERSION..."
if ! git tag -a "v$NEW_VERSION" -m "$RELEASE_TYPE(release): v$NEW_VERSION"; then
  fail "git tag failed."
fi

# Publish to crates.io
echo "[release] Publishing to crates.io..."
if ! cargo publish; then
  echo "[release] ERROR: cargo publish failed. Commit and tag exist locally; push skipped."
  echo "[release] Fix the issue and run: cargo publish && git push --follow-tags"
  exit 1
fi

# Push
if [[ "$NO_PUSH" == "false" ]]; then
  echo "[release] Pushing commit and tags to git remote..."
  if ! git push --follow-tags; then
    echo "[release] ERROR: git push failed. Commit exists locally; push manually."
    exit 1
  fi
  echo "[release] SUCCESS: v$NEW_VERSION committed, tagged, published, and pushed."
else
  echo "[release] Skipping git push due to --no-push."
  echo "[release] SUCCESS: v$NEW_VERSION committed, tagged, and published. Push skipped."
fi

exit 0
