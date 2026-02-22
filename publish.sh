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
  echo "- Publishes to crates.io via cargo publish."
  echo "- Publishes Docker image to GitHub Container Registry (ghcr.io) when pushing."
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

cargo_home_path() {
  if [ -n "${CARGO_HOME:-}" ]; then
    echo "$CARGO_HOME"
  elif [ -n "${HOME:-}" ]; then
    echo "$HOME/.cargo"
  else
    echo ".cargo"
  fi
}

has_cargo_registry_token() {
  if [ -n "${CARGO_REGISTRY_TOKEN:-}" ]; then
    return 0
  fi

  local cargo_home
  cargo_home="$(cargo_home_path)"
  local credentials_path
  for credentials_path in "$cargo_home/credentials.toml" "$cargo_home/credentials"; do
    if [ -f "$credentials_path" ] && grep -Eq '^[[:space:]]*token[[:space:]]*=[[:space:]]*".+?"[[:space:]]*$' "$credentials_path"; then
      return 0
    fi
  done

  return 1
}

ensure_cargo_registry_token() {
  if has_cargo_registry_token; then
    return 0
  fi

  warn "No crates.io publish token found (cargo login credentials or CARGO_REGISTRY_TOKEN)."

  if [ ! -t 0 ]; then
    fail "Missing crates.io token for cargo publish." \
      "Set CARGO_REGISTRY_TOKEN in environment, or run cargo login <token>." \
      "Re-run ./publish.sh after token is configured."
  fi

  local input_token=""
  read -rsp "[release] Enter crates.io token (input hidden): " input_token </dev/tty
  echo

  if [ -z "$input_token" ]; then
    fail "crates.io token cannot be empty." \
      "Run cargo login <token>, or rerun this script and provide a valid token when prompted."
  fi

  export CARGO_REGISTRY_TOKEN="$input_token"
  info "Using CARGO_REGISTRY_TOKEN from this shell process only (not saved)."
  info "Running cargo login to persist token for future publishes..."
  if printf '%s\n' "$input_token" | cargo login >/dev/null 2>&1; then
    info "cargo login succeeded; token saved to cargo credentials."
  else
    warn "cargo login failed; continuing with in-memory token for this run only."
  fi
}

resolve_ghcr_image() {
  if [ -n "${GEPHYR_GHCR_IMAGE:-}" ]; then
    echo "${GEPHYR_GHCR_IMAGE,,}"
    return 0
  fi

  local origin
  origin="$(git config --get remote.origin.url 2>/dev/null || true)"
  if [ -z "$origin" ]; then
    return 1
  fi

  origin="${origin%.git}"
  origin="${origin#ssh://git@github.com/}"
  origin="${origin#git@github.com:}"
  origin="${origin#https://github.com/}"
  origin="${origin#http://github.com/}"

  if [[ "$origin" != */* ]]; then
    return 1
  fi

  local owner="${origin%%/*}"
  local repo="${origin#*/}"
  repo="${repo%%/*}"
  if [ -z "$owner" ] || [ -z "$repo" ]; then
    return 1
  fi

  echo "ghcr.io/${owner,,}/${repo,,}"
}

resolve_ghcr_auth() {
  local default_user="$1"

  GHCR_AUTH_TOKEN="${GHCR_TOKEN:-${GITHUB_TOKEN:-}}"
  if [ -z "$GHCR_AUTH_TOKEN" ] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    GHCR_AUTH_TOKEN="$(gh auth token 2>/dev/null || true)"
  fi

  GHCR_AUTH_USER="${GITHUB_ACTOR:-}"
  if [ -z "$GHCR_AUTH_USER" ] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    GHCR_AUTH_USER="$(gh api user -q .login 2>/dev/null || true)"
  fi
  if [ -z "$GHCR_AUTH_USER" ]; then
    GHCR_AUTH_USER="$default_user"
  fi

  if [ -z "$GHCR_AUTH_TOKEN" ]; then
    fail "Missing GHCR auth token for docker publish." \
      "Set GHCR_TOKEN (or GITHUB_TOKEN) with packages:write scope, or run gh auth login." \
      "Re-run ./publish.sh after token is configured."
  fi
  if [ -z "$GHCR_AUTH_USER" ]; then
    fail "Could not resolve GitHub username for GHCR login." \
      "Set GITHUB_ACTOR, or authenticate gh CLI with gh auth login." \
      "Re-run ./publish.sh after username is available."
  fi
}

publish_docker_image_to_ghcr() {
  local version="$1"
  local ghcr_image
  ghcr_image="$(resolve_ghcr_image)" || fail "Could not resolve GHCR image name from git remote." \
    "Ensure origin points to GitHub, or set GEPHYR_GHCR_IMAGE (example: ghcr.io/owner/gephyr)." \
    "Re-run ./publish.sh after GHCR image is configured."

  if ! command -v docker >/dev/null 2>&1; then
    fail "docker is required to publish container package to GHCR." \
      "Install Docker Desktop and ensure docker is in PATH." \
      "Re-run ./publish.sh after Docker is available."
  fi

  if ! docker info >/dev/null 2>&1; then
    fail "Docker daemon is not available; cannot publish container package." \
      "Start Docker Desktop and wait for engine startup to complete." \
      "Re-run ./publish.sh after docker info succeeds."
  fi

  local image_path="${ghcr_image#ghcr.io/}"
  local default_user="${image_path%%/*}"
  resolve_ghcr_auth "$default_user"

  info "Logging in to GHCR as $GHCR_AUTH_USER..."
  if ! printf '%s' "$GHCR_AUTH_TOKEN" | docker login ghcr.io -u "$GHCR_AUTH_USER" --password-stdin >/dev/null 2>&1; then
    fail "GHCR docker login failed." \
      "Verify GHCR token scope includes packages:write." \
      "Try: echo \$GHCR_TOKEN | docker login ghcr.io -u <username> --password-stdin"
  fi

  info "Building Docker image for GHCR: $ghcr_image"
  if ! docker build -f docker/Dockerfile \
    -t "$ghcr_image:v$version" \
    -t "$ghcr_image:$version" \
    -t "$ghcr_image:latest" \
    .; then
    fail "Docker build failed for GHCR publish." \
      "Fix Docker build errors above." \
      "Then rerun ./publish.sh to continue release publish."
  fi

  local tag
  for tag in "v$version" "$version" "latest"; do
    info "Pushing GHCR image tag: $ghcr_image:$tag"
    if ! docker push "$ghcr_image:$tag"; then
      fail "Failed pushing GHCR image tag $ghcr_image:$tag." \
        "Verify repository permissions and token scope (packages:write)." \
        "Retry with: docker push $ghcr_image:$tag"
    fi
  done

  info "GHCR publish complete: $ghcr_image (tags: v$version, $version, latest)"
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
ensure_cargo_registry_token
if ! cargo publish; then
  fail "cargo publish failed. Commit and tag exist locally; push was skipped." \
    "Ensure crates.io token is valid: cargo login <token> or set CARGO_REGISTRY_TOKEN." \
    "After publish succeeds, run: git push --follow-tags"
fi

if [ "$NO_PUSH" = false ]; then
  publish_docker_image_to_ghcr "$NEW_VERSION"
else
  warn "Skipping GHCR Docker publish due to -NoPush."
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

  echo "[release] SUCCESS: v$NEW_VERSION committed, tagged, crate published, GHCR image published, and git pushed."
else
  warn "Skipping git push due to -NoPush."
  echo "[release] SUCCESS: v$NEW_VERSION committed, tagged, and crate published. Push + GHCR publish skipped."
fi

popd > /dev/null
exit 0
