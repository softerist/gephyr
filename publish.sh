#!/usr/bin/env bash
set -e

BUMP="patch"
RELEASE_TYPE=""
SKIP_TESTS=false
HELP=false
NO_PUSH=false
RESUME=false
RESUME_VERSION=""
NEW_VERSION=""
GHCR_PACKAGE_STATUS_SUMMARY="not checked (GHCR publish not attempted)."

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -Bump|--bump) BUMP="$2"; shift ;;
    -ReleaseType|--release-type) RELEASE_TYPE="$2"; shift ;;
    -SkipTests|--skip-tests) SKIP_TESTS=true ;;
    -Help|--help|-h) HELP=true ;;
    -NoPush|--no-push) NO_PUSH=true ;;
    -Resume|--resume) RESUME=true ;;
    -ResumeVersion|--resume-version) RESUME_VERSION="$2"; shift ;;
    *) echo "Unknown parameter passed: $1"; exit 1 ;;
  esac
  shift
done

if [ "$HELP" = true ]; then
  echo ""
  echo "Usage:"
  echo "  ./publish.sh [-Bump patch|minor|major|prerelease|x.y.z] [-ReleaseType fix|feat|chore] [-SkipTests] [-NoPush]"
  echo "  ./publish.sh --resume [--resume-version x.y.z] [--no-push]"
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
  echo "- Use --resume to continue a partially completed release (after commit/tag/crates publish)."
  echo "- --resume-version is optional; defaults to Cargo.toml version."
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

assert_required_tools() {
  local require_docker="$1"
  local require_gh_for_auth="$2"
  local missing=()

  local tool
  for tool in git cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done

  if [ "$require_docker" = true ] && ! command -v docker >/dev/null 2>&1; then
    missing+=("docker")
  fi

  if [ "$require_gh_for_auth" = true ] && ! command -v gh >/dev/null 2>&1; then
    missing+=("gh")
  fi

  if [ "${#missing[@]}" -gt 0 ]; then
    local missing_list
    missing_list="$(IFS=', '; echo "${missing[*]}")"
    local hints=(
      "Install missing tools and ensure they are available in PATH for this shell session."
    )
    if [ "$require_gh_for_auth" = true ]; then
      hints+=("Or set GHCR_TOKEN/GITHUB_TOKEN to skip interactive gh authentication for GHCR publish.")
    fi

    fail "Missing required tools in PATH: $missing_list." "${hints[@]}"
  fi

  if [ "$NO_PUSH" = false ] && ! command -v gh >/dev/null 2>&1; then
    warn "gh CLI is not available; GitHub Release creation and package metadata checks will be skipped."
  fi
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

normalize_version_literal() {
  local raw="${1:-}"
  raw="${raw#v}"
  if [[ "$raw" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]]; then
    echo "$raw"
    return 0
  fi
  return 1
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

ensure_gh_cli_auth_with_scopes() {
  if ! command -v gh >/dev/null 2>&1; then
    fail "gh CLI is required for interactive GHCR authentication when GHCR_TOKEN is not set." \
      "Install gh from https://cli.github.com, or set GHCR_TOKEN/GITHUB_TOKEN with packages:write scope." \
      "Re-run ./publish.sh after auth prerequisites are available."
  fi

  if ! gh auth status -h github.com >/dev/null 2>&1; then
    if [ ! -t 0 ]; then
      fail "GitHub authentication is required for GHCR publish, but this session is non-interactive." \
        "Set GHCR_TOKEN/GITHUB_TOKEN with packages:write scope for non-interactive usage." \
        "Or run this script in an interactive terminal."
    fi

    warn "No active GitHub CLI auth found. Starting interactive gh auth login..."
    if ! gh auth login -h github.com -s repo -s write:packages -s read:packages; then
      fail "gh auth login failed." \
        "Retry: gh auth login -h github.com -s repo -s write:packages -s read:packages" \
        "Or set GHCR_TOKEN/GITHUB_TOKEN with packages:write scope."
    fi
  fi

  local status_text
  status_text="$(gh auth status -h github.com -t 2>&1 || true)"
  if ! printf '%s' "$status_text" | grep -q "write:packages"; then
    if [ ! -t 0 ]; then
      fail "GitHub token is missing write:packages scope for GHCR publish." \
        "Refresh scopes interactively: gh auth refresh -h github.com -s write:packages -s read:packages -s repo" \
        "Or set GHCR_TOKEN/GITHUB_TOKEN with packages:write scope."
    fi

    warn "GitHub token is missing write:packages scope. Refreshing gh auth scopes interactively..."
    if ! gh auth refresh -h github.com -s write:packages -s read:packages -s repo; then
      fail "gh auth refresh failed; required scopes not granted." \
        "Run: gh auth refresh -h github.com -s write:packages -s read:packages -s repo" \
        "Then rerun ./publish.sh."
    fi
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

  GHCR_AUTH_TOKENS=()
  GHCR_AUTH_TOKEN_SOURCES=()

  local seen_tokens="|"
  local add_candidate_token
  add_candidate_token() {
    local token_value="$1"
    local token_source="$2"
    if [ -z "$token_value" ]; then
      return
    fi
    if [[ "$seen_tokens" == *"|$token_value|"* ]]; then
      return
    fi
    seen_tokens="${seen_tokens}${token_value}|"
    GHCR_AUTH_TOKENS+=("$token_value")
    GHCR_AUTH_TOKEN_SOURCES+=("$token_source")
  }

  if [ -n "${GHCR_TOKEN:-}" ]; then
    add_candidate_token "${GHCR_TOKEN}" "GHCR_TOKEN"
  fi
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    add_candidate_token "${GITHUB_TOKEN}" "GITHUB_TOKEN"
  fi

  if [ "${#GHCR_AUTH_TOKENS[@]}" -eq 0 ]; then
    ensure_gh_cli_auth_with_scopes
  fi

  if command -v gh >/dev/null 2>&1 && gh auth status -h github.com >/dev/null 2>&1; then
    local gh_token
    gh_token="$(gh auth token 2>/dev/null || true)"
    add_candidate_token "$gh_token" "gh auth token"
  fi

  GHCR_AUTH_USER="${GITHUB_ACTOR:-}"
  if [ -z "$GHCR_AUTH_USER" ] && command -v gh >/dev/null 2>&1 && gh auth status -h github.com >/dev/null 2>&1; then
    GHCR_AUTH_USER="$(gh api user -q .login 2>/dev/null || true)"
  fi
  if [ -z "$GHCR_AUTH_USER" ]; then
    GHCR_AUTH_USER="$default_user"
  fi
  if [ -z "$GHCR_AUTH_USER" ] && [ -t 0 ]; then
    read -r -p "[release] Enter GitHub username for GHCR login: " GHCR_AUTH_USER
  fi

  if [ "${#GHCR_AUTH_TOKENS[@]}" -eq 0 ] && [ -t 0 ]; then
    warn "No GHCR token detected in environment or gh auth. Prompting for token."
    local prompt_token
    read -r -s -p "[release] Enter GHCR token (input hidden): " prompt_token
    echo ""
    add_candidate_token "$prompt_token" "interactive prompt"
  fi

  if [ "${#GHCR_AUTH_TOKENS[@]}" -eq 0 ]; then
    fail "Missing GHCR auth token for docker publish." \
      "Set GHCR_TOKEN (or GITHUB_TOKEN) with packages:write scope, or run gh auth login/refresh." \
      "Re-run ./publish.sh after token is configured."
  fi
  if [ -z "$GHCR_AUTH_USER" ]; then
    fail "Could not resolve GitHub username for GHCR login." \
      "Set GITHUB_ACTOR, or authenticate gh CLI with gh auth login." \
      "Re-run ./publish.sh after username is available."
  fi
}

get_github_repo_slug() {
  local ghcr_image
  ghcr_image="$(resolve_ghcr_image 2>/dev/null || true)"
  if [ -z "$ghcr_image" ]; then
    return 1
  fi
  echo "${ghcr_image#ghcr.io/}"
}

ensure_release_tag_exists() {
  local version="$1"
  if ! git rev-parse --verify "refs/tags/v$version" >/dev/null 2>&1; then
    fail "Tag v$version was not found locally." \
      "Use full release mode first to create the tag, or pass the correct --resume-version." \
      "If tag exists remotely only, run: git fetch --tags"
  fi
}

push_and_create_github_release() {
  local version="$1"

  info "Pushing commit and tags to git remote..."
  if ! git push --follow-tags; then
    warn "git push failed. Commit/tag exist locally; push manually."
    popd > /dev/null
    exit 1
  fi

  if command -v gh >/dev/null 2>&1; then
    if gh release view "v$version" >/dev/null 2>&1; then
      info "GitHub Release v$version already exists; skipping create."
    else
      info "Creating GitHub Release..."
      if ! gh release create "v$version" --title "v$version" --generate-notes; then
        warn "GitHub Release creation failed. Create it manually at:"
        echo "  https://github.com/softerist/gephyr/releases/new"
      else
        echo "[release] GitHub Release v$version created."
      fi
    fi
  else
    warn "gh CLI not found. Skipping GitHub Release creation."
    info "Install gh from https://cli.github.com to enable this feature."
  fi
}

confirm_ghcr_package_discoverability() {
  local ghcr_image="$1"

  if ! command -v gh >/dev/null 2>&1; then
    GHCR_PACKAGE_STATUS_SUMMARY="not checked (gh CLI unavailable)."
    return 0
  fi
  if ! gh auth status -h github.com >/dev/null 2>&1; then
    GHCR_PACKAGE_STATUS_SUMMARY="not checked (gh auth unavailable)."
    return 0
  fi
  if [[ ! "$ghcr_image" =~ ^ghcr\.io/([^/]+)/(.+)$ ]]; then
    GHCR_PACKAGE_STATUS_SUMMARY="not checked (unable to parse GHCR image name)."
    return 0
  fi

  local owner="${BASH_REMATCH[1]}"
  local package_name="${BASH_REMATCH[2]}"
  local encoded_package="${package_name//\//%2F}"
  local endpoint="/users/$owner/packages/container/$encoded_package"

  local package_visibility
  package_visibility="$(gh api "$endpoint" -q .visibility 2>/dev/null || true)"
  if [ -z "$package_visibility" ]; then
    warn "Unable to inspect GHCR package metadata for $ghcr_image."
    GHCR_PACKAGE_STATUS_SUMMARY="unknown (failed reading package metadata for $ghcr_image)."
    return 0
  fi

  local package_url
  package_url="$(gh api "$endpoint" -q .html_url 2>/dev/null || true)"
  if [ -z "$package_url" ]; then
    package_url="https://github.com/users/$owner/packages/container/package/$package_name"
  fi

  if [ "$package_visibility" = "private" ]; then
    warn "GHCR package is private: $ghcr_image"
    warn "Private package visibility can hide it from repo sidebar package listings."
    warn "Set visibility in GitHub UI: $package_url/settings"
  fi

  local repo_slug
  repo_slug="$(get_github_repo_slug 2>/dev/null || true)"
  local package_repo_link
  package_repo_link="$(gh api "$endpoint" -q .repository.full_name 2>/dev/null || true)"
  if [ -z "$package_repo_link" ]; then
    package_repo_link="$(gh api "$endpoint" -q .repository.nameWithOwner 2>/dev/null || true)"
  fi
  if [ -z "$package_repo_link" ] && [ -n "$repo_slug" ]; then
    warn "If repo sidebar still shows 'No packages published', connect this package to repository $repo_slug."
    warn "Package settings: $package_url/settings"
    GHCR_PACKAGE_STATUS_SUMMARY="visibility=$package_visibility, repository_link=missing (expected $repo_slug; configure: $package_url/settings)"
  elif [ -z "$package_repo_link" ]; then
    warn "If repo sidebar still shows 'No packages published', open package settings: $package_url/settings"
    GHCR_PACKAGE_STATUS_SUMMARY="visibility=$package_visibility, repository_link=missing (configure: $package_url/settings)"
  elif [ "$package_visibility" = "public" ]; then
    info "GHCR package is public and linked for discoverability: $ghcr_image"
    GHCR_PACKAGE_STATUS_SUMMARY="visibility=$package_visibility, repository_link=$package_repo_link"
  else
    GHCR_PACKAGE_STATUS_SUMMARY="visibility=$package_visibility, repository_link=$package_repo_link"
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
  local login_ok=false
  local login_errors=()
  local idx
  for idx in "${!GHCR_AUTH_TOKENS[@]}"; do
    local token="${GHCR_AUTH_TOKENS[$idx]}"
    local source="${GHCR_AUTH_TOKEN_SOURCES[$idx]}"
    info "Trying GHCR auth via $source..."

    local login_output
    if login_output="$(printf '%s' "$token" | docker login ghcr.io -u "$GHCR_AUTH_USER" --password-stdin 2>&1)"; then
      info "GHCR docker login succeeded via $source."
      login_ok=true
      break
    fi

    warn "GHCR login attempt via $source failed."
    login_output="$(printf '%s' "$login_output" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
    login_errors+=("$source: ${login_output:-"(no docker error text)"}")
  done

  if [ "$login_ok" = false ]; then
    if [ "${#login_errors[@]}" -gt 0 ]; then
      warn "GHCR login failure details: $(IFS=' | '; echo "${login_errors[*]}")"
    fi
    if [ -t 0 ]; then
      warn "All detected GHCR tokens failed. You can enter a fresh token now."
      local prompt_retry_token
      read -r -s -p "[release] Enter GHCR token (input hidden, leave blank to skip): " prompt_retry_token
      echo ""
      if [ -n "$prompt_retry_token" ]; then
        info "Trying GHCR auth via interactive prompt token..."
        if printf '%s' "$prompt_retry_token" | docker login ghcr.io -u "$GHCR_AUTH_USER" --password-stdin >/dev/null 2>&1; then
          info "GHCR docker login succeeded via interactive prompt token."
          login_ok=true
        else
          warn "Interactive GHCR token login failed."
        fi
      fi
    fi
  fi

  if [ "$login_ok" = false ]; then
    fail "GHCR docker login failed." \
      "Verify GHCR token scope includes write:packages (and read:packages)." \
      "If GHCR_TOKEN/GITHUB_TOKEN is stale, clear it and rely on gh auth token." \
      "Try: gh auth refresh -h github.com -s write:packages -s read:packages -s repo" \
      "Try: echo \$GHCR_TOKEN | docker login ghcr.io -u <username> --password-stdin"
  fi

  local max_build_attempts=3
  local build_ok=false
  local attempt
  for attempt in $(seq 1 "$max_build_attempts"); do
    info "Building Docker image for GHCR: $ghcr_image (platform linux/amd64, provenance disabled) [attempt $attempt/$max_build_attempts]"
    local build_log
    build_log="$(mktemp)"
    if docker build --platform linux/amd64 --provenance=false --sbom=false -f docker/Dockerfile \
      -t "$ghcr_image:v$version" \
      -t "$ghcr_image:$version" \
      -t "$ghcr_image:latest" \
      . 2>&1 | tee "$build_log"; then
      build_ok=true
      rm -f "$build_log"
      break
    fi

    if grep -Eqi 'DeadlineExceeded|context deadline exceeded|TLS handshake timeout|i/o timeout|failed to resolve source metadata|temporary failure|connection reset|EOF' "$build_log" && [ "$attempt" -lt "$max_build_attempts" ]; then
      local sleep_sec=$((5 * attempt))
      warn "Docker build failed due to transient network/registry error. Retrying in ${sleep_sec}s..."
      rm -f "$build_log"
      sleep "$sleep_sec"
      continue
    fi

    rm -f "$build_log"
    break
  done

  if [ "$build_ok" = false ]; then
    fail "Docker build failed for GHCR publish." \
      "Network/registry timeout can be transient. Retry ./publish.sh once network is stable." \
      "If persistent, run: docker pull debian:bookworm-slim and docker pull rust:1.88-slim" \
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
  confirm_ghcr_package_discoverability "$ghcr_image"
}

require_docker=false
if [ "$NO_PUSH" = false ]; then
  require_docker=true
fi
require_gh_for_auth=false
if [ "$NO_PUSH" = false ] && [ -z "${GHCR_TOKEN:-}" ] && [ -z "${GITHUB_TOKEN:-}" ]; then
  require_gh_for_auth=true
fi
assert_required_tools "$require_docker" "$require_gh_for_auth"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  fail "Current directory is not a git repository."
fi

if [ "$RESUME" = true ]; then
  local_resume_version="$RESUME_VERSION"
  if [ -z "$local_resume_version" ]; then
    local_resume_version="$(get_cargo_version)"
  fi

  if ! NEW_VERSION="$(normalize_version_literal "$local_resume_version")"; then
    fail "Invalid resume version '$local_resume_version'." \
      "Pass --resume-version x.y.z (or vx.y.z), for example: --resume-version 1.16.15"
  fi

  old_version_now="$(get_cargo_version)"
  if [ -n "$old_version_now" ] && [ "$old_version_now" != "$NEW_VERSION" ]; then
    warn "Cargo.toml version is $old_version_now while resume target is $NEW_VERSION."
  fi

  ensure_release_tag_exists "$NEW_VERSION"

  echo "[release] Repository: $REPO_ROOT"
  echo "[release] Resume mode: true"
  echo "[release] Target version: $NEW_VERSION"

  if ! git diff-index --quiet HEAD --; then
    warn "Working tree is not clean. Resume mode continues because it does not create a new commit."
  fi

  if [ "$NO_PUSH" = false ]; then
    publish_docker_image_to_ghcr "$NEW_VERSION"
    push_and_create_github_release "$NEW_VERSION"
    echo "[release] SUCCESS: Resume completed for v$NEW_VERSION (GHCR publish + git push + GitHub Release)."
    echo "[release] Package visibility/link status: $GHCR_PACKAGE_STATUS_SUMMARY"
  else
    warn "Skipping GHCR publish and git push due to --no-push in resume mode."
    GHCR_PACKAGE_STATUS_SUMMARY="skipped (-NoPush)."
    echo "[release] SUCCESS: Resume validation complete for v$NEW_VERSION. No network publish performed."
    echo "[release] Package visibility/link status: $GHCR_PACKAGE_STATUS_SUMMARY"
  fi

  popd > /dev/null
  exit 0
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
set +e
publish_output="$(cargo publish 2>&1)"
publish_exit=$?
set -e
printf '%s\n' "$publish_output"
if [ $publish_exit -ne 0 ]; then
  if printf '%s' "$publish_output" | grep -qi "verified email address is required"; then
    fail "cargo publish failed. Commit and tag exist locally; push was skipped." \
      "Verify your crates.io email at https://crates.io/settings/profile, then retry cargo publish." \
      "After publish succeeds, run: git push --follow-tags"
  fi

  fail "cargo publish failed. Commit and tag exist locally; push was skipped." \
    "Ensure crates.io token is valid: cargo login <token> or set CARGO_REGISTRY_TOKEN." \
    "After publish succeeds, run: git push --follow-tags"
fi

if [ "$NO_PUSH" = false ]; then
  publish_docker_image_to_ghcr "$NEW_VERSION"
else
  warn "Skipping GHCR Docker publish due to -NoPush."
  GHCR_PACKAGE_STATUS_SUMMARY="skipped (-NoPush)."
fi

if [ "$NO_PUSH" = false ]; then
  push_and_create_github_release "$NEW_VERSION"

  echo "[release] SUCCESS: v$NEW_VERSION committed, tagged, crate published, GHCR image published, and git pushed."
  echo "[release] Package visibility/link status: $GHCR_PACKAGE_STATUS_SUMMARY"
else
  warn "Skipping git push due to -NoPush."
  echo "[release] SUCCESS: v$NEW_VERSION committed, tagged, and crate published. Push + GHCR publish skipped."
  echo "[release] Package visibility/link status: $GHCR_PACKAGE_STATUS_SUMMARY"
fi

popd > /dev/null
exit 0
