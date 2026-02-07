# Gephyr

Gephyr is a headless local API relay/proxy service for Google AI services.

## Scope

This repository is cleaned for headless operation only:
- No frontend UI source
- No desktop runtime path
- No release packaging assets for desktop UI

## Run (Docker)

```bash
docker build -t gephyr:latest -f docker/Dockerfile .
docker run --rm -p 127.0.0.1:8045:8045 \
  -e API_KEY=replace-with-strong-api-key \
  -e WEB_PASSWORD=replace-with-strong-admin-password \
  -e AUTH_MODE=strict \
  -e ALLOW_LAN_ACCESS=false \
  -v ~/.gephyr:/home/gephyr/.gephyr \
  gephyr:latest
```

Script entrypoint:

- Primary: `.\console.ps1` (PowerShell) / `./console.sh` (bash)
- Single entrypoint only: use `console.*` commands

Smoke test scripts:

- Windows: `.\test-clean.ps1 -RunApiTest`
- Linux/macOS: `bash ./test-clean.sh --run-api-test`

## Configuration

- `API_KEY`: required API auth token.
- `WEB_PASSWORD`: optional admin password (used only if admin API is enabled).
- `AUTH_MODE`: recommended `strict`.
- `ALLOW_LAN_ACCESS`: keep `false` unless explicitly needed.
- `ABV_ENABLE_ADMIN_API`: defaults to `false`; set to `true` to expose `/api/*` admin routes.
- `GEPHYR_GOOGLE_OAUTH_CLIENT_ID`: required for `login` (`/api/auth/url` + `/auth/callback`) flow.
- `GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET`: optional (some OAuth clients require it for token exchange/refresh).
- `ABV_PUBLIC_URL`: optional public base URL for callback construction (for hosted deployments).

## Admin API Mode

`-EnableAdminApi` in `console.ps1` enables Gephyr admin routes (`/api/*`) by setting:

- `ABV_ENABLE_ADMIN_API=true`

Use it when you need setup/maintenance actions:

- OAuth login bootstrap (`login`)
- Account management (`accounts`, `logout`, `refresh`)
- Admin config and management endpoints

Without admin API enabled:

- Proxy traffic endpoints still work (`/v1/*`, `/v1/messages`, `/healthz`)
- Admin/script commands that rely on `/api/*` fail or are unavailable

Recommended pattern:

- Enable admin API only during setup/maintenance
- Run normal proxy runtime with admin API disabled

## OAuth Client Type

Gephyr uses OAuth Authorization Code + PKCE with CSRF state checks.

Pick OAuth client type by callback style:
- `Desktop app` client: use for local loopback callbacks (`http://localhost:8045/auth/callback`).
- `Web application` client: use only when Gephyr is hosted behind a public HTTPS domain and `ABV_PUBLIC_URL` is set.

Examples:
- Local Docker on your machine: use `Desktop app` client.
- VPS/shared deployment with `https://proxy.example.com/auth/callback`: use `Web application` client and register that exact redirect URI in Google Cloud.

See `GOOGLE_OAUTH_SETUP.md` for full step-by-step setup.

## Multiple Accounts (OAuth)

Gephyr supports multiple linked Google accounts in one instance.

- OAuth login is single-flow at a time. Add accounts sequentially.
- Logging in again with the same email updates that account (no duplicate account entry).

Typical flow:

```powershell
.\console.ps1 restart -EnableAdminApi
.\console.ps1 login     # complete OAuth for account A
.\console.ps1 login     # complete OAuth for account B
.\console.ps1 login     # complete OAuth for account C
.\console.ps1 accounts  # verify all linked accounts
.\console.ps1 restart   # optional: restart with admin API disabled
```

## Data Directory

Default data path is:
- Linux/macOS: `~/.gephyr`
- Windows: `%USERPROFILE%\\.gephyr`

Override with:
- `ABV_DATA_DIR`
