# Google OAuth Setup (Desktop vs Web)

This guide explains how to create Google OAuth credentials for Gephyr and when to use each client type.
These credentials are needed as environment variables in the .env.local file.

## Quick Decision

- Use `Desktop app` client if your callback is local loopback:
  - `http://localhost:8045/auth/callback`
  - `http://127.0.0.1:<port>/auth/callback`
- Use `Web application` client if your callback is public HTTPS:
  - `https://proxy.example.com/auth/callback`
  - Typically used with `ABV_PUBLIC_URL`.

## Why This Matters

Gephyr runs as a local/headless proxy and uses OAuth Authorization Code + PKCE.
- Local loopback flow maps to installed/native app behavior.
- Public domain callback flow maps to hosted web app behavior.

## Step-by-Step: Create Google Cloud OAuth Credentials

1. Create/select a Google Cloud project:
   - <https://console.cloud.google.com/>

2. Configure OAuth consent screen:
   - Google Auth Platform -> Branding.
   - Set app name, support email, and contact email.
   - Audience: choose `External` for personal Google accounts.
   - Add your Google account under Test users (if app is in Testing mode).

3. Configure scopes:
   - Use the exact scopes currently requested by Gephyr:
   - `openid`
   - `https://www.googleapis.com/auth/cloud-platform`
   - `https://www.googleapis.com/auth/userinfo.email`
   - `https://www.googleapis.com/auth/userinfo.profile`
   - `https://www.googleapis.com/auth/cclog`
   - `https://www.googleapis.com/auth/experimentsandconfigs`

4. Create OAuth client:
   - Google Auth Platform -> Clients -> Create Client.
   - Choose one:
   - `Desktop app` for localhost/loopback use.
   - `Web application` for public HTTPS callback.

5. If using `Web application`, add exact redirect URI(s):
   - Example: `https://proxy.example.com/auth/callback`
   - Must match exactly (scheme, domain, path, and port if present).

6. Put credentials in `.env.local`:

```env
GEPHYR_GOOGLE_OAUTH_CLIENT_ID=your-client-id.apps.googleusercontent.com
GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret
```

Notes:
- `GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET` is optional in Gephyr code path, but some client types/policies may require it for exchange/refresh.
- OAuth scopes are fixed in code (no runtime scope override env var).
- If you use a public hosted callback flow, set:
  - `ABV_PUBLIC_URL=https://proxy.example.com`

7. Restart Gephyr so env vars are loaded, then run login flow again.

## Deployment Examples

### Example A: Local machine (Docker or bare metal)
- Callback: `http://localhost:8045/auth/callback`
- OAuth client type: `Desktop app`
- `ABV_PUBLIC_URL`: not needed

### Example B: Hosted server (VPS/K8s) with domain
- Callback: `https://proxy.example.com/auth/callback`
- OAuth client type: `Web application`
- Set `ABV_PUBLIC_URL=https://proxy.example.com`

## Identity Hardening (Recommended)

Use these settings to reduce account-correlation risk and tighten identity checks.

### 1) Restrict accepted Google domains (optional but recommended for Workspace)

If you only expect accounts from specific Workspace domains:

```env
ABV_ALLOWED_GOOGLE_DOMAINS=example.com,subsidiary.example.com
```

Behavior:
- Empty/unset: all domains accepted.
- Set: login/import is rejected when Google identity does not match the allowlist.

### 2) Add scheduler jitter to avoid synchronized refresh waves

```env
ABV_SCHEDULER_REFRESH_JITTER_MIN_SECONDS=30
ABV_SCHEDULER_REFRESH_JITTER_MAX_SECONDS=120
```

Behavior:
- Scheduler still runs every 10 minutes, but each run waits a random delay in this range before starting refresh.
- Keep `MIN <= MAX`.

### 3) One-IP hardening: disable shared proxy fallback (optional)

This is a runtime config setting (not an env var):

```json
{
  "proxy": {
    "proxy_pool": {
      "allow_shared_proxy_fallback": false
    }
  }
}
```

Equivalent admin API update:

```bash
curl -X POST http://127.0.0.1:8045/api/proxy/pool/runtime \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "allow_shared_proxy_fallback": false
  }'
```

### 4) One-IP hardening: fail-closed account proxy routing (optional)

Use this only if you prefer strict isolation over availability.

```json
{
  "proxy": {
    "proxy_pool": {
      "allow_shared_proxy_fallback": false,
      "require_proxy_for_account_requests": true
    }
  }
}
```

Equivalent admin API update:

```bash
curl -X POST http://127.0.0.1:8045/api/proxy/pool/runtime \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "allow_shared_proxy_fallback": false,
    "require_proxy_for_account_requests": true
  }'
```

One-IP guidance:
- If availability is more important, keep shared fallback enabled.
- If strict anti-correlation behavior is more important, disable fallback and enable fail-closed routing.

### 5) One-IP hardening: stricter per-account traffic budgets

Default compliance guidance is now:
- `max_account_requests_per_minute = 10`
- `max_account_concurrency = 1`

Example:

```json
{
  "proxy": {
    "compliance": {
      "enabled": true,
      "max_global_requests_per_minute": 120,
      "max_account_requests_per_minute": 10,
      "max_account_concurrency": 1,
      "risk_cooldown_seconds": 300,
      "max_retry_attempts": 2
    }
  }
}
```

## Common Errors

- `redirect_uri_mismatch`:
  - Your callback URI does not exactly match a registered Web client redirect URI.
- OAuth success page shown but login not completed:
  - Verify callback reachability and state handling.
  - For hosted setups, ensure `ABV_PUBLIC_URL` is correct and HTTPS is valid.
- Health/API returns `401` after key rotation:
  - Your local API key and running container key differ. Restart container with the updated key.
