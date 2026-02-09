# Security and Auth (Code-Derived)

## Auth Modes

Defined in `src/proxy/config.rs` and resolved in `src/proxy/security.rs`:

- `Off`
- `Strict`
- `AllExceptHealth`
- `Auto` (resolves to `Strict`)

Runtime hardening (`src/lib.rs`) forces `Strict` if configured `Off`/`Auto` in headless startup.

## Auth Middleware Behavior

From `src/proxy/middleware/auth.rs`:

- `OPTIONS` bypasses auth.
- Health endpoints can bypass depending on mode.
- `/internal/*` bypass logic exists (non-force-strict path).
- API key sources:
- `Authorization: Bearer ...`
- `x-api-key`
- `x-goog-api-key`
- Admin auth (`force_strict`) checks admin password first (if set), else API key.

## IP Filtering

From `src/proxy/middleware/ip_filter.rs` and `src/modules/persistence/security_db.rs`:

- whitelist-only mode
- whitelist-priority mode
- blacklist mode with exact IP and CIDR matching
- blocked request response payload includes reason
- blocked requests are logged into security DB

Client IP extraction precedence:

- `x-forwarded-for`
- `x-real-ip`
- connection `ConnectInfo`

## CORS and Exposure

From `src/proxy/middleware/cors.rs`:

- `allow_origin(Any)`
- `allow_headers(Any)`
- `allow_credentials(false)`

From `src/proxy/server.rs`:

- Admin API (`/api`) and `/auth/callback` are mounted only when `ABV_ENABLE_ADMIN_API=true`.

## User Token Validation and Usage

From `src/modules/persistence/user_token_db.rs` and auth middleware:

- Tokens support expiry, IP cap, curfew.
- Usage and IP binding logs are persisted.
- Auth middleware can attach user token identity and allow request via token path.

Known risk:

- `validate_token` does not enforce `enabled` flag.
