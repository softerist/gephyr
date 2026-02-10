# Security and Auth (Code-Derived)

## Auth Modes

Defined in `src/proxy/config.rs` and resolved in `src/proxy/security.rs`:

- `Off`
- `Strict`
- `AllExceptHealth`

Runtime hardening (`src/lib.rs`) forces `Strict` if configured `Off` in headless startup.
Legacy compatibility: `AUTH_MODE=auto` (or persisted `auth_mode: "auto"`) is coerced to `strict` with warning.

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

- v1 safe default: connection `ConnectInfo` only
- forwarded headers (`x-forwarded-for`, `x-real-ip`) are ignored in middleware IP resolution by default

## CORS and Exposure

From `src/proxy/middleware/cors.rs`:

- `allow_origin(Any)`
- `allow_headers(Any)`
- `allow_credentials(false)`

From `src/proxy/server.rs`:

- Admin API (`/api`) and `/auth/callback` are mounted only when `ABV_ENABLE_ADMIN_API=true`.

## User Token Validation and Usage

From `src/modules/persistence/user_token_db.rs` and auth middleware:

- Tokens enforce `enabled`, expiry, IP cap, and curfew constraints.
- Usage and IP binding logs are persisted.
- Auth middleware can attach user token identity and allow request via token path.
- In auth `Off` mode, identity attachment still uses token validation checks before attaching identity.

## Encryption Key Source

From `src/utils/crypto.rs`:

- Primary key source: `ABV_ENCRYPTION_KEY`
- Fallback source: machine UID (when available)
- No constant/default shared fallback key
- Encrypted payloads fail closed when no key source is available (plaintext compatibility remains for non-encrypted values)
