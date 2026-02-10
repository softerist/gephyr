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
- API/admin secret comparison uses a constant-time helper to reduce timing side-channel leakage.

## IP Filtering

From `src/proxy/middleware/ip_filter.rs` and `src/modules/persistence/security_db.rs`:

- whitelist-only mode
- whitelist-priority mode
- blacklist mode with exact IP and CIDR matching
- blocked request response payload includes reason
- blocked requests are logged into security DB

Client IP extraction precedence:

- default safe mode: connection `ConnectInfo` only (`proxy.trusted_proxies` empty)
- forwarded headers are considered only when socket peer IP matches configured `proxy.trusted_proxies` (IP/CIDR)
- header precedence for trusted peers: `x-forwarded-for` (first valid IP) then `x-real-ip`, then socket IP fallback

## CORS and Exposure

From `src/proxy/middleware/cors.rs`:

- CORS policy is config-driven via `proxy.cors`
- Default mode is `strict` with localhost allowlist:
- `http://localhost:3000`
- `http://127.0.0.1:3000`
- `http://localhost:5173`
- `http://127.0.0.1:5173`
- In `strict` mode, empty `allowed_origins` intentionally blocks all cross-origin browser access (no `Access-Control-Allow-Origin` header).
- `permissive` mode is explicit opt-in and allows any origin/headers
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
- New encrypted writes use versioned ciphertext format (`v2:<base64>`).
- Legacy unversioned ciphertext remains decryptable for backward compatibility.

## Secret Re-encryption Migration

From `src/commands/crypto.rs` and `src/lib.rs`:

- One-time migration command: run the binary with `--reencrypt-secrets`.
- Flow:
- load + save app config to rewrite encrypted fields to v2 format
- iterate account JSON files and load + save each account to rewrite encrypted fields
- startup exits after migration completes (service does not stay running in this mode)
- Migration requires a valid key source (`ABV_ENCRYPTION_KEY` recommended).
