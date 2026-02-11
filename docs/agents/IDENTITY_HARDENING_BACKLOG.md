# Identity Hardening Backlog (PR-Sized)

This backlog focuses on Google identity hardening and one-IP risk controls.

## Current Baseline (Already Implemented)

- Identity keying/upsert supports immutable Google subject (`google_sub`) with email fallback/backfill.
- `id_token` JWT validation exists (JWKS, issuer/audience/exp/email_verified checks, optional `ABV_ALLOWED_GOOGLE_DOMAINS` enforcement).
- OAuth/account paths derive identity from Google claims instead of trusting caller-provided email.
- OAuth calls apply explicit UA + bound device profile headers when available.
- Refresh timing hardening is in place (`ABV_SCHEDULER_REFRESH_JITTER_MIN_SECONDS` / `ABV_SCHEDULER_REFRESH_JITTER_MAX_SECONDS` + per-account deterministic jitter in refresh window checks).
- One-IP strict mode is available with:
  - `proxy.proxy_pool.allow_shared_proxy_fallback`
  - `proxy.proxy_pool.require_proxy_for_account_requests`
- Compliance defaults are hardened for one-IP operation:
  - `max_account_requests_per_minute = 10`
  - `max_account_concurrency = 1`

## Backlog

## PR-1: OAuth/User-Agent Profile Override

- Goal: Allow optional UA pinning for OAuth calls without changing global relay UA behavior.
- Scope:
  - Add env var `ABV_OAUTH_USER_AGENT` (optional).
  - Use override in `src/modules/auth/oauth.rs` for token exchange/refresh/userinfo requests.
  - Keep current default (`crate::constants::USER_AGENT`) when unset.
- Tests:
  - Unit test: empty override -> default UA used.
  - Unit test: override set -> override UA used.
- Risk:
  - Low. Header-only behavior; fallback remains unchanged.

## PR-2: Proxy-Pool Strict Mode Observability

- Goal: Make one-IP strict mode diagnosable in production.
- Scope:
  - Add counters/log fields for:
    - shared fallback used
    - strict fail-closed rejection (`require_proxy_for_account_requests=true`)
  - Expose counters via `GET /api/proxy/metrics`.
- Tests:
  - Unit tests for counter increments in selection/fail paths.
  - Admin metrics endpoint test includes new fields.
- Risk:
  - Low. Observability-only.

## PR-3: TLS Fingerprint Strategy Toggle (Point 4)

- Goal: Provide an explicit choice between current rustls path and OS TLS stack.
- Scope:
  - Add optional runtime toggle for OAuth HTTP client TLS backend (or document build/profile split if runtime toggle is not feasible).
  - Keep existing default behavior unchanged.
  - Add operator docs that this is best-effort and can change by OS/runtime.
- Tests:
  - Build/test matrix proving both modes compile and requests succeed in integration smoke tests.
- Risk:
  - Medium. TLS backend differences can affect cert/proxy behavior.

## PR-4: Device Profile Coverage Audit (Point 5)

- Goal: Ensure device profile consistency on all Google identity-sensitive calls.
- Scope:
  - Audit all outbound Google endpoints (`oauth2.googleapis.com`, `www.googleapis.com`, `content-autofill.googleapis.com`, v1internal paths).
  - Apply a shared helper where appropriate so account-bound calls consistently send bound device headers.
  - Document endpoints intentionally excluded (if any).
- Tests:
  - Unit/integration tests for header propagation on each covered call path.
- Risk:
  - Medium. Header changes can alter upstream behavior.

## PR-5: One-IP Operations Runbook

- Goal: Make one-IP deployment choices explicit and safe by default.
- Scope:
  - Add runbook section with two presets:
    - Availability-first: shared fallback on, strict fail-closed off.
    - Isolation-first: shared fallback off, strict fail-closed on.
  - Include recommended compliance and jitter settings, and expected failure modes.
- Tests:
  - Docs/config examples validated against current config schema.
- Risk:
  - Low. Documentation-only.

