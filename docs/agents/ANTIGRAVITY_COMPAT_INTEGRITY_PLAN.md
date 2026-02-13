# Antigravity Compatibility: Integrity Plan (Non-Evasive)

This plan is about correctness, consistency, and operational safety when interoperating with Antigravity-style flows.

It explicitly does **not** aim to make Gephyr "indistinguishable" from Antigravity, bypass platform controls, or evade detection.

## Goals

- Keep outbound Google-facing requests internally consistent (UA, headers, token usage).
- Avoid sending fabricated identity/telemetry headers as if they were real IDE identifiers.
- Remove accidental "staging scanning" behavior (sandbox/daily) from default operation.
- Provide a clean login and logout lifecycle that behaves like a normal OAuth client:
  - browser-based login
  - backend token exchange/refresh
  - explicit token revocation on logout
- Make all of the above observable and testable.

## Non-Goals

- TLS/JA3/JA4 impersonation or "BoringSSL fingerprint mimicry".
- Generating IDs to match VS Code/Antigravity formats for the purpose of stealth.
- Using non-public/internal endpoints without explicit authorization.

## Current Findings (Local Investigation)

- Antigravity `storage.json` in the wild can omit some telemetry keys (observed: missing `macMachineId`).
- Gephyr token persistence relies on a stable encryption key. If `ENCRYPTION_KEY` is missing, existing `v2:` tokens may fail to decrypt and accounts appear unavailable.

## Work Items

### 1) Endpoint Hygiene (High Priority)

- Default to production-only upstream endpoints.
- Make any sandbox/daily endpoints opt-in, explicitly labeled dev/test.
- Remove hardcoded sandbox URLs from:
  - `src/modules/system/quota.rs`
  - `src/proxy/project_resolver.rs`
- Keep fallbacks only if you can justify them for reliability, and ensure prod-first order.

Acceptance:
- Grep-based regression: no requests are sent to `*.sandbox.googleapis.com` or `daily-*` domains unless an explicit config/env enables them.

### 2) Device Profile Header Integrity (High Priority)

- Continue treating device profile fields as optional (real storage can omit keys).
- Only attach `x-machine-id`, `x-mac-machine-id`, `x-dev-device-id`, `x-sqm-id` when present.
- Change defaults so "capture from local IDE storage" is the primary path.
- Guardrails:
  - `generate` should be explicit opt-in (admin endpoint may allow it, but it should not happen silently).
  - add an admin warning/metric when a bound device profile is synthetic (e.g. labeled `generate`).

Acceptance:
- `POST /api/accounts/:id/bind-device` with `mode=capture` succeeds when `storage.json` has `machineId` but lacks `macMachineId`.
- No `x-*` headers are sent for absent fields.

### 3) User-Agent Single Source Of Truth (Medium Priority)

- Keep one effective UA for all Google calls (OAuth + upstream).
- If UA overrides exist, make them come from one place (config/runtime knob), and write tests that validate consistency.

Acceptance:
- Integration-style tests prove OAuth refresh and upstream calls carry the same UA when configured.
- Startup warns if conflicting UA knobs are configured.

### 4) Login Lifecycle (Browser + Backend Exchange) (Medium Priority)

- Keep the browser-based OAuth flow and backend token exchange.
- Ensure token exchange uses the same client routing policy as other Google calls (proxy pool / upstream proxy).
- Validate prerequisites at startup:
  - if encryption key prerequisites are not satisfied, fail early with actionable error (or at minimum warn loudly).

Acceptance:
- When existing encrypted tokens are present, startup does not silently drop accounts due to missing key.

### 5) Logout Lifecycle (Revocation + Local Cleanup) (High Priority)

Add a "logout" that behaves like a standard OAuth client:

- Revoke refresh token via Google's revoke endpoint.
- Clear local stored tokens for that account (and optionally remove the account).
- Ensure subsequent requests do not attempt refresh with revoked tokens.

Acceptance:
- New admin endpoint (or CLI command) revokes and then the account is unusable until re-linked.

### 6) Burst/Correlation Controls (Medium Priority)

- Keep or strengthen rate limiting and concurrency caps (this is stability and service-safety, not stealth).
- Prefer "refresh near expiry on demand" over periodic bulk refresh.
- If bulk refresh exists, require explicit operator confirmation (already partially enforced on `/api/accounts/refresh`).

Acceptance:
- Metrics show bounded refresh attempts per minute and bounded per-account concurrency.
