# Identity Hardening Backlog (PR-Sized)

This backlog tracks Google identity hardening and one-IP risk controls.

## Completed In Current Wave

### PR-02: `google_sub` Model Migration + Coverage
- Status: Implemented
- Delivered:
  - `google_sub: Option<String>` in account model + summary with backward-compatible serde defaults.
  - Added model serde coverage tests:
    - `account_deserialize_without_google_sub_is_ok`
    - `account_serialize_with_google_sub`
- Files:
  - `src/models/account.rs`

### PR-04: Remove Caller-Provided Email Trust (Legacy Import Hardening)
- Status: Implemented
- Delivered:
  - Legacy migration/import paths now fail closed if Google token refresh or identity verification fails.
  - No fallback persistence from placeholder/external email when identity cannot be verified.
- Files:
  - `src/modules/system/migration.rs`

### PR-05: OAuth Verification Wiring Completion
- Status: Implemented
- Delivered:
  - Centralized identity verification via `oauth::verify_identity(...)`.
  - `id_token` remains preferred; strict userinfo fallback requires `email_verified=true`.
  - Admin OAuth background flow now uses verified identity path for progress/account status.
  - OIDC-compatible userinfo endpoint used for fallback (`openidconnect.googleapis.com/v1/userinfo`).
- Files:
  - `src/modules/auth/oauth.rs`
  - `src/modules/auth/account_service.rs`
  - `src/proxy/token/account_ops.rs`
  - `src/proxy/token/manager_ops.rs`
  - `src/proxy/admin/accounts/oauth.rs`

### PR-06: OAuth UA Consistency Test Gap
- Status: Implemented
- Delivered:
  - Added integration-style tests proving OAuth refresh + userinfo requests send configured UA.
  - Added shared HTTP client UA propagation test.
- Files:
  - `src/modules/auth/oauth.rs`
  - `src/utils/http.rs`

### PR-07: Refresh Jitter + Staggering Completion
- Status: Implemented
- Delivered:
  - Unified refresh decision helper (`should_refresh_token`) with per-account window jitter reused by runtime managers.
  - Added deterministic per-account stagger for batch refresh tasks:
    - `ABV_ACCOUNT_REFRESH_STAGGER_MIN_MS`
    - `ABV_ACCOUNT_REFRESH_STAGGER_MAX_MS`
  - Added tests for stagger determinism and bounds handling.
- Files:
  - `src/modules/auth/oauth.rs`
  - `src/modules/auth/account.rs`
  - `src/proxy/token/manager_runtime_preferred.rs`
  - `src/proxy/token/manager_runtime_rotation.rs`

### PR-10: TLS Strategy Toggle Completion
- Status: Implemented
- Delivered:
  - Runtime TLS backend override: `ABV_TLS_BACKEND` (`native-tls` or `rustls`) when compiled support exists.
  - TLS backend selection applied consistently across shared/proxy/upstream/zai/update-checker clients.
  - Runtime metric now reports effective backend through existing metrics path.
- Files:
  - `src/utils/http.rs`
  - `src/proxy/proxy_pool.rs`
  - `src/proxy/upstream/client.rs`
  - `src/proxy/providers/zai_anthropic.rs`
  - `src/modules/system/update_checker.rs`

### PR-11: Correlation-Risk Metrics Expansion
- Status: Implemented
- Delivered:
  - Added rolling one-minute counters for compliance risk signals and account-switch velocity.
  - Added per-account 403/429 rolling maps in compliance snapshot and `/api/proxy/metrics`.
  - Added refresh-attempt observability (global + per-account) for OAuth refresh paths.
  - Added scheduler refresh-burst observability:
    - runs/minute
    - failures/minute
    - accounts attempted/minute
- Files:
  - `src/proxy/token/manager.rs`
  - `src/proxy/token/manager_compliance.rs`
  - `src/proxy/token/manager_runtime_rotation.rs`
  - `src/modules/auth/oauth.rs`
  - `src/modules/system/scheduler.rs`
  - `src/proxy/admin/runtime/service_control.rs`
  - `src/proxy/tests/admin_runtime_endpoints.rs`
  - `src/proxy/token/manager_tests.rs`

### PR-12: OAuth Fallback Strictness for Optional Legacy Flows
- Status: Implemented
- Delivered:
  - Centralized refresh+identity verification helper:
    - `oauth::refresh_and_verify_identity(...)`
  - Import/add flows now consistently call centralized refresh+verify path:
    - migration imports (`import_from_v1`, `import_from_custom_db_path`)
    - token account add/verify helpers
    - account service refresh-token add flow
  - Tightened fallback identity acceptance:
    - userinfo fallback now requires `email_verified=true`
    - userinfo fallback now requires non-empty Google subject identifier (`sub`)
  - Added regression tests for fail-closed behavior:
    - unverified email rejected in fallback
    - missing `sub` rejected in fallback
    - refresh+verify helper enforces missing-`sub` rejection
- Files:
  - `src/modules/auth/oauth.rs`
  - `src/modules/system/migration.rs`
  - `src/proxy/token/account_ops.rs`
  - `src/modules/auth/account_service.rs`

## Documentation Updated

- `.env` templates:
  - `.env.example`
  - `.env.local`
- Operator docs:
  - `README.md`
  - `OAUTH_SETUP.md`

## Remaining Backlog (Next PR-Sized Tasks)

### PR-13: TLS Canary + Startup Diagnostics
- Goal: make TLS mode changes safer in production.
- Scope:
  - Add startup diagnostics log: requested backend, compiled support, effective backend.
  - Add optional canary probe endpoint check on boot with explicit error surfaces.
- Files:
  - `src/utils/http.rs`
  - `src/proxy/admin/runtime/service_control.rs`
- Tests:
  - Startup selection tests under different env values.

## Verification

- Core validation command:
  - `cargo test --workspace`
