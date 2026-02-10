# Execution Tracked Checklist (Security + Reliability)

This is the implementation tracker for the agreed hardening plan.

Use this file as the source for assignment, status updates, and PR scope control.

## Status Legend

- `todo`: not started
- `in_progress`: currently being implemented
- `blocked`: waiting on decision/dependency
- `done`: merged and verified

## Ticket Board

| ID | Priority | Status | Owner | Depends On | Summary |
|---|---|---|---|---|---|
| GEP-SEC-001 | P0 | done | unassigned | - | Security contract + remove `Auto` auth mode |
| GEP-SEC-002A | P0 | done | unassigned | GEP-SEC-001 | IP extraction v1: socket-only default, ignore forwarded headers |
| GEP-SEC-004A | P0 | done | unassigned | - | Encryption key phase 1 (`ABV_ENCRYPTION_KEY`, remove `"default"` fallback) |
| GEP-SEC-005 | P1 | done | unassigned | GEP-SEC-001 | CORS origin allowlist + secure defaults |
| GEP-REL-006 | P1 | done | unassigned | - | Runtime-safe monitor initialization |
| GEP-SEC-007 | P1 | done | unassigned | - | Constant-time credential comparison |
| GEP-PERF-008 | P1 | done | unassigned | - | Remove blocking remote fetch from `USER_AGENT` init |
| GEP-REL-011 | P1 | done | unassigned | - | Graceful shutdown for accept loop and in-flight requests |
| GEP-CLEAN-012 | P2 | done | unassigned | - | Audit `thought_signature_map` and `SignatureCache`; then remove or bound |
| GEP-SEC-002B | P2 | done | unassigned | GEP-SEC-002A | Trusted proxy support for forwarded headers |
| GEP-SEC-004B | P2 | done | unassigned | GEP-SEC-004A | Versioned ciphertext + re-encryption utility |
| GEP-OPS-009 | P3 | done | unassigned | - | Docker build context/cache optimization |
| GEP-ARCH-010 | P4 | done | unassigned | - | HTTP/2 capability evaluation (optional) |

---

## GEP-SEC-001: Security Contract + Remove `Auto`

**Goal**
- Make auth behavior explicit and eliminate dead/ambiguous mode handling.

**Scope**
- `docs/ARCHITECTURE.md`
- `docs/AGENT_CODE_CAPABILITIES.md`
- `docs/agents/SECURITY_AUTH.md`
- `docs/agents/PRE_PR_VERIFICATION_CHECKLIST.md`
- `src/proxy/config.rs`
- `src/proxy/security.rs`
- `src/lib.rs`

**Implementation Checklist**
- [x] Define final auth mode set for headless runtime (recommended: `Strict`, `AllExceptHealth`, `Off` policy explicitly documented).
- [x] Remove `ProxyAuthMode::Auto` from config enum and parsing paths.
- [x] Add config migration/compatibility handling: persisted/env `auto` maps to `strict` with warning.
- [x] Rename/update misleading tests and docs that currently imply dynamic `Auto` behavior.

**Acceptance Criteria**
- [x] No runtime path depends on `Auto`.
- [x] Startup/auth behavior is documented and matches code.
- [x] Existing configs using `auto` continue to boot with explicit warning.

**Validation**
- [x] Auth mode tests updated (currently in `src/proxy/security.rs`).
- [x] Headless startup tests verify env `AUTH_MODE=auto` coercion behavior (`tests::headless_env_auto_auth_mode_is_coerced_to_strict` in `src/lib.rs`).

---

## GEP-SEC-002A: IP Extraction v1 (Safe Default)

**Goal**
- Close spoofing bypass quickly by defaulting to socket IP only.

**Scope**
- `src/proxy/middleware/auth.rs`
- `src/proxy/middleware/ip_filter.rs`
- `src/proxy/middleware/monitor.rs`
- `src/proxy/middleware/mod.rs`
- `src/proxy/server.rs`

**Implementation Checklist**
- [x] Add shared client IP resolver module used by auth/IP-filter/monitor.
- [x] Resolve IP from `ConnectInfo` only in v1.
- [x] Ignore `x-forwarded-for` and `x-real-ip` by default.
- [x] Remove duplicated local `extract_client_ip()` functions from `auth.rs` and `ip_filter.rs`; replace with shared module call.
- [x] Remove auth fallback to `"127.0.0.1"` when extraction fails.

**Acceptance Criteria**
- [x] Same request yields same resolved IP across middlewares.
- [x] Forwarded headers cannot affect auth/IP decisions in default deployment.

**Validation**
- [x] Add spoofing/safe-default resolver tests in `src/proxy/tests/security_ip_tests.rs`.
- [x] Add consistency tests across middleware call paths (`spoofed_forwarded_headers_do_not_change_ip_across_middleware_paths` in `src/proxy/tests/security_ip_tests.rs`).

---

## GEP-SEC-004A: Encryption Key Phase 1

**Goal**
- Eliminate worst-case shared-key vulnerability with minimal migration risk.

**Scope**
- `src/utils/crypto.rs`
- `src/lib.rs` (env parsing path if needed)
- `src/modules/system/config.rs`
- `docs/agents/SECURITY_AUTH.md`

**Implementation Checklist**
- [x] Support `ABV_ENCRYPTION_KEY` as primary key source.
- [x] Remove `"default"` fallback entirely.
- [x] Keep legacy decrypt compatibility for existing stored values.
- [x] On startup/config load, fail fast when encrypted values are present but no valid key source is available.
- [x] Keep plaintext compatibility path for non-encrypted legacy values.

**Acceptance Criteria**
- [x] No code path derives key from constant fallback string.
- [x] Existing encrypted values still decrypt on upgraded runtime when proper key source is present (`encrypted_values_decrypt_with_configured_key_source` in `src/utils/crypto.rs`).

**Validation**
- [x] Unit tests in `src/utils/crypto.rs` for key source precedence and failure behavior.
- [x] Tightened encrypted-payload heuristic threshold to AES-GCM structural minimum (`nonce + tag = 28` bytes) with coverage for both fail-closed and plaintext-fallback paths.

---

## GEP-SEC-005: CORS Hardening

**Goal**
- Reduce browser-origin attack surface on LAN/public exposure.

**Scope**
- `src/proxy/middleware/cors.rs`
- `src/proxy/config.rs`
- `src/modules/system/validation.rs`
- `docs/ARCHITECTURE.md`
- `docs/agents/SECURITY_AUTH.md`

**Implementation Checklist**
- [x] Replace `allow_origin(Any)` default with configurable allowlist.
- [x] Define secure default origin set.
- [x] Keep an explicit opt-in permissive mode for local/dev compatibility.

**Acceptance Criteria**
- [x] Disallowed origins are blocked by default.
- [x] Allowed origins and preflight behavior are deterministic and documented.

**Validation**
- [x] Add CORS allow/deny tests and OPTIONS preflight coverage.
- [x] Added explicit test for `strict` mode with empty allowlist: cross-origin requests remain blocked (no `Access-Control-Allow-Origin` header).
- Current status: implementation complete; ready for PR/merge verification.

---

## GEP-REL-006: Runtime-Safe Monitor Initialization

**Goal**
- Remove fragility from `tokio::spawn` in sync constructor.

**Scope**
- `src/proxy/monitor.rs`
- `src/commands/proxy.rs`

**Implementation Checklist**
- [x] Make `ProxyMonitor::new` side-effect free (no runtime-dependent spawn).
- [x] Move cleanup startup into async service boot path.

**Acceptance Criteria**
- [x] Constructor can run safely outside Tokio runtime.
- [x] Cleanup still executes when service starts.

**Validation**
- [x] Unit test constructor in non-async context.
- [x] Startup integration test verifies cleanup scheduling path (`startup_runs_monitor_maintenance_and_initializes_proxy_db` in `src/commands/proxy.rs`).
- Current status: implementation complete; ready for PR/merge verification.

---

## GEP-SEC-007: Constant-Time Credential Compare

**Goal**
- Harden API/admin key comparisons against timing side channels.

**Scope**
- `src/proxy/middleware/auth.rs`
- `Cargo.toml` (if new dependency used)

**Implementation Checklist**
- [x] Replace string `==` with constant-time comparison helper.
- [x] Preserve existing auth semantics.

**Acceptance Criteria**
- [x] Auth success/failure behavior unchanged from user perspective.

**Validation**
- [x] Regression tests for admin password and API key flows.
- Current status: implementation complete; ready for PR/merge verification.

---

## GEP-PERF-008: Non-Blocking `USER_AGENT` Init

**Goal**
- Remove startup/first-use coupling to remote network fetch.

**Scope**
- `src/constants.rs`
- `src/proxy/upstream/client.rs`
- `Cargo.toml`

**Implementation Checklist**
- [x] Remove blocking remote fetch from `USER_AGENT` lazy static path.
- [x] Use deterministic local version immediately.
- [x] Optional: async background refresh (non-blocking) decision captured: not enabled to keep startup deterministic and network-silent.
- [x] If `reqwest::blocking` is no longer used, remove `blocking` feature from `reqwest` dependency.

**Acceptance Criteria**
- [x] Startup/client initialization no longer waits on external network calls.

**Validation**
- [x] Test proving no blocking path during first client creation.
- Current status: synchronous blocking path removed; optional background refresh intentionally deferred.

---

## GEP-REL-011: Graceful Shutdown

**Goal**
- Stop listener cleanly and drain/abort in-flight tasks on shutdown.

**Scope**
- `src/lib.rs`
- `src/proxy/server.rs`
- `src/commands/proxy.rs`
- `src/proxy/token/manager.rs` (integrate existing graceful task shutdown where relevant)

**Implementation Checklist**
- [x] Add shutdown receiver channel/token for server accept loop.
- [x] Convert accept loop to `tokio::select!` over `listener.accept()` and shutdown signal.
- [x] Track spawned connection tasks and stop accepting new sockets on shutdown.
- [x] Drain for bounded timeout, then abort remaining tasks.
- [x] Invoke shutdown path on Ctrl+C and optional admin stop hook (`ABV_ADMIN_STOP_SHUTDOWN=true` enables `/api/proxy/stop` to trigger graceful server shutdown).
- [x] Make shutdown drain timeout configurable (`ABV_SHUTDOWN_DRAIN_TIMEOUT_SECS`, default 10s).

**Acceptance Criteria**
- [x] Ctrl+C triggers deterministic shutdown sequence.
- [x] No orphaned accept loop after shutdown.

**Validation**
- [x] Integration test with active in-flight request during shutdown (`shutdown_completes_with_in_flight_request_after_drain_timeout` in `src/proxy/server.rs`).
- Current status: graceful shutdown path is implemented and wired to Ctrl+C and optional admin stop hook.

---

## GEP-CLEAN-012: `thought_signature_map` + `SignatureCache` Audit

**Goal**
- Verify real usage boundaries before removing state, and ensure signature-related caches remain bounded.

**Scope**
- `src/proxy/state.rs`
- `src/proxy/server.rs`
- `src/proxy/signature_cache.rs`
- `src/proxy/tests/admin_runtime_endpoints.rs`

**Implementation Checklist**
- [x] Audit production reads/writes of `thought_signature_map`.
- [x] Audit `SignatureCache` usage paths in handlers/mappers to avoid accidental regression.
- [x] If `thought_signature_map` is unused, remove field and wiring; if needed, replace with bounded lifecycle rules.

**Acceptance Criteria**
- [x] Outcome documented: removed dead state or justified bounded retention.
- [x] No regression in thought/signature handling paths.
- Current status: implementation complete; ready for PR/merge verification.

**Validation**
- [x] Compile and targeted signature-path tests pass after audit/refactor.

---

## GEP-SEC-002B: Trusted Proxy Support (v2)

**Goal**
- Re-enable forwarded header support safely for reverse-proxy deployments.

**Scope**
- `src/proxy/config.rs`
- `src/modules/system/validation.rs`
- shared client IP resolver module
- docs under `docs/agents/SECURITY_AUTH.md`

**Implementation Checklist**
- [x] Add `trusted_proxies` config (CIDR/IP list).
- [x] Use forwarded headers only when remote socket IP is trusted.
- [x] Preserve socket-IP fallback for all untrusted sources.

**Acceptance Criteria**
- [x] Forwarded header trust is explicit and auditable.

**Validation**
- [x] Tests for trusted/untrusted proxy source behavior.
- Current status: implementation complete; ready for PR/merge verification.

---

## GEP-SEC-004B: Crypto Format v2 + Re-encryption Utility

**Goal**
- Complete long-term crypto migration safely.

**Scope**
- `src/utils/crypto.rs`
- `src/commands/crypto.rs`
- `src/lib.rs` (CLI switch wiring)
- docs updates in `docs/agents/SECURITY_AUTH.md`

**Implementation Checklist**
- [x] Introduce versioned ciphertext format for new writes (`v2:` prefix).
- [x] Keep backward decrypt support for legacy format (unversioned payload support retained).
- [x] Implement one-time re-encrypt utility/command (`--reencrypt-secrets`).

**Acceptance Criteria**
- [x] Mixed old/new encrypted records are handled correctly.
- [x] Operators have a clear migration path.

**Validation**
- [x] Migration tests covering legacy-to-v2 conversion (`reencrypt_command_rewrites_mixed_legacy_and_v2_records` in `src/commands/crypto.rs`).
- [x] Crypto compatibility tests cover new-write format + legacy decrypt (`encrypt_string_uses_v2_prefix`, `decrypt_string_supports_unversioned_legacy_ciphertext` in `src/utils/crypto.rs`).
- Current status: implementation complete; one-time migration path is available via `--reencrypt-secrets`.

---

## GEP-OPS-009: Docker Build Optimization

**Goal**
- Improve build cache efficiency and context hygiene.

**Scope**
- `docker/Dockerfile`
- `.dockerignore`

**Implementation Checklist**
- [x] Adjust copy order for dependency caching.
- [x] Keep `.dockerignore` exclusions strict.

**Acceptance Criteria**
- [x] Build cache hit-rate improves in CI/local rebuilds.
- Validation metrics (local, same tag rebuild, `docker build -f docker/Dockerfile -t gephyr:cache-eval --progress=plain .`):
- build #1: `39,505 ms`
- build #2: `1,018 ms`
- speedup: `97.42%`
- cache indicators: `CACHED` lines increased from `7` to `12`
- logs captured under `output/docker-cache-metrics/build1.log` and `output/docker-cache-metrics/build2.log`.

---

## GEP-ARCH-010: HTTP/2 Evaluation (Optional)

**Goal**
- Determine if HTTP/2 support is needed for actual workloads.

**Scope**
- `src/proxy/server.rs`
- `docs/ARCHITECTURE.md`

**Implementation Checklist**
- [x] Measure current HTTP/1.1 behavior under expected concurrency (`http1_health_concurrency_smoke_benchmark`: 1500 requests @ concurrency 64, ~894ms elapsed, ~1676.90 req/s).
- [x] Decide go/no-go with benchmark evidence (no-go for HTTP/2 for now; current HTTP/1.1 throughput is sufficient for expected relay workloads).

**Acceptance Criteria**
- [x] Decision documented with metrics.
- Current status: HTTP/2 deferred; revisit only if real workloads show multiplexing pressure beyond current HTTP/1.1 performance envelope.

---

## Global Release Gates

- [x] Security regression tests pass (`src/proxy/tests/security_ip_tests.rs`, `src/proxy/tests/security_integration_tests.rs`).
- [x] Startup path has no blocking remote dependency for `USER_AGENT`.
- [x] Auth mode docs and runtime behavior are fully aligned.
- [x] Shutdown sequence validated under active request load.
- [x] Docs in `docs/agents/` updated for any behavior changes before merge.
