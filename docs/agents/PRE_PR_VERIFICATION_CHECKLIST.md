# Pre-PR Verification Checklist (Agent)

Use this before opening a PR. It is aligned to:

- `docs/agents/QUICK_START_WORKFLOW.md`
- `docs/agents/API_SURFACE.md`
- `docs/agents/RUNTIME_ROUTING.md`
- `docs/agents/SECURITY_AUTH.md`
- `docs/agents/DEFECT_DISCOVERY_REPORT.md`

## 1) Scope and Risk

- Confirm the task scope matches what was requested.
- Confirm whether changes touch known defect areas from `docs/agents/DEFECT_DISCOVERY_REPORT.md`.
- Confirm whether behavior can differ based on env flags:
- `ABV_ENABLE_ADMIN_API`
- `ABV_AUTH_MODE`
- `ABV_MAX_BODY_SIZE`
- `ABV_ALLOW_LAN_ACCESS`

## 2) API and Contract Checks

- If route changes were made, verify route and extractor signatures match.
- Verify no accidental endpoint removal or method mismatch.
- Verify response status codes remain intentional (especially auth, health, and admin routes).
- Verify pagination metadata correctness (`total`, `page`, `page_size`) if list APIs changed.

## 3) Runtime and Middleware Checks

- Validate middleware order impact (IP filter -> auth -> monitor).
- Validate service-status behavior for `/health` and `/healthz`.
- Validate behavior when service is disabled.
- Validate stream vs non-stream behavior for modified handlers.

## 4) Security and Auth Checks

- Verify auth mode behavior (`Off`, `Strict`, `AllExceptHealth`, `Auto`).
- Verify admin auth remains strict where required.
- Verify user token validation paths enforce intended constraints:
- enabled flag
- expiry
- IP cap
- curfew
- If SQL changed, ensure parameterized queries are used (no string interpolation of untrusted input).

## 5) Token/Rate-Limit/Proxy-Pool Checks

- Verify token selection still handles preferred/sticky/rotation paths.
- Verify rate-limit behavior for account-level and model-level locks.
- Verify proxy-pool strategy behavior remains consistent with config semantics.
- If weighted strategy changed, confirm it is truly weighted and tested.

## 6) Observability and Data Integrity

- Verify monitor toggles behave as intended (no unintended accounting when disabled).
- Verify token/account usage is recorded exactly once per request path.
- Verify DB writes are still valid for:
- `proxy_logs.db`
- `security.db`
- `user_tokens.db`
- `token_stats.db`

## 7) Regression Targets (Known Defects)

Before PR, explicitly re-test these areas if related code changed:

- model-scoped availability checks in fallback path (`src/proxy/token/availability.rs`).
- CIDR behavior and validation boundaries in security DB/middleware (`src/modules/persistence/security_db.rs`).

## 8) Test and Validation

- Run the smallest focused test set that covers the changed area.
- If no test exists, add one for the bug/behavior touched.
- For handler changes, include at least one failure-path assertion.
- For auth/security changes, include both allow and deny path checks.

## 9) PR Readiness

- Update relevant docs in `docs/agents/` if behavior changed.
- Include in PR description:
- what changed
- why it changed
- risk level
- how it was validated
- any known limitations or follow-ups
