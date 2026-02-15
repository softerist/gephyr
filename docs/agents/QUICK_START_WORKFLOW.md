# Agent Quick-Start Workflow

Use this when starting a new task quickly and safely.

## Triage Order

1. Read `docs/agents/EDGE_CASES_DEFECTS.md` first to avoid known breakpoints/regressions.
2. Read `docs/agents/RUNTIME_ROUTING.md` to understand request flow and middleware order.
3. Read `docs/agents/API_SURFACE.md` for endpoint coverage and handler ownership.
4. Read `docs/agents/SECURITY_AUTH.md` before touching auth, tokens, IP rules, or admin exposure.
5. Use `docs/AGENT_CODE_CAPABILITIES.md` only when you need full-system depth.

## Read-First by Task Type

- `Task: Add/change endpoint` -> `docs/agents/API_SURFACE.md`, then `docs/agents/RUNTIME_ROUTING.md`
- `Task: Fix routing/middleware behavior` -> `docs/agents/RUNTIME_ROUTING.md`, then `docs/agents/EDGE_CASES_DEFECTS.md`
- `Task: Auth/token/security changes` -> `docs/agents/SECURITY_AUTH.md`, then `docs/agents/EDGE_CASES_DEFECTS.md`
- `Task: Debug production issue` -> `docs/agents/EDGE_CASES_DEFECTS.md`, then `docs/agents/RUNTIME_ROUTING.md`
- `Task: Account/proxy-pool/rate-limit behavior` -> `docs/agents/RUNTIME_ROUTING.md`, then `docs/AGENT_CODE_CAPABILITIES.md`
- `Task: Google legit-connection/trace diffing` -> `docs/agents/GOOGLE_TRACE_VALIDATION.md`, then `docs/agents/API_SURFACE.md`
- `Task: Quick orientation` -> `AGENTS.md`, then `docs/agents/README.md`

## Execution Checklist

1. Confirm whether admin API exposure (`ENABLE_ADMIN_API`) affects reproducibility.
2. Confirm whether headless-only startup assumptions apply (`src/lib.rs` path).
3. Validate middleware interaction order before changing handlers.
4. Re-check known defect list before finalizing any fix (or confirm it is still empty).
5. For session-stickiness/restart issues, verify proxy config uses:
   - `persist_session_bindings: true`
   - `scheduling.mode: balance` or `cache_first` (not `performance_first`)
6. For client-driven stickiness, verify requests provide a stable explicit session id (`x-session-id` or payload `session_id`/`sessionId`).
7. For low-risk account traffic profile, verify `proxy.compliance.enabled=true` and sane budgets (`max_global_requests_per_minute`, `max_account_requests_per_minute`, `max_account_concurrency`, `risk_cooldown_seconds`, `max_retry_attempts`).
8. Prefer `POST /api/proxy/compliance` for compliance-only changes instead of posting full `/api/config`.
9. Prefer `POST /api/proxy/sticky` for stickiness-only changes (`persist_session_bindings`, `scheduling`) instead of posting full `/api/config`.
10. Prefer `POST /api/proxy/request-timeout` for timeout-only changes instead of posting full `/api/config`.
11. Prefer `POST /api/proxy/pool/strategy` for proxy-pool strategy-only changes instead of posting full `/api/config`.
12. Prefer `POST /api/proxy/pool/runtime` for proxy-pool runtime knobs (`enabled`, `auto_failover`, `allow_shared_proxy_fallback`, `require_proxy_for_account_requests`, `health_check_interval`) instead of posting full `/api/config`.
13. For manual bulk quota refresh, require explicit operator intent by sending `x-gephyr-confirm-bulk-refresh: true` with `POST /api/accounts/refresh` (request is rejected with `400` if omitted).

## Smoke Scripts

- `scripts/test-session-binding-persistence.ps1`: validates sticky-session persistence across restart.
- `scripts/test-compliance-counters.ps1`: validates compliance counters and optional stress in-flight behavior.
- `scripts/test-proxy-pool-strategy.ps1`: validates `GET|POST /api/proxy/pool/strategy`.
- `scripts/test-proxy-pool-runtime.ps1`: validates `GET|POST /api/proxy/pool/runtime`.

## Session Persistence Quick Config

Use this `config.json` shape when validating sticky sessions across restart:

```json
{
  "proxy": {
    "persist_session_bindings": true,
    "scheduling": {
      "mode": "balance",
      "max_wait_seconds": 60
    },
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
