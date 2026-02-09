# Agent Quick-Start Workflow

Use this when starting a new task quickly and safely.

## Triage Order

1. Read `docs/agents/EDGE_CASES_DEFECTS.md` first to avoid known breakpoints/regressions (currently none open).
2. Read `docs/agents/RUNTIME_ROUTING.md` to understand request flow and middleware order.
3. Read `docs/agents/API_SURFACE.md` for endpoint coverage and handler ownership.
4. Read `docs/agents/SECURITY_AUTH.md` before touching auth, tokens, IP rules, or admin exposure.
5. Use `docs/AGENT_CODE_CAPABILITIES_REPORT.md` only when you need full-system depth.

## Read-First by Task Type

- `Task: Add/change endpoint` -> `docs/agents/API_SURFACE.md`, then `docs/agents/RUNTIME_ROUTING.md`
- `Task: Fix routing/middleware behavior` -> `docs/agents/RUNTIME_ROUTING.md`, then `docs/agents/EDGE_CASES_DEFECTS.md`
- `Task: Auth/token/security changes` -> `docs/agents/SECURITY_AUTH.md`, then `docs/agents/EDGE_CASES_DEFECTS.md`
- `Task: Debug production issue` -> `docs/agents/EDGE_CASES_DEFECTS.md`, then `docs/agents/RUNTIME_ROUTING.md`
- `Task: Account/proxy-pool/rate-limit behavior` -> `docs/agents/RUNTIME_ROUTING.md`, then `docs/AGENT_CODE_CAPABILITIES_REPORT.md`
- `Task: Quick orientation` -> `AGENTS.md`, then `docs/agents/README.md`

## Execution Checklist

1. Confirm whether admin API exposure (`ABV_ENABLE_ADMIN_API`) affects reproducibility.
2. Confirm whether headless-only startup assumptions apply (`src/lib.rs` path).
3. Validate middleware interaction order before changing handlers.
4. Re-check known defect list before finalizing any fix (or confirm it is still empty).
5. For session-stickiness/restart issues, verify proxy config uses:
   - `persist_session_bindings: true`
   - `scheduling.mode: balance` or `cache_first` (not `performance_first`)
6. For client-driven stickiness, verify requests provide a stable explicit session id (`x-session-id` or payload `session_id`/`sessionId`).

## Session Persistence Quick Config

Use this `config.json` shape when validating sticky sessions across restart:

```json
{
  "proxy": {
    "persist_session_bindings": true,
    "scheduling": {
      "mode": "balance",
      "max_wait_seconds": 60
    }
  }
}
```
