# Gephyr Agent Notes (Code-Derived)

This agent guide is derived from `src/` code analysis, not from markdown docs as source-of-truth.

## Start Here

- Full report: `docs/AGENT_CODE_CAPABILITIES.md`
- Split docs index: `docs/agents/README.md`
- Quick-start workflow: `docs/agents/QUICK_START_WORKFLOW.md`
- API-focused: `docs/agents/API_SURFACE.md`
- Runtime/routing-focused: `docs/agents/RUNTIME_ROUTING.md`
- Security/auth-focused: `docs/agents/SECURITY_AUTH.md`
- Edge-cases/defects: `docs/agents/EDGE_CASES_DEFECTS.md`
- Defect report: `docs/agents/DEFECT_DISCOVERY_REPORT.md`
- Pre-PR checklist: `docs/agents/PRE_PR_VERIFICATION_CHECKLIST.md`

## Quick Routing by Task

- `Endpoint changes` -> `docs/agents/API_SURFACE.md` then `docs/agents/RUNTIME_ROUTING.md`
- `Routing/middleware changes` -> `docs/agents/RUNTIME_ROUTING.md` then `docs/agents/EDGE_CASES_DEFECTS.md`
- `Auth/security/token work` -> `docs/agents/SECURITY_AUTH.md` then `docs/agents/EDGE_CASES_DEFECTS.md`
- `Incident/debug triage` -> `docs/agents/EDGE_CASES_DEFECTS.md` then `docs/agents/RUNTIME_ROUTING.md`

## High-Impact Warnings

- `/api/zai/models/fetch` route/handler extractor mismatch likely breaks endpoint:
- Route has no path param: `src/proxy/routes/admin.rs`
- Handler expects `Path<String>`: `src/proxy/admin/runtime/service_control.rs`
- Service disabled gating bypasses `/health` but not `/healthz`: `src/proxy/middleware/service_status.rs`, `src/proxy/routes/mod.rs`
- Blacklist/whitelist clear handlers likely ineffective (remove by `ip_pattern` while DB removes by `id`): `src/proxy/admin/security.rs`, `src/modules/persistence/security_db.rs`
- User token `enabled` flag is not enforced in token validation: `src/modules/persistence/user_token_db.rs`
- Monitor can record token usage before/without monitor enabled and may double-record when enabled: `src/proxy/monitor.rs`

## Operational Facts

- Runtime is headless-only in current boot path: `src/lib.rs`
- Admin API is disabled unless `ABV_ENABLE_ADMIN_API=true`: `src/proxy/server.rs`
- `ABV_MAX_BODY_SIZE` controls body cap; default is 100MB: `src/proxy/server.rs`
