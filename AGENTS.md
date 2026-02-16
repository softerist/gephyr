# Gephyr Agent Notes (Code-Derived)

This agent guide is derived from `src/` code analysis, not from markdown docs as source-of-truth.

## Start Here

- Full report: `docs/AGENT_CODE_CAPABILITIES.md`
- Split docs index: `docs/agents/README.md`
- Quick-start workflow: `docs/agents/QUICK_START_WORKFLOW.md`
- API-focused: `docs/agents/API_SURFACE.md`
- Runtime/routing-focused: `docs/agents/RUNTIME_ROUTING.md`
- Security/auth-focused: `docs/agents/SECURITY_AUTH.md`
- Identity hardening backlog: `docs/agents/IDENTITY_HARDENING_BACKLOG.md`
- Edge-cases/defects: `docs/agents/EDGE_CASES_DEFECTS.md`
- Defect report: `docs/agents/DEFECT_DISCOVERY_REPORT.md`
- Pre-PR checklist: `docs/agents/PRE_PR_VERIFICATION_CHECKLIST.md`

## Quick Routing by Task

- `Endpoint changes` -> `docs/agents/API_SURFACE.md` then `docs/agents/RUNTIME_ROUTING.md`
- `Routing/middleware changes` -> `docs/agents/RUNTIME_ROUTING.md` then `docs/agents/EDGE_CASES_DEFECTS.md`
- `Auth/security/token work` -> `docs/agents/SECURITY_AUTH.md` then `docs/agents/EDGE_CASES_DEFECTS.md`
- `Incident/debug triage` -> `docs/agents/EDGE_CASES_DEFECTS.md` then `docs/agents/RUNTIME_ROUTING.md`

## High-Impact Warnings

- None currently confirmed in this pass.

## Operational Facts

- Runtime is headless-only in current boot path: `src/lib.rs`
- Admin API is disabled unless `ENABLE_ADMIN_API=true`: `src/proxy/server.rs`
- `MAX_BODY_SIZE` controls body cap; default is 100MB: `src/proxy/server.rs`
