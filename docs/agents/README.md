# Agent Docs Index

These files split the code-derived capability report into focused sections.

- Master report: `docs/AGENT_CODE_CAPABILITIES.md`
- Quick-start workflow: `docs/agents/QUICK_START_WORKFLOW.md`
- API surface: `docs/agents/API_SURFACE.md`
- Runtime and routing: `docs/agents/RUNTIME_ROUTING.md`
- Security and auth: `docs/agents/SECURITY_AUTH.md`
- Google trace validation runbook: `docs/agents/GOOGLE_TRACE_VALIDATION.md`
- Google strict mimic validation: `docs/agents/GOOGLE_STRICT_MIMIC_VALIDATION.md`
- Google generation mapping guardrail (static): `scripts/validate-google-generation-mapping.ps1`
- Identity hardening backlog: `docs/agents/IDENTITY_HARDENING_BACKLOG.md`
- Edge cases and defects: `docs/agents/EDGE_CASES_DEFECTS.md`
- Architecture overview: `docs/ARCHITECTURE.md`
- Sticky session persistence quick config: `docs/agents/QUICK_START_WORKFLOW.md` ("Session Persistence Quick Config")
- Sticky session persistence overview: `README.md` ("Persistent Session Bindings (Sticky Sessions Across Restart)")

Scope note:

- Source-of-truth is code under `src/`.
- These docs summarize behavior and known risks for agent use.
- Current defect status is tracked in `docs/agents/EDGE_CASES_DEFECTS.md`.

## Fast Path

1. Start with `docs/agents/QUICK_START_WORKFLOW.md`.
2. Jump to the task-specific file from its "Read-First by Task Type" map.

## Google Parity Entry Points

1. Interactive launcher (recommended): `scripts/live-google-parity-verify-interactive.ps1`
2. Non-interactive engine: `scripts/live-google-parity-verify.ps1`
3. Antigravity scoped wrapper: `scripts/live-google-parity-verify-antigravity.ps1`
