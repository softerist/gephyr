# Edge Cases and Defects (Code-Derived)

Fixed defects were removed from this list after code updates on 2026-02-09. This file now tracks only open code-level issues.

## Open Defects

None currently confirmed in this pass.

## Operational Limitations

- Runtime is effectively headless-only in current startup path (`src/lib.rs`)
- No mounted `/internal/*` routes in router definitions (only middleware checks)
- Warmup config exists, but scheduler indicates warmup disabled in headless mode (`src/modules/system/scheduler.rs`)
