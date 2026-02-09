# Edge Cases and Defects (Code-Derived)

Fixed defects were removed from this list after code updates on 2026-02-09. This file now tracks only open code-level issues.

## Open Defects

- CIDR implementation limits:
- IPv4-only split/parse logic in matcher (`src/modules/persistence/security_db.rs`)
- Model-scoped availability blind spot:
- availability check uses rate-limit check with `model=None` in one path (`src/proxy/token/availability.rs`)

## Operational Limitations

- Runtime is effectively headless-only in current startup path (`src/lib.rs`)
- No mounted `/internal/*` routes in router definitions (only middleware checks)
- Logging middleware module is placeholder test-only (`src/proxy/middleware/logging.rs`)
- Warmup config exists, but scheduler indicates warmup disabled in headless mode (`src/modules/system/scheduler.rs`)
