# Edge Cases and Defects (Code-Derived)

Fixed defects were removed from this list after code updates on 2026-02-09. This file now tracks only open code-level issues.

## Open Defects

1. `/api/zai/models/fetch` route/handler extractor mismatch:
   - Route has no path param: `src/proxy/routes/admin.rs`
   - Handler expects `Path<String>`: `src/proxy/admin/runtime/service_control.rs`
2. Service-disabled gating bypasses `/health` but not `/healthz`:
   - `src/proxy/middleware/service_status.rs`
   - `src/proxy/routes/mod.rs`
3. Blacklist/whitelist clear handlers likely ineffective (`ip_pattern` vs `id` removal mismatch):
   - `src/proxy/admin/security.rs`
   - `src/modules/persistence/security_db.rs`
4. User token `enabled` flag is not enforced in token validation:
   - `src/modules/persistence/user_token_db.rs`
5. Monitor can record token usage before/without monitor enabled and may double-record when enabled:
   - `src/proxy/monitor.rs`

## Operational Limitations

- Runtime is effectively headless-only in current startup path (`src/lib.rs`)
- No mounted `/internal/*` routes in router definitions (only middleware checks)
- Logging middleware module is placeholder test-only (`src/proxy/middleware/logging.rs`)
- Warmup config exists, but scheduler indicates warmup disabled in headless mode (`src/modules/system/scheduler.rs`)
