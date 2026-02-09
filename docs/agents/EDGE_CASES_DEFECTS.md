# Edge Cases and Defects (Code-Derived)

## Confirmed High-Impact Issues

- ZAI fetch route/handler mismatch:
- Route `/api/zai/models/fetch` has no path param (`src/proxy/routes/admin.rs`)
- Handler expects `Path<String>` (`src/proxy/admin/runtime/service_control.rs`)
- Service-status bypass inconsistency:
- bypass includes `/health` but not `/healthz` (`src/proxy/middleware/service_status.rs`)
- both routes exist (`src/proxy/routes/mod.rs`)
- Blacklist/whitelist clear mismatch:
- clear handlers call remove by `ip_pattern` (`src/proxy/admin/security.rs`)
- DB removal APIs delete by `id` (`src/modules/persistence/security_db.rs`)
- User token `enabled` not enforced:
- validation path does not check `enabled` (`src/modules/persistence/user_token_db.rs`)
- Auth `Off` mode token identity path:
- can attach identity via token lookup without full validate path (`src/proxy/middleware/auth.rs`)
- Monitor usage accounting behavior:
- records usage before monitor-enabled check
- can record usage twice when monitor is enabled (`src/proxy/monitor.rs`)
- Security logs total count pagination issue:
- `total = logs.len()` page-count semantics (`src/proxy/admin/security.rs`)
- SQL assembly risk:
- `format!`-based SQL in security DB log retrieval with ip filter (`src/modules/persistence/security_db.rs`)
- CIDR implementation limits:
- IPv4-only split/parse logic in matcher (`src/modules/persistence/security_db.rs`)
- Model-scoped availability blind spot:
- availability check uses rate-limit check with `model=None` in one path (`src/proxy/token/availability.rs`)
- Weighted strategy not weighted:
- weighted selector currently maps to priority logic (`src/proxy/proxy_pool.rs`)
- User token summary placeholder:
- `today_requests` hardcoded `0` (`src/commands/user_token.rs`)

## Operational Limitations

- Runtime is effectively headless-only in current startup path (`src/lib.rs`)
- No mounted `/internal/*` routes in router definitions (only middleware checks)
- Logging middleware module is placeholder test-only (`src/proxy/middleware/logging.rs`)
- Warmup config exists, but scheduler indicates warmup disabled in headless mode (`src/modules/system/scheduler.rs`)
