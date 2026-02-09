# Defect Discovery Report (Code-Derived)

Date: 2026-02-09  
Scope: `src/` code only (static analysis, no markdown docs used as evidence)

## Summary

- Total findings: 11
- Critical: 0
- High: 4
- Medium: 6
- Low: 1

## Findings

### 1) Route extractor mismatch for `/api/zai/models/fetch`

- Severity: High
- Evidence:
- Route is defined without path params: `src/proxy/routes/admin.rs:200`
- Handler expects `Path<String>`: `src/proxy/admin/runtime/service_control.rs:152`
- Impact:
- Request extraction can fail, making endpoint unusable.
- Recommended fix:
- Remove `Path(_id): Path<String>` from handler signature, or add a matching route param.

### 2) Health endpoint inconsistency when service is disabled

- Severity: High
- Evidence:
- Service-status bypass includes `/health` only: `src/proxy/middleware/service_status.rs:15`
- Both `/health` and `/healthz` are exposed: `src/proxy/routes/mod.rs:17`, `src/proxy/routes/mod.rs:18`
- Impact:
- `/healthz` can return `503` while `/health` is healthy, causing inconsistent liveness behavior.
- Recommended fix:
- Add `/healthz` to service-status bypass.

### 3) Blacklist/whitelist clear endpoints likely ineffective

- Severity: High
- Evidence:
- Clear handlers pass `entry.ip_pattern` to removal: `src/proxy/admin/security.rs:197`, `src/proxy/admin/security.rs:291`
- DB removal functions delete by `id`: `src/modules/persistence/security_db.rs:358`, `src/modules/persistence/security_db.rs:497`
- Impact:
- Bulk clear operations may silently fail to delete entries.
- Recommended fix:
- Pass `entry.id` to remove functions in clear handlers.

### 4) User token `enabled` flag is not enforced during validation

- Severity: High
- Evidence:
- Validation logic starts at `validate_token` and never checks `token.enabled`: `src/modules/persistence/user_token_db.rs:465`
- Impact:
- Disabled tokens may still authenticate successfully.
- Recommended fix:
- Add an early check:
- if `!token.enabled`, return invalid token result.

### 5) Auth `Off` mode uses token lookup without full validation

- Severity: Medium
- Evidence:
- In `ProxyAuthMode::Off`, middleware uses `get_token_by_value` and directly attaches identity: `src/proxy/middleware/auth.rs:48`, `src/proxy/middleware/auth.rs:63`
- Full validation (`validate_token`) is in a different branch: `src/proxy/middleware/auth.rs:149`
- Impact:
- In `Off` mode, expiry/IP-limit/curfew checks are bypassed for identity attachment.
- Recommended fix:
- Reuse `validate_token` before attaching `UserTokenIdentity`, even in `Off` mode.

### 6) Token usage can be recorded even when monitor is disabled

- Severity: Medium
- Evidence:
- Usage recording runs before enabled check: `src/proxy/monitor.rs:83`
- Enabled gate is later: `src/proxy/monitor.rs:90`
- Impact:
- Token stats continue to grow despite monitor being disabled.
- Recommended fix:
- Move early token stats write behind feature flag or split monitoring vs accounting toggles explicitly.

### 7) Potential double token usage accounting when monitor is enabled

- Severity: Medium
- Evidence:
- First `record_usage` call before enabled check: `src/proxy/monitor.rs:83`
- Second `record_usage` call inside async persistence path: `src/proxy/monitor.rs:145`
- Impact:
- Inflated usage stats for monitored requests.
- Recommended fix:
- Keep a single accounting write path.

### 8) IP access logs API returns page-size total, not full total

- Severity: Medium
- Evidence:
- `total` is assigned from current page length: `src/proxy/admin/security.rs:49`
- Impact:
- Pagination UI/API consumers may receive incorrect totals.
- Recommended fix:
- Add a dedicated `COUNT(*)` query and return that as total.

### 9) SQL query assembly uses string interpolation for `ip_filter`

- Severity: Medium
- Evidence:
- SQL statements built with `format!` and embedded `ip_filter`: `src/modules/persistence/security_db.rs:174`, `src/modules/persistence/security_db.rs:183`, `src/modules/persistence/security_db.rs:193`, `src/modules/persistence/security_db.rs:202`
- Impact:
- Unsafe SQL construction pattern; potential injection or malformed query risks.
- Recommended fix:
- Use parameterized queries with placeholders and bound values.

### 10) `WeightedRoundRobin` strategy currently behaves as priority

- Severity: Low
- Evidence:
- Weighted selector calls priority selector directly: `src/proxy/proxy_pool.rs:226`
- Impact:
- Config option is misleading and does not implement weighted behavior.
- Recommended fix:
- Implement true weighted selection, or rename/deprecate strategy.

### 11) User token summary has placeholder `today_requests`

- Severity: Medium
- Evidence:
- Summary response hardcodes `today_requests: 0`: `src/commands/user_token.rs:73`
- Impact:
- Misleading operational metrics for admin users.
- Recommended fix:
- Compute today’s request count from `token_usage_logs` with a day-bucket query.

## Notes

- Findings above are static code findings; runtime behavior may vary by configuration and deployment.
- Highest-priority fixes are findings 1–4 due to direct API correctness and security/authorization impact.
