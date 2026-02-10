# API Surface (Code-Derived)

## Public Proxy Routes

Defined in `src/proxy/routes/mod.rs`.

- `GET /health`
- `GET /healthz`
- `GET /v1/models`
- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/responses`
- `POST /v1/messages`
- `POST /v1/messages/count_tokens`
- `GET /v1/models/claude`
- `GET /v1beta/models`
- `GET|POST /v1beta/models/:model`
- `POST /v1beta/models/:model/countTokens`
- `POST /v1/models/detect`

## Admin Routes

Defined in `src/proxy/routes/admin.rs`; mounted under `/api` only if `ABV_ENABLE_ADMIN_API=true` (`src/proxy/server.rs`).

Primary groups:

- Accounts:
- list/add/current/switch/refresh/delete
- bind device/profile, version list/restore/delete
- import v1/db/custom-db, sync-db
- bulk delete, export, reorder
- fetch quota, toggle proxy status
- OAuth:
- prepare/start/complete/cancel/submit-code
- web auth URL + callback flow
- status: `GET /api/auth/status` returns phase + detail
- phases include `idle`, `prepared`, `callback_received`, `exchanging_token`, `fetching_user_info`, `saving_account`, `linked`, `rejected`, `failed`, `cancelled`
- `GET /api/auth/status` also includes `recent_events` (ring buffer of the latest phase transitions) to make short-lived phases observable in polling clients
- OAuth consent denial from callback (`error=access_denied`) is mapped to `phase=rejected` with `detail=oauth_access_denied`
- Proxy control:
- status/start/stop
- model mapping update
- api-key generation
- config save (`POST /api/config`) now returns `{ ok, saved, message, warnings[] }` and protects against empty `proxy.api_key` lockout by preserving the existing key
- version/routes capability snapshot (`GET /api/version/routes`)
- `GET /api/version/routes` is now generated from shared admin-route capability metadata (reduces manual drift risk)
- sticky runtime snapshot/config update (`GET|POST /api/proxy/sticky`) for scheduling + `persist_session_bindings` without full config round-trip
- request-timeout runtime snapshot/config update (`GET|POST /api/proxy/request-timeout`) to tune timeout without full config round-trip
- metrics snapshot (`GET /api/proxy/metrics`) with runtime/monitor/sticky/compliance aggregates
- metrics snapshot also includes `runtime_apply_policies_supported` for policy discovery
- scoped proxy update responses include `runtime_apply` (`policy`, `applied`, `requires_restart`) for hot-reload transparency
- session bindings debug snapshot (bindings + recent sticky decisions)
- compliance debug snapshot (live RPM/in-flight/cooldown counters)
- compliance config update (`POST /api/proxy/compliance`) without full `config` round-trip
- key mutating admin endpoints emit `[ADMIN_AUDIT]` logs with actor identity and before/after details
- clear session bindings
- clear rate limits (all or account)
- preferred account get/set
- ZAI:
- fetch model list
- Proxy pool:
- config, runtime knobs snapshot/update (`GET|POST /api/proxy/pool/runtime`), strategy snapshot/update (`GET|POST /api/proxy/pool/strategy`), list bindings, bind/unbind account, account binding lookup
- scoped policy note: pool strategy/runtime updates currently return `runtime_apply.policy = hot_applied_when_safe`; sticky/request-timeout/compliance return `always_hot_applied`
- trigger proxy health check
- Logs/stats:
- proxy stats
- logs list/count/detail/clear
- token stats hourly/daily/weekly/by-account/by-model/trends/summary/clear
- Security:
- access logs/stats/token-stats
- blacklist get/add/remove/clear/check
- whitelist get/add/remove/clear/check
- security config get/update
- User tokens:
- list/create/update/delete/renew/summary
- System and integrations:
- data dir, update settings/check/touch/save
- antigravity path/args/cache paths/cache clear
- log cache clear
- debug console enable/disable/logs/clear
- CLI sync status/sync/restore/config
- OpenCode sync status/sync/restore/config

## Route-Mounted Conditions

- `/api/*` routes are not exposed unless `ABV_ENABLE_ADMIN_API=true`: `src/proxy/server.rs`.
- `/auth/callback` is also only mounted when admin API is enabled: `src/proxy/server.rs`.
- Sticky debug endpoint is `GET /api/proxy/session-bindings`; clear endpoint is `POST /api/proxy/session-bindings/clear`.
