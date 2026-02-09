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
- Proxy control:
- status/start/stop
- model mapping update
- api-key generation
- config save (`POST /api/config`) now returns `{ ok, saved, message, warnings[] }` and protects against empty `proxy.api_key` lockout by preserving the existing key
- version/routes capability snapshot (`GET /api/version/routes`)
- sticky runtime snapshot/config update (`GET|POST /api/proxy/sticky`) for scheduling + `persist_session_bindings` without full config round-trip
- session bindings debug snapshot (bindings + recent sticky decisions)
- compliance debug snapshot (live RPM/in-flight/cooldown counters)
- compliance config update (`POST /api/proxy/compliance`) without full `config` round-trip
- clear session bindings
- clear rate limits (all or account)
- preferred account get/set
- ZAI:
- fetch model list
- Proxy pool:
- config, list bindings, bind/unbind account, account binding lookup
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
