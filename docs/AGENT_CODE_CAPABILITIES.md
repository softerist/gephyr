# Gephyr Agent Capability Report (Code-Derived)

This report is derived from **source code only** under `src/` (no `.md` docs used as primary inputs).

## Runtime and Boot Model

- Entrypoint starts headless runtime: `src/main.rs`, `src/lib.rs`
- Headless startup initializes:
- Token stats DB: `src/modules/stats/token_stats.rs`
- Security DB: `src/modules/persistence/security_db.rs`
- User token DB: `src/modules/persistence/user_token_db.rs`
- Security hardening forces proxy auth mode to `Strict` when configured as `Off`: `src/lib.rs`
- Scheduler runs quota refresh every 10 minutes when `auto_refresh=true`, with pre-run jitter window controlled by `ABV_SCHEDULER_REFRESH_JITTER_MIN_SECONDS` / `ABV_SCHEDULER_REFRESH_JITTER_MAX_SECONDS` (default `30..120`), and warmup is explicitly disabled in headless mode: `src/modules/system/scheduler.rs`
- Opening data folder is disabled in headless mode: `src/commands/mod.rs`
- One-time secret migration mode is available via `--reencrypt-secrets` (rewrites config + account encrypted fields, then exits): `src/lib.rs`, `src/commands/crypto.rs`
- Ctrl+C headless shutdown now triggers graceful proxy stop (accept-loop shutdown + bounded connection drain controlled by `ABV_SHUTDOWN_DRAIN_TIMEOUT_SECS`, default 10s); optional admin stop hook via `ABV_ADMIN_STOP_SHUTDOWN=true` + `POST /api/proxy/stop`: `src/lib.rs`, `src/commands/proxy.rs`, `src/proxy/server.rs`, `src/proxy/admin/runtime/service_control.rs`
- HTTP/2 is currently deferred after local HTTP/1.1 concurrency benchmark (`1500` requests @ `64` concurrency, `~1676.90 req/s`): `src/proxy/server.rs`
- TLS backend is compile-time selectable via Cargo features (`tls-native` default, optional `tls-rustls` profile): `Cargo.toml`, `src/utils/http.rs`

## Public Proxy API Surface

Defined in `src/proxy/routes/mod.rs`:

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

Proxy middleware order:

- IP filter
- Auth
- Monitor

## Admin API Surface

Admin routes are defined in `src/proxy/routes/admin.rs` and mounted under `/api` only when `ABV_ENABLE_ADMIN_API=true` (`src/proxy/server.rs`).

Main admin groups include:

- Accounts CRUD/switch/import/export/reorder/quota/proxy-toggle
- OAuth prepare/start/complete/cancel/manual-code
- Proxy start/stop/status/mapping/api-key/session/rate-limit/preferred-account
- Proxy scoped update endpoints expose runtime-apply contract (`runtime_apply.policy`, `runtime_apply.applied`, `runtime_apply.requires_restart`)
- Proxy metrics snapshot endpoint (`GET /api/proxy/metrics`) exposes runtime/monitor/sticky/proxy-pool/compliance aggregates (including `runtime.tls_backend`, shared-fallback, and strict-rejection counters) and supported runtime-apply policies
- Proxy pool config/bindings/bind/unbind/health-check
- Logs and proxy stats
- Token stats (hourly/daily/weekly/by-account/by-model/trends/summary/clear)
- Security logs/stats/blacklist/whitelist/config/token-stats
- User tokens CRUD/renew/summary
- CLI sync status/sync/restore/config (Claude/Codex/Gemini)
- OpenCode sync status/sync/restore/config
- System data-dir/update settings/check/cache clear/debug console controls
- OAuth callback route `/auth/callback` (only mounted with admin API enabled)

## Auth and Security Behavior

- Auth modes: `Off`, `Strict`, `AllExceptHealth` in `src/proxy/config.rs`, `src/proxy/security.rs`
- Legacy compatibility: `auto` auth mode values are coerced to `strict` during env/config load in headless runtime
- `OPTIONS` requests bypass auth in middleware: `src/proxy/middleware/auth.rs`
- `/internal/*` bypass exists in auth/monitor middleware logic (no mounted internal routes were found)
- API key sources:
- `Authorization: Bearer ...`
- `x-api-key`
- `x-goog-api-key`
- Admin strict auth checks admin password first (if configured), then API key fallback: `src/proxy/middleware/auth.rs`
- API/admin secret comparison uses a constant-time helper in auth middleware: `src/proxy/middleware/auth.rs`
- Secret encryption writes are versioned (`v2:<base64>`), while decrypt path remains backward-compatible with legacy unversioned payloads: `src/utils/crypto.rs`
- `decrypt_secret_or_plaintext` fails closed for explicit `v2:` and encrypted-looking payloads; malformed/undecryptable prefixed ciphertext no longer silently falls back to plaintext: `src/utils/crypto.rs`
- serde secret adapter (`deserialize_secret`) is resilient for account-management deserialization and logs decrypt failures while preserving raw value (prevents account-list/load bricking when on-disk ciphertext is malformed): `src/utils/crypto.rs`, `src/modules/auth/account.rs`
- IP filter supports whitelist mode, whitelist-priority mode, blacklist exact/CIDR matching, blocked-request JSON responses, and blocked log persistence: `src/proxy/middleware/ip_filter.rs`, `src/modules/persistence/security_db.rs`
- Client IP resolution trusts forwarded headers only for socket peers in `proxy.trusted_proxies` (IP/CIDR); otherwise it uses socket `ConnectInfo` only: `src/proxy/middleware/client_ip.rs`, `src/proxy/config.rs`

## Service Status, CORS, Body Limits

- Service-status middleware can return `503` when service disabled: `src/proxy/middleware/service_status.rs`
- CORS is config-driven via `proxy.cors`:
- default `strict` mode with localhost allowlist
- explicit `permissive` mode for any-origin local/dev compatibility
- credentials remain disabled: `src/proxy/middleware/cors.rs`, `src/proxy/config.rs`
- Body limit defaults to 100MB via `DefaultBodyLimit::max`, configurable by `ABV_MAX_BODY_SIZE`: `src/proxy/server.rs`
- `USER_AGENT` initialization is deterministic/local and does not perform blocking remote fetch on first use: `src/constants.rs`

## Protocol Handling and Transformations

### OpenAI (`src/proxy/handlers/openai.rs`)

- Supports chat/completions/responses style payloads
- Supports Codex-like `input` + `instructions` normalization
- Converts many non-stream requests into internal stream flow, then collects to JSON
- Handles signature-related recovery logic
- Handles 401/403 with account block/forbidden handling via token manager
- Handles tool calls and tool outputs normalization

### Gemini (`src/proxy/handlers/gemini.rs`)

- Supports `generateContent` and `streamGenerateContent`
- Wraps requests and unwraps responses via mappers
- Injects anthropic beta headers when mapped model is Claude-like
- Stream path extracts/caches thought signatures and can collect stream to JSON

### Claude (`src/proxy/handlers/claude.rs`)

- Supports ZAI dispatch modes: `Off`, `Exclusive`, `Fallback`, `Pooled`
- Warmup detection/interception returns synthetic stream/non-stream response
- Background task detection routes to internal background model
- Context compression pipeline:
- Layer 1 tool-round trimming
- Layer 2 thinking compression with signature preservation
- Layer 3 XML summary fallback flow
- Signature family checks and tool-loop closure logic
- Upstream call path is now stream-first for requests (Gemini `streamGenerateContent`), with non-stream client responses built by collecting the stream to JSON
- Legacy unary response mapper path was removed (`src/proxy/mappers/claude/response.rs`)
- `count_tokens` is placeholder unless routed through ZAI provider path

## Model Routing and Mapping

- Extensive static + alias + wildcard custom mapping engine in `src/proxy/common/model_mapping.rs`
- `resolve_model_route` applies:
- exact custom mapping
- most-specific wildcard mapping
- system fallback mapping
- Supports canonicalization helpers and compatibility checks for signature families

## Token and Account Orchestration

- Token manager loads account JSONs from data dir
- Skips disabled/proxy-disabled/forbidden/validation-blocked accounts
- Auto-clears expired validation-block flags on disk
- Proxy token loader now hard-fails invalid encrypted token payloads during runtime account load (malformed `v2:` token fields are rejected in loader path): `src/proxy/token/loader.rs`
- Token acquisition timeout: 5 seconds (`src/proxy/token/manager_runtime.rs`)
- Selection strategy combines:
- preferred-account mode
- sticky sessions
- 60s last-used lock behavior
- P2C selection
- fallback delay and optimistic global reset
- Refreshes access tokens near expiry and persists updates
- On `invalid_grant`, disables account and removes it from active in-memory pool
- Project ID resolution from upstream with fallback generation path
- Periodic rate-limit cleanup task runs every 15s

## Rate Limiting and Circuit Breaker

- Account-level and model-level lock keys
- Parses retry from headers and multiple body patterns (including `quotaResetDelay`)
- Distinguishes reasons (`QUOTA_EXHAUSTED`, `RATE_LIMIT_EXCEEDED`, `MODEL_CAPACITY_EXHAUSTED`, `ServerError`)
- Uses configurable backoff steps from app config
- Supports precise lockout from reset timestamps and realtime quota fetch attempts
- Circuit breaker can disable RL enforcement globally

## Proxy Pool and Upstream Routing

- Proxy pool manager supports:
- `RoundRobin`
- `Random`
- `Priority`
- `LeastConnections`
- `WeightedRoundRobin` (weighted random selection using priority-derived weights)
- Supports account-to-proxy bindings with max-accounts enforcement
- When all healthy proxies are already bound, unbound account routing uses shared healthy proxy fallback only if `proxy.proxy_pool.allow_shared_proxy_fallback=true` (default true); when false, selection returns no proxy
- When `proxy.proxy_pool.require_proxy_for_account_requests=true`, account-routed requests fail closed if no eligible proxy exists (no app-upstream/direct fallback path for account requests)
- `max_accounts` semantics apply to persistent bindings; shared fallback is request-scoped routing for unbound accounts and does not create bindings
- `LeastConnections` strategy currently uses total historical usage counter (monotonic) rather than live active-connection count
- Persists bindings to app config
- Health checks run in loop and on-demand
- Default health-check URL path enforces HTTP `204`; custom configured health-check URLs accept `2xx`
- Upstream client routing order:
- account-bound proxy
- pool-selected proxy
- app upstream proxy fallback
- direct
- Internal endpoint fallback chain for `v1internal` across sandbox/daily/prod

## Monitoring and Persistence

- Monitor middleware captures request/response metadata and bodies
- Monitor persistence writes are backpressure-limited by bounded semaphore; overflow writes are dropped and counted (`dropped_persist_writes`) instead of unbounded fire-and-forget fanout: `src/proxy/monitor.rs`
- Stream responses are reconstructed/parsing-attempted for usage and content
- Excludes `/api/*`, `/internal/*`, and `event_logging` from monitor middleware
- Persistence stores:
- `proxy_logs.db` (`request_logs`)
- `security.db` (`ip_access_logs`, `ip_blacklist`, `ip_whitelist`)
- `user_tokens.db` (`user_tokens`, `token_ip_bindings`, `token_usage_logs`)
- `token_stats.db` (`token_usage`, `token_stats_hourly`)

## User Token Capabilities

- Create/update/delete/renew/list/summary via admin and command layer
- Per-token fields include:
- expiry window
- enable flag
- max IP cap
- curfew window
- usage counters
- bound IP entries
- Auth middleware supports user-token-based access when primary API key auth fails and strict admin mode is not in effect

## OAuth, Account Lifecycle, Device Profiles

- OAuth:
- PKCE verifier/challenge
- local callback listeners (IPv4/IPv6)
- CSRF `state` checks
- browser-driven and manual code-submit paths
- account service supports add/upsert/switch/delete/list
- device profile operations:
- bind/capture/generate
- version history
- restore baseline/current/version
- delete non-current history version
- bound device headers (`x-machine-id`, `x-mac-machine-id`, `x-dev-device-id`, `x-sqm-id`) are applied to OAuth calls, quota/loadCodeAssist calls, and account-bound v1internal upstream calls when a device profile is present

## CLI and OpenCode Integrations

- CLI sync (`src/proxy/cli_sync.rs`):
- app detection/version probe
- config patching for Claude/Codex/Gemini
- backup and restore
- config content readback
- OpenCode sync (`src/proxy/opencode_sync.rs`):
- install detection across OS-specific paths
- sync/restore/status/config readback
- optional account export sync into `antigravity-accounts.json`

## Environment Variables Used by Code

- Runtime proxy/auth:
- `ABV_API_KEY`, `API_KEY`
- `ABV_WEB_PASSWORD`, `WEB_PASSWORD`
- `ABV_AUTH_MODE`, `AUTH_MODE`
- `ABV_ALLOW_LAN_ACCESS`, `ALLOW_LAN_ACCESS`
- `ABV_ENCRYPTION_KEY`
- `ABV_MAX_BODY_SIZE`
- `ABV_SHUTDOWN_DRAIN_TIMEOUT_SECS`
- `ABV_ADMIN_STOP_SHUTDOWN`
- `ABV_ENABLE_ADMIN_API`
- `ABV_PUBLIC_URL`
- `ABV_DATA_DIR`
- `ABV_ALLOWED_GOOGLE_DOMAINS`
- `ABV_OAUTH_USER_AGENT`
- `ABV_SCHEDULER_REFRESH_JITTER_MIN_SECONDS`
- `ABV_SCHEDULER_REFRESH_JITTER_MAX_SECONDS`
- OAuth:
- `GEPHYR_GOOGLE_OAUTH_CLIENT_ID`, `ABV_GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_ID`
- `GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET`, `ABV_GOOGLE_OAUTH_CLIENT_SECRET`, `GOOGLE_OAUTH_CLIENT_SECRET`

## Open Edge Cases / Defects

- None currently open (as of 2026-02-11).
- Deferred follow-up items are tracked in `docs/agents/FOLLOW_UP_TICKETS.md`.

## Notable Implementation Limits

- No non-headless runtime mode in current boot path
- No mounted `/internal/*` endpoints found in router definitions
- Middleware logging module is placeholder test-only (`src/proxy/middleware/logging.rs`)
- Warmup config exists in app config model but runtime scheduler states warmup disabled in headless mode
