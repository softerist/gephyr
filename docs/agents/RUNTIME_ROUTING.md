# Runtime and Routing (Code-Derived)

## Boot and Runtime Model

- Entrypoint: `src/main.rs` -> `gephyr_lib::run()`.
- Runtime is headless in current boot path: `src/lib.rs`.
- Startup does:
- load and validate config
- apply env overrides
- force strict auth hardening
- start proxy service
- init scheduler
- wait for Ctrl+C

## Config and Env Overlays

From `src/lib.rs` and `src/proxy/server.rs`:

- `API_KEY`
- `WEB_PASSWORD`
- `AUTH_MODE`
- `ALLOW_LAN_ACCESS`
- `MAX_BODY_SIZE`
- `ENABLE_ADMIN_API`
- `PUBLIC_URL`
- `DATA_DIR`
- `ALLOWED_GOOGLE_DOMAINS`
- Optional: `ANTIGRAVITY_STORAGE_JSON_PATH` (override path to IDE `storage.json` for device profile capture)
- `SCHEDULER_REFRESH_JITTER_MIN_SECONDS`
- `SCHEDULER_REFRESH_JITTER_MAX_SECONDS`
- `SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS`
- `SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS`
- `STARTUP_HEALTH_DELAY_MIN_SECONDS`
- `STARTUP_HEALTH_DELAY_MAX_SECONDS`

TLS backend note:
- TLS backend selection is compile-time (`tls-native` default, `tls-rustls` alternate) and is surfaced at runtime via `GET /api/proxy/metrics` -> `runtime.tls_backend`: `Cargo.toml`, `src/utils/http.rs`, `src/proxy/admin/runtime/service_control.rs`

From `proxy` config (`src/proxy/config.rs`):

- `persist_session_bindings` (default: `true`) controls whether sticky session bindings are persisted across process restarts.
- `compliance` (default: disabled) adds runtime request guardrails:
- `max_global_requests_per_minute`
- `max_account_requests_per_minute`
- `max_account_concurrency`
- `risk_cooldown_seconds` for risky upstream statuses (`401`,`403`,`429`,`500`,`503`,`529`)
- `max_retry_attempts` cap for handler retry loops

## Middleware Stack

Proxy routes (`src/proxy/routes/mod.rs`) apply:

- IP filter
- Auth
- Monitor

App-wide layers (`src/proxy/server.rs`) apply:

- service-status middleware
- CORS layer
- default body limit

## Protocol Routing and Transforms

- OpenAI path: `src/proxy/handlers/openai.rs`
- Gemini path: `src/proxy/handlers/gemini.rs`
- Claude path: `src/proxy/handlers/claude.rs`

Shared behavior:

- Non-stream client requests are often converted to internal stream calls and collected back to JSON.
- Claude handler now always uses Gemini `streamGenerateContent` upstream and converts back to JSON for non-stream clients via stream collection (unary mapper path removed): `src/proxy/handlers/claude.rs`, `src/proxy/mappers/claude/mod.rs`
- Model routing uses custom mappings + wildcard rules + defaults: `src/proxy/common/model_mapping.rs`.
- account-bound upstream requests apply bound device profile headers (`x-machine-id`, `x-mac-machine-id`, `x-dev-device-id`, `x-sqm-id`) when a device profile is available: `src/proxy/upstream/client.rs`
- Session identity precedence for OpenAI/Gemini requests:
- explicit session headers (`x-session-id`, `x-client-session-id`, `x-gephyr-session-id`, `x-conversation-id`, `x-thread-id`)
- explicit payload fields (`session_id`/`sessionId`, `conversation_id`/`conversationId`, `thread_id`/`threadId`, metadata session/user id fields)
- fallback content-derived hash when explicit id is absent

## Token/Account Scheduling

From `src/proxy/token/*`:

- 5s token-acquisition timeout
- preferred-account mode
- sticky session reuse
- 60s last-used lock path
- P2C candidate selection
- fallback delay + optimistic reset path
- model-scoped rate-limit checks are applied in sticky reuse, preferred selection, and rotation fallback paths
- sticky session bindings can be persisted to disk and restored on startup when `persist_session_bindings=true`
- `scheduling.max_wait_seconds` controls sticky binding retention on bound-account rate limits:
- if wait is `<= max_wait_seconds`, binding is retained and current request may use fallback account without rebinding
- if wait is `> max_wait_seconds`, binding is released and a new binding may be established
- admin visibility endpoint for sticky behavior: `GET /api/proxy/session-bindings` (current bindings + recent sticky decision events)
- admin visibility endpoint for compliance behavior: `GET /api/proxy/compliance` (config + live RPM/in-flight/cooldown snapshot)
- compliance guard path (when enabled):
- retries are capped by `max_retry_attempts`
- per-account/global RPM caps and per-account concurrency caps are enforced before upstream attempt
- risky statuses (`401`,`403`,`429`,`500`,`503`,`529`) place the selected account in temporary cooldown
- near-expiry refresh + persistence
- account disable/removal on `invalid_grant`
- startup health token refresh now runs sequentially (one account at a time), with randomized delay between accounts to avoid simultaneous Google refresh spikes (defaults `1..10s`, configurable via `STARTUP_HEALTH_DELAY_MIN_SECONDS` / `STARTUP_HEALTH_DELAY_MAX_SECONDS`): `src/proxy/token/startup_health.rs`

From scheduler path (`src/modules/system/scheduler.rs`, `src/commands/mod.rs`, `src/modules/auth/account.rs`):

- periodic quota refresh still runs every 10 minutes when `auto_refresh=true`, with pre-run scheduler jitter (`SCHEDULER_REFRESH_JITTER_MIN_SECONDS` / `SCHEDULER_REFRESH_JITTER_MAX_SECONDS`)
- per-run account processing is now sequential with randomized per-account delay (defaults `5..30s`, configurable via `SCHEDULER_ACCOUNT_REFRESH_MIN_SECONDS` / `SCHEDULER_ACCOUNT_REFRESH_MAX_SECONDS`)

## Upstream and Proxy Pool Routing

- Upstream client: `src/proxy/upstream/client.rs`
- Proxy pool manager: `src/proxy/proxy_pool.rs`

Routing order:

- account-bound proxy
- pool-selected proxy
- app upstream proxy
- direct

Pool strategies:

- `RoundRobin`, `Random`, `Priority`, `LeastConnections`, `WeightedRoundRobin`
- weighted uses weighted random selection derived from proxy priority.
- `LeastConnections` currently uses total historical proxy usage (counter is monotonic), not live in-flight connection count: `src/proxy/proxy_pool.rs`
- if every healthy proxy is already account-bound, unbound traffic can still be routed through a shared healthy proxy only when `proxy_pool.allow_shared_proxy_fallback=true`; otherwise selection returns no proxy: `src/proxy/proxy_pool.rs`
- if `proxy_pool.require_proxy_for_account_requests=true`, account requests fail closed when no eligible proxy is available (no app-upstream/direct fallback): `src/proxy/proxy_pool.rs`, `src/proxy/upstream/client.rs`
- `max_accounts` enforcement applies to explicit persistent bindings (`bind_account_to_proxy`), while shared fallback selection is request-scoped routing for unbound accounts: `src/proxy/proxy_pool.rs`
- default health-check URL (`http://cp.cloudflare.com/generate_204`) now requires `204` specifically; custom health-check URLs accept any `2xx`: `src/proxy/proxy_pool.rs`

Claude-specific runtime notes:

- Layer-3 compression sync call path now uses shared upstream client routing (proxy-pool/app-upstream/direct) instead of constructing a raw `reqwest::Client`: `src/proxy/handlers/claude.rs`
- signature-recovery retry path now sets `retried_without_thinking=true`, so downstream transform/retry strategy can observe that state correctly: `src/proxy/handlers/claude.rs`
