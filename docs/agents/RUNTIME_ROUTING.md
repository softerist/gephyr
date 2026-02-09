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

- `ABV_API_KEY` / `API_KEY`
- `ABV_WEB_PASSWORD` / `WEB_PASSWORD`
- `ABV_AUTH_MODE` / `AUTH_MODE`
- `ABV_ALLOW_LAN_ACCESS` / `ALLOW_LAN_ACCESS`
- `ABV_MAX_BODY_SIZE`
- `ABV_ENABLE_ADMIN_API`
- `ABV_PUBLIC_URL`
- `ABV_DATA_DIR`

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
- Model routing uses custom mappings + wildcard rules + defaults: `src/proxy/common/model_mapping.rs`.
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
- compliance guard path (when enabled):
- retries are capped by `max_retry_attempts`
- per-account/global RPM caps and per-account concurrency caps are enforced before upstream attempt
- risky statuses (`401`,`403`,`429`,`500`,`503`,`529`) place the selected account in temporary cooldown
- near-expiry refresh + persistence
- account disable/removal on `invalid_grant`

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
