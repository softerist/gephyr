# Gephyr Architecture

## Runtime Component Map

Core runtime state is assembled in `src/proxy/server.rs` and carried via `AppState` (`src/proxy/state.rs`):

- `CoreServices`
  - `token_manager`: account pool, selection, sticky/session bindings, compliance guards (`src/proxy/token/manager.rs`)
  - `upstream`: outbound HTTP client (`src/proxy/upstream/client.rs`)
  - `monitor`: request logs + counters (`src/proxy/monitor.rs`)
  - `integration` + `account_service`: system integration and account management
- `ConfigState`
  - mutable runtime config mirrors (mapping, security, timeouts, etc.)
  - synchronized hot-apply entrypoint: `apply_proxy_config`
- `RuntimeState`
  - runtime-only controls (running flag, port, proxy-pool runtime state/manager)

## Routing and Middleware

Public and admin route composition:

- Public proxy routes: `src/proxy/routes/mod.rs` -> `build_proxy_routes`
- Admin routes: `src/proxy/routes/admin.rs` -> grouped builders in `src/proxy/routes/admin_groups.rs`
- Admin capabilities snapshot: `GET /api/version/routes` from `admin_version_route_capabilities`

Middleware order for proxy routes (`src/proxy/routes/mod.rs`):

1. IP filter
2. auth
3. monitor

Admin routes are guarded by `admin_auth_middleware` in `build_admin_routes`.

Server-level CORS is applied in `src/proxy/server.rs` via `cors_layer`, sourced from `proxy.cors` config:

- default: `strict` with localhost allowlist
- opt-in: `permissive` mode for local/dev compatibility

Client IP resolution for middleware (`src/proxy/middleware/client_ip.rs`) is trust-gated:

- default (`proxy.trusted_proxies` empty): use socket `ConnectInfo` only
- if peer socket IP matches trusted proxy IP/CIDR, forwarded headers may be used (`x-forwarded-for`, then `x-real-ip`)

## Config Mutation Flow

### Full config path

- Endpoint: `POST /api/config` (`src/proxy/admin/runtime/config_pool.rs`)
- Flow:
  1. load submitted config
  2. validate
  3. persist (`save_app_config`)
  4. hot-apply to runtime (`ConfigState::apply_proxy_config` + token-manager sync)
  5. emit structured admin audit

### Scoped proxy patch path

Scoped endpoints use shared patch helper in `src/proxy/admin/runtime/config_patch.rs`:

1. resolve actor
2. load persisted config
3. apply endpoint patch closure
4. validate
5. persist
6. return `before/after + runtime_apply_policy`
7. endpoint applies runtime mutation and returns `runtime_apply` in API response

Scoped endpoints in this path:

- `POST /api/proxy/sticky`
- `POST /api/proxy/request-timeout`
- `POST /api/proxy/compliance`
- `POST /api/proxy/pool/strategy`
- `POST /api/proxy/pool/runtime`

## Hot-Reload Policy

Policy enum: `RuntimeApplyPolicy` in `src/proxy/admin/runtime/config_patch.rs`.

Current scoped endpoint policy mapping:

- `always_hot_applied`
  - sticky config
  - request-timeout
  - compliance config
- `hot_applied_when_safe`
  - proxy-pool strategy
  - proxy-pool runtime knobs
- `requires_restart`
  - currently not assigned to scoped proxy update endpoints (reserved for fields that cannot be safely hot-applied)

API contract for scoped updates includes:

- `runtime_apply.policy`
- `runtime_apply.applied`
- `runtime_apply.requires_restart`

This makes hot-apply behavior explicit for operators and scripts.

## Token Manager Data Flow

Main selection and control paths:

- request -> account selection (`manager_runtime.rs` + selection/rotation modules)
- sticky bindings:
  - in-memory map + optional persisted `session_bindings.json`
  - debug snapshot via `GET /api/proxy/session-bindings`
- compliance controls:
  - global/account RPM windows
  - in-flight concurrency
  - cooldown windows
  - debug snapshot via `GET /api/proxy/compliance`

Operational snapshot endpoint:

- `GET /api/proxy/metrics` aggregates runtime/monitor/sticky/compliance data.
- `GET /api/proxy/metrics` also exposes `runtime_apply_policies_supported` for machine-readable policy discovery.

## Observability and Audit

- Request monitor:
  - stats/logs in `src/proxy/monitor.rs`
  - admin endpoints in `src/proxy/admin/runtime/logs.rs`
- Structured admin audit:
  - actor resolution/logging in `src/proxy/admin/runtime/audit.rs`
  - event model in `src/proxy/admin/runtime/audit_event.rs`
  - emitted with `[ADMIN_AUDIT]` prefix for grep compatibility

## Failure Domains and Recovery

- Persisted config errors:
  - validation failure -> request rejected (400)
  - save/read failure -> internal error (500)
- Secret migration path:
  - run binary with `--reencrypt-secrets` to rewrite encrypted config/account fields into current ciphertext format
  - command exits after migration; normal proxy service startup is skipped in this mode
- Runtime drift risks:
  - minimized via shared scoped patch helper and explicit runtime apply policy
- Session stickiness restart behavior:
  - persistence controlled by `persist_session_bindings`
  - validated by restart smoke tests/scripts
- Admin auth lockout risk:
  - `POST /api/config` preserves existing API key when blank input is submitted
- OAuth linkage contract:
  - callback success means `authorization received`, not `account linked`
  - account linking is only successful when OAuth flow reaches terminal `linked`
  - if token exchange/user-info/account-save fails, terminal state must be explicit (`failed`, `rejected`, or `cancelled`) and never presented as linked
  - containerized/runtime prerequisite for reliable encrypted persistence: set `ABV_ENCRYPTION_KEY` (machine UID may be unavailable in some containers)
- Graceful shutdown path:
  - Ctrl+C signals accept-loop shutdown
  - optional admin stop hook can also signal graceful shutdown when `ABV_ADMIN_STOP_SHUTDOWN=true` and `POST /api/proxy/stop` is called
  - listener stops accepting new sockets
  - active connections are drained with bounded timeout (`ABV_SHUTDOWN_DRAIN_TIMEOUT_SECS`, default 10s, range 1-600), then aborted if needed
  - long-running streams may be aborted on shutdown once drain timeout is exceeded

## HTTP/2 Evaluation

- Current server runtime is HTTP/1.1 (`hyper::server::conn::http1::Builder`) by design.
- Local concurrency benchmark (`src/proxy/server.rs` test `http1_health_concurrency_smoke_benchmark`) measured:
  - `1500` requests
  - concurrency `64`
  - elapsed `~894ms`
  - throughput `~1676.90 req/s`
- Decision: no immediate HTTP/2 implementation; revisit only if real workloads show sustained multiplexing bottlenecks.

## Test Strategy Map

Unit-heavy coverage in `src/proxy/tests` with focused admin runtime suite:

- `src/proxy/tests/admin_runtime_endpoints.rs`
  - scoped config updates
  - auth regression
  - restart-like reinit persistence flow
  - route capability and group parity checks
  - metrics schema stability

Operator smoke scripts in `scripts/` validate live runtime behavior:

- session binding persistence
- compliance counters
- proxy pool strategy/runtime endpoints
