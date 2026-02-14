# Gephyr

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-CC--BY--NC--SA--4.0-blue)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue?logo=docker)](https://www.docker.com/)

Gephyr is a headless local API relay/proxy service for Google AI services. It provides a unified OpenAI-compatible API interface for routing requests to Google's AI backends.

## Features

- 🔒 **Secure API Authentication** — Bearer token auth with configurable modes
- 🔄 **Multi-Account Support** — Link multiple Google accounts and rotate between them
- 🌐 **OpenAI-Compatible API** — Use with any OpenAI SDK client
- 🐳 **Docker Native** — One-command deployment
- ⚡ **High Performance** — Built with Rust + Axum for low latency

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed and running
- [PowerShell](https://docs.microsoft.com/en-us/powershell/) (Windows) or Bash (Linux/macOS)

### 1. Clone & Configure

```bash
git clone https://github.com/softerist/gephyr.git
cd gephyr

# Copy the example env file and edit with your values
cp .env.example .env.local
```

Edit `.env.local` with your API key and OAuth credentials:

```env
API_KEY=gph_your_secure_api_key
GOOGLE_OAUTH_CLIENT_ID=your_client_id.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-your_secret

# Optional: restrict accepted Google Workspace domains for identity verification
ALLOWED_GOOGLE_DOMAINS=example.com,subsidiary.example.com

# Optional: scheduler jitter window in seconds (defaults shown)
SCHEDULER_REFRESH_JITTER_MIN_SECONDS=30
SCHEDULER_REFRESH_JITTER_MAX_SECONDS=120

# Optional: deterministic per-account stagger before each batch refresh task
ACCOUNT_REFRESH_STAGGER_MIN_MS=250
ACCOUNT_REFRESH_STAGGER_MAX_MS=1500

# Optional: startup health-check smoothing (boot-time token refresh)
STARTUP_HEALTH_MAX_CONCURRENT_REFRESHES=5
STARTUP_HEALTH_JITTER_MIN_MS=150
STARTUP_HEALTH_JITTER_MAX_MS=1200

# Optional runtime TLS backend override when binary includes both stacks
TLS_BACKEND=rustls

# Optional startup TLS canary probe (recommended when changing TLS backend)
TLS_CANARY_URL=https://oauth2.googleapis.com/token
TLS_CANARY_TIMEOUT_SECS=5
TLS_CANARY_REQUIRED=false
```

### 2. Build & Run

```powershell
# Build Docker image
docker build -t gephyr:latest -f docker/Dockerfile .

# Start the service
.\console.ps1 start

# Check status
.\console.ps1 status
```

### 3. Link Google Account (OAuth)

```powershell
.\console.ps1 login
# Browser opens → Complete Google OAuth → Account linked
```

### 4. Test the API

```powershell
.\console.ps1 api-test
```

---

## API Reference

### Base URL

```
http://127.0.0.1:8045
```

### Authentication

All requests require a Bearer token in the `Authorization` header:

```
Authorization: Bearer YOUR_API_KEY
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | Health check |
| `/v1/chat/completions` | POST | OpenAI-compatible chat completions |
| `/v1/messages` | POST | Claude-compatible messages API |
| `/api/accounts` | GET | List linked accounts (admin API) |
| `/api/auth/url` | GET | Get OAuth login URL (admin API) |

### Example: Chat Completion

```bash
curl http://127.0.0.1:8045/v1/chat/completions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.3-codex",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_KEY` | ✅ | — | API key for console scripts and runtime auth |
| `AUTH_MODE` | — | `strict` | Auth mode: `strict`, `off`, `all_except_health`, `auto` |
| `ALLOW_LAN_ACCESS` | — | `false` | Bind to `0.0.0.0` instead of `127.0.0.1` |
| `ENABLE_ADMIN_API` | — | `false` | Enable `/api/*` admin routes |
| `GOOGLE_OAUTH_CLIENT_ID` | — | — | Google OAuth Client ID |
| `GOOGLE_OAUTH_CLIENT_SECRET` | — | — | Google OAuth Client Secret |
| `TLS_BACKEND` | — | compiled default | Runtime TLS backend override (`native-tls`/`rustls`) when build includes both |
| `TLS_CANARY_URL` | — | — | Optional startup TLS canary probe URL |
| `TLS_CANARY_TIMEOUT_SECS` | — | `5` | Startup TLS canary timeout seconds (clamped 1..60) |
| `TLS_CANARY_REQUIRED` | — | `false` | If `true`, startup fails when TLS canary probe fails |
| `ALLOWED_GOOGLE_DOMAINS` | — | — | Optional comma-separated Workspace domain allowlist for identity verification |
| `DATA_DIR` | — | `~/.gephyr` | Data directory path |
| `PUBLIC_URL` | — | — | Public URL for OAuth callbacks (hosted deployments) |
| `MAX_BODY_SIZE` | — | `104857600` | Max request body size in bytes |
| `SCHEDULER_REFRESH_JITTER_MIN_SECONDS` | — | `30` | Min random delay before each scheduled quota-refresh batch |
| `SCHEDULER_REFRESH_JITTER_MAX_SECONDS` | — | `120` | Max random delay before each scheduled quota-refresh batch |
| `ACCOUNT_REFRESH_STAGGER_MIN_MS` | — | `250` | Min deterministic per-account delay before each batch refresh task |
| `ACCOUNT_REFRESH_STAGGER_MAX_MS` | — | `1500` | Max deterministic per-account delay before each batch refresh task |
| `STARTUP_HEALTH_MAX_CONCURRENT_REFRESHES` | — | `5` | Max concurrent token refreshes during startup health-check (clamped 1..32) |
| `STARTUP_HEALTH_JITTER_MIN_MS` | — | `150` | Min random per-account delay before startup health refresh |
| `STARTUP_HEALTH_JITTER_MAX_MS` | — | `1200` | Max random per-account delay before startup health refresh |

Proxy-pool isolation knobs are config/API settings (not env vars):
- `proxy.proxy_pool.allow_shared_proxy_fallback`
- `proxy.proxy_pool.require_proxy_for_account_requests`

### Persistent Session Bindings (Sticky Sessions Across Restart)

`persist_session_bindings` is a config-file setting (not an env var).  
It controls whether sticky session bindings (`session_id -> account_id`) survive process/container restarts.

- Default: `true`
- Config file: `config.json` under your data dir (for example `~/.gephyr/config.json` or `%USERPROFILE%\.gephyr\config.json`)

Example:

```json
{
  "proxy": {
    "persist_session_bindings": true,
    "scheduling": {
      "mode": "balance",
      "max_wait_seconds": 60
    }
  }
}
```

Admin visibility:
- `GET /api/version/routes` returns running version + key route capabilities (useful to detect old images).
- `GET /api/proxy/sticky` returns sticky runtime config (`persist_session_bindings`, scheduling, preferred account).
- `POST /api/proxy/sticky` updates sticky settings only (avoids full `/api/config` round-trip).
- `GET /api/proxy/request-timeout` returns configured/effective runtime timeout.
- `POST /api/proxy/request-timeout` updates timeout only (avoids full `/api/config` round-trip).
- `GET /api/proxy/pool/runtime` returns proxy-pool runtime knobs (`enabled`, `auto_failover`, `allow_shared_proxy_fallback`, `require_proxy_for_account_requests`, `health_check_interval`) plus strategy snapshot.
- `POST /api/proxy/pool/runtime` updates only proxy-pool runtime knobs (avoids full `/api/config` round-trip).
- `GET /api/proxy/pool/strategy` returns current proxy-pool strategy snapshot.
- `POST /api/proxy/pool/strategy` updates proxy-pool strategy only (avoids full `/api/config` round-trip).
- `GET /api/proxy/metrics` returns runtime/monitor/sticky/proxy-pool/compliance aggregates (including TLS diagnostics: backend/requested/compiled/canary snapshot) and supported runtime-apply policy values.
- `GET /api/proxy/google/outbound-policy` returns the effective Google outbound header policy snapshot (mode, host-header behavior, metadata shape, passthrough allow/block policy, debug redaction contract).
- `GET /api/proxy/tls-canary` returns latest TLS canary probe snapshot.
- `POST /api/proxy/tls-canary/run` runs TLS canary probe on demand and returns the latest canary snapshot.
- `GET /api/proxy/compliance` returns live compliance counters/cooldowns (requires admin API enabled).
- `POST /api/proxy/compliance` updates only compliance settings (avoids full `/api/config` round-trip).
- scoped `POST /api/proxy/*` update responses include `runtime_apply` (`policy`, `applied`, `requires_restart`).

Example update call:

```bash
curl -X POST http://127.0.0.1:8045/api/proxy/compliance \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "max_global_requests_per_minute": 120,
    "max_account_requests_per_minute": 10,
    "max_account_concurrency": 1,
    "risk_cooldown_seconds": 300,
    "max_retry_attempts": 2
  }'
```

Sticky-only update call:

```bash
curl -X POST http://127.0.0.1:8045/api/proxy/sticky \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "persist_session_bindings": true,
    "scheduling": {
      "mode": "Balance",
      "max_wait_seconds": 60
    }
  }'
```

Request-timeout-only update call:

```bash
curl -X POST http://127.0.0.1:8045/api/proxy/request-timeout \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "request_timeout": 120
  }'
```

Proxy-pool-strategy-only update call:

```bash
curl -X POST http://127.0.0.1:8045/api/proxy/pool/strategy \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "strategy": "round_robin"
  }'
```

Proxy-pool-runtime-only update call:

```bash
curl -X POST http://127.0.0.1:8045/api/proxy/pool/runtime \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "auto_failover": true,
    "allow_shared_proxy_fallback": false,
    "require_proxy_for_account_requests": true,
    "health_check_interval": 120
  }'
```

### Google Outbound Policy (Config + Runtime)

Google-bound calls now use a shared policy with explicit defaults:

- Always set: `authorization`, `user-agent`, `accept-encoding: gzip`
- JSON requests additionally set: `content-type: application/json`
- Passthrough policy: deny-by-default (only explicit allowlist keys are forwarded)
- Optional explicit `Host` header: compat mode only (`codeassist_compat` + `send_host_header=true`)

Config example (`config.json`):

```json
{
  "proxy": {
    "google": {
      "mode": "public_google",
      "headers": {
        "send_host_header": false
      },
      "identity_metadata": {
        "ide_type": "ANTIGRAVITY",
        "platform": "PLATFORM_UNSPECIFIED",
        "plugin_type": "GEMINI"
      }
    },
    "debug_logging": {
      "log_google_outbound_headers": false
    }
  }
}
```

Runtime note:

- Saving config via `POST /api/config` hot-applies Google outbound policy to live upstream calls (no restart required).
- Verify effective runtime policy with `GET /api/proxy/google/outbound-policy`.

Staging trace validation runbook:

- See `docs/agents/GOOGLE_TRACE_VALIDATION.md` for a step-by-step manual diff workflow.

Manual TLS canary run:

```bash
curl -X POST http://127.0.0.1:8045/api/proxy/tls-canary/run \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json"
```

Practical notes:

- Keep `scheduling.mode` as `balance` or `cache_first` to use sticky session behavior.
- `performance_first` intentionally disables sticky session reuse.
- runtime apply policy mapping:
- sticky / request-timeout / compliance updates: `always_hot_applied`
- proxy-pool strategy / runtime updates: `hot_applied_when_safe`
- `scheduling.max_wait_seconds` keeps sticky binding during short bound-account rate-limit windows; long windows release/rebind.
- `allow_shared_proxy_fallback=false` prevents borrowing an already-bound proxy for unbound accounts.
- `require_proxy_for_account_requests=true` makes account requests fail closed when no eligible proxy is available (instead of app-upstream/direct fallback).
- For maximum stickiness from clients, send a stable explicit session id:
- Header: `x-session-id` (or `x-client-session-id`, `x-gephyr-session-id`, `x-conversation-id`, `x-thread-id`)
- Payload: `session_id` / `sessionId` (also `conversation_id` / `conversationId`, `thread_id` / `threadId`)

### Compliance Guardrails (Low-Risk Account Traffic Profile)

`proxy.compliance` applies runtime guardrails to reduce bursty/account-risky traffic patterns.

- `enabled`: turns guardrails on/off (default: `false`)
- `max_global_requests_per_minute`: global request budget across all accounts
- `max_account_requests_per_minute`: per-account request budget (default `10`)
- `max_account_concurrency`: max in-flight requests per account (default `1`)
- `risk_cooldown_seconds`: temporary cooldown applied after risky upstream statuses (`401`, `403`, `429`, `500`, `503`, `529`)
- `max_retry_attempts`: hard cap for handler retry loops when compliance mode is enabled

Example:

```json
{
  "proxy": {
    "compliance": {
      "enabled": true,
      "max_global_requests_per_minute": 120,
      "max_account_requests_per_minute": 10,
      "max_account_concurrency": 1,
      "risk_cooldown_seconds": 300,
      "max_retry_attempts": 2
    }
  }
}
```

### One-IP Presets (Runbook)

Choose one profile and monitor `/api/proxy/metrics` proxy-pool counters.

- Availability-first:
- `allow_shared_proxy_fallback=true`
- `require_proxy_for_account_requests=false`
- keeps traffic flowing when pool is saturated, but allows shared-proxy reuse

- Isolation-first:
- `allow_shared_proxy_fallback=false`
- `require_proxy_for_account_requests=true`
- fails closed when no eligible proxy exists, reducing shared routing but increasing hard failures

Keep these in both modes:
- `max_account_requests_per_minute=10`
- `max_account_concurrency=1`
- scheduler jitter enabled (`SCHEDULER_REFRESH_JITTER_MIN_SECONDS`, `SCHEDULER_REFRESH_JITTER_MAX_SECONDS`)

### Console Commands

```powershell
.\console.ps1 <command> [options]
```

| Command | Description |
|---------|-------------|
| `start` | Start the container |
| `stop` | Stop and remove container |
| `restart` | Restart container |
| `status` | Show container and API status |
| `logs` | Show container logs |
| `health` | Check `/healthz` endpoint |
| `login` | Start OAuth flow (opens browser) |
| `accounts` | List linked accounts |
| `api-test` | Run a test API completion |
| `rotate-key` | Generate new API key |
| `docker-repair` | Repair Docker builder cache for snapshot/export errors |
| `logout` | Remove all linked accounts |

---

## Admin API Mode

The admin API (`/api/*` routes) is disabled by default for security. Enable it when you need to:

- Bootstrap OAuth login
- Manage accounts
- Access admin configuration

```powershell
# Start with admin API enabled
.\console.ps1 start -EnableAdminApi

# Or restart with admin API
.\console.ps1 restart -EnableAdminApi
```

> **Recommendation**: Enable admin API only during setup/maintenance. Run normal proxy with it disabled.

---

## Multiple Accounts

Gephyr supports linking multiple Google accounts:

```powershell
.\console.ps1 restart -EnableAdminApi
.\console.ps1 login  # Link account A
.\console.ps1 login  # Link account B
.\console.ps1 login  # Link account C
.\console.ps1 accounts  # Verify all linked
.\console.ps1 restart  # Restart with admin API disabled
```

---

## OAuth Setup

See [OAUTH_SETUP.md](OAUTH_SETUP.md) for detailed Google Cloud OAuth configuration.

**Quick summary:**
- **Local/Docker**: Use "Desktop app" OAuth client type
- **Hosted deployment**: Use "Web application" client with `PUBLIC_URL` set

---

## Data Directory

| Platform | Default Path |
|----------|--------------|
| Linux/macOS | `~/.gephyr` |
| Windows | `%USERPROFILE%\.gephyr` |

Override with `DATA_DIR` environment variable.

---

## Docker Build Troubleshooting

If Docker build fails with an error like:

```text
failed to prepare extraction snapshot ... parent snapshot ... does not exist
```

This is typically a Docker BuildKit/builder cache issue on the host (not a Gephyr code issue).

### Fast recovery

```powershell
.\console.ps1 docker-repair
docker build -t gephyr:latest -f docker/Dockerfile .
```

```bash
./console.sh docker-repair
docker build -t gephyr:latest -f docker/Dockerfile .
```

### If it still fails

Use aggressive mode (clears more builder cache; next build will be slower):

```powershell
.\console.ps1 docker-repair -Aggressive
```

```bash
./console.sh docker-repair --aggressive
```

### Preventive tips

- Avoid force-closing Docker Desktop during builds.
- Keep sufficient free disk space for image layers and cache.
- If Docker was updated/restarted mid-build, rerun `docker-repair` before rebuilding.

---

## Development

### Build from Source

```bash
cargo build --release
```

TLS backend build profiles:
- Default build uses `native-tls`.
- Rustls build profile:

```bash
cargo build --release --no-default-features --features tls-rustls
```

### Run Tests

```bash
cargo test
```

### Code Quality

```bash
cargo fmt --check
cargo clippy
cargo audit
```

---

## License

This project is licensed under [CC-BY-NC-SA-4.0](LICENSE).
