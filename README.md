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
GEPHYR_API_KEY=gph_your_secure_api_key
GEPHYR_GOOGLE_OAUTH_CLIENT_ID=your_client_id.apps.googleusercontent.com
GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-your_secret

# Optional: restrict accepted Google Workspace domains for identity verification
ABV_ALLOWED_GOOGLE_DOMAINS=example.com,subsidiary.example.com

# Optional: scheduler jitter window in seconds (defaults shown)
ABV_SCHEDULER_REFRESH_JITTER_MIN_SECONDS=30
ABV_SCHEDULER_REFRESH_JITTER_MAX_SECONDS=120
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
  -H "Authorization: Bearer $GEPHYR_API_KEY" \
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
| `GEPHYR_API_KEY` | ✅ (for scripts) | — | API key used by `console.ps1`; passed to container as `API_KEY` |
| `API_KEY` / `ABV_API_KEY` | ✅ (runtime) | — | Runtime API authentication token |
| `AUTH_MODE` / `ABV_AUTH_MODE` | — | `strict` | Auth mode: `strict`, `off`, `all_except_health`, `auto` |
| `ALLOW_LAN_ACCESS` / `ABV_ALLOW_LAN_ACCESS` | — | `false` | Bind to `0.0.0.0` instead of `127.0.0.1` |
| `ABV_ENABLE_ADMIN_API` | — | `false` | Enable `/api/*` admin routes |
| `GEPHYR_GOOGLE_OAUTH_CLIENT_ID` / `ABV_GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_ID` | — | — | Google OAuth Client ID |
| `GEPHYR_GOOGLE_OAUTH_CLIENT_SECRET` / `ABV_GOOGLE_OAUTH_CLIENT_SECRET` / `GOOGLE_OAUTH_CLIENT_SECRET` | — | — | Google OAuth Client Secret |
| `ABV_ALLOWED_GOOGLE_DOMAINS` | — | — | Optional comma-separated Workspace domain allowlist for identity verification |
| `ABV_DATA_DIR` | — | `~/.gephyr` | Data directory path |
| `ABV_PUBLIC_URL` | — | — | Public URL for OAuth callbacks (hosted deployments) |
| `ABV_MAX_BODY_SIZE` | — | `104857600` | Max request body size in bytes |
| `ABV_SCHEDULER_REFRESH_JITTER_MIN_SECONDS` | — | `30` | Min random delay before each scheduled quota-refresh batch |
| `ABV_SCHEDULER_REFRESH_JITTER_MAX_SECONDS` | — | `120` | Max random delay before each scheduled quota-refresh batch |

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
- `GET /api/proxy/metrics` returns runtime/monitor/sticky/compliance aggregates and supported runtime-apply policy values.
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
- **Hosted deployment**: Use "Web application" client with `ABV_PUBLIC_URL` set

---

## Data Directory

| Platform | Default Path |
|----------|--------------|
| Linux/macOS | `~/.gephyr` |
| Windows | `%USERPROFILE%\.gephyr` |

Override with `ABV_DATA_DIR` environment variable.

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
