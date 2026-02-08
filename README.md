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
    "model": "gpt-4o",
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
| `ABV_DATA_DIR` | — | `~/.gephyr` | Data directory path |
| `ABV_PUBLIC_URL` | — | — | Public URL for OAuth callbacks (hosted deployments) |
| `ABV_MAX_BODY_SIZE` | — | `104857600` | Max request body size in bytes |

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
