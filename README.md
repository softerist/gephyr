# Gephyr

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue?logo=docker)](https://www.docker.com/)

Gephyr is a headless local AI relay/proxy server. It gives you one local API endpoint and supports three client styles:
- OpenAI-compatible
- Claude-compatible
- Google AI (Gemini)-compatible

## What This Server Is For

Use Gephyr when you want local, API-key-protected access to Google-backed model traffic through familiar API formats.

## What It Does

- Exposes OpenAI-compatible, Claude-compatible, and Gemini-compatible routes
- Handles API-key auth and request routing
- Supports linked Google accounts and account rotation
- Runs as a local headless service (Docker-first workflow)

## Requirements

- Docker Desktop (or Docker Engine)
- PowerShell (Windows) or Bash (Linux/macOS)
- A Google OAuth client (`GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`)
- An API key for Gephyr (`API_KEY`)

## Install

```bash
git clone https://github.com/softerist/gephyr.git
cd gephyr
cp .env.example .env.local
```

Set at least these values in `.env.local`:

```env
API_KEY=gph_your_secure_api_key
GOOGLE_OAUTH_CLIENT_ID=your_client_id.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-your_secret
```

## Run

```powershell
# Build image
docker build -t gephyr:latest -f docker/Dockerfile .

# Start service
.\console.ps1 start

# Link at least one Google account (opens browser)
.\console.ps1 login
```

Quick health check:

```powershell
curl.exe -sS http://127.0.0.1:8045/health
```

## API Examples (One Per Provider)

Set values:

```powershell
$API_KEY = "YOUR_API_KEY"
$BASE = "http://127.0.0.1:8045"
```

OpenAI-compatible:

```powershell
curl.exe -sS "$BASE/v1/chat/completions" `
  -H "Authorization: Bearer $API_KEY" `
  -H "Content-Type: application/json" `
  -d '{"model":"gpt-5.3-codex","messages":[{"role":"user","content":"Hello from OpenAI-style request."}]}'
```

Claude-compatible:

```powershell
curl.exe -sS "$BASE/v1/messages" `
  -H "Authorization: Bearer $API_KEY" `
  -H "Content-Type: application/json" `
  -d '{"model":"claude-sonnet-4-5","max_tokens":128,"messages":[{"role":"user","content":"Hello from Claude-style request."}]}'
```

Gemini-compatible:

```powershell
curl.exe -sS "$BASE/v1beta/models/gemini-2.5-flash:generateContent" `
  -H "Authorization: Bearer $API_KEY" `
  -H "Content-Type: application/json" `
  -d '{"contents":[{"role":"user","parts":[{"text":"Hello from Gemini-style request."}]}]}'
```

## Advanced Guides

For configuration, full endpoint reference, admin API details, runtime tuning, compliance, proxy pool, and troubleshooting:

- Full advanced guide: `docs/ADVANCED_GUIDE.md`
- OAuth setup details: `OAUTH_SETUP.md`
- Architecture notes: `docs/ARCHITECTURE.md`
- Code-derived capability map: `docs/AGENT_CODE_CAPABILITIES.md`

## License

MIT. See `LICENSE`.
