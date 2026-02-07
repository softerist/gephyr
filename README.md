# Gephyr

Gephyr is a headless local AI relay/proxy service for Google AI services.

## Scope

This repository is cleaned for headless operation only:
- No frontend UI source
- No desktop runtime path
- No release packaging assets for desktop UI

## Run (Docker)

```bash
docker build -t gephyr:latest -f docker/Dockerfile .
docker run --rm -p 127.0.0.1:8045:8045 \
  -e API_KEY=replace-with-strong-api-key \
  -e WEB_PASSWORD=replace-with-strong-admin-password \
  -e AUTH_MODE=strict \
  -e ALLOW_LAN_ACCESS=false \
  -v ~/.gephyr:/home/gephyr/.gephyr \
  gephyr:latest
```

## Configuration

- `API_KEY`: required API auth token.
- `WEB_PASSWORD`: optional admin password (used only if admin API is enabled).
- `AUTH_MODE`: recommended `strict`.
- `ALLOW_LAN_ACCESS`: keep `false` unless explicitly needed.
- `ABV_ENABLE_ADMIN_API`: defaults to `false`; set to `true` to expose `/api/*` admin routes.

## Data Directory

Default data path is:
- Linux/macOS: `~/.gephyr`
- Windows: `%USERPROFILE%\\.gephyr`

Override with:
- `ABV_DATA_DIR`
