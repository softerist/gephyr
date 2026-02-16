# Google Strict Mimic Validation

This runbook validates strict Antigravity parity for Google auth/onboarding behavior in `codeassist_compat` mode.

## Required Runtime Settings

1. `proxy.google.mode=codeassist_compat`
2. `proxy.google.mimic.profile=strict_mimic`
3. `proxy.google.mimic.trigger_on_auth_events=true`
4. `proxy.google.userinfo_endpoint=oauth2_v2` (or `dual_fallback` if intentionally configured)
5. `proxy.debug_logging.log_google_outbound_headers=true`
6. Process started with `RUST_LOG=debug`

## Antigravity Default Agent Window Endpoint Set

Observed baseline endpoint family (2026-02-15):

1. `https://cloudcode-pa.googleapis.com/v1internal/cascadeNuxes`
2. `https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels`
3. `https://cloudcode-pa.googleapis.com/v1internal:fetchUserInfo`
4. `https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist`
5. `https://cloudcode-pa.googleapis.com/v1internal:onboardUser`
6. `https://oauth2.googleapis.com/token`
7. `https://www.googleapis.com/oauth2/v2/userinfo`

Notes:

1. `daily-cloudcode-pa.googleapis.com` and `cloudcode-pa.googleapis.com` are normalized as equivalent.
2. `content-length` and `connection` are transport-derived and ignored in parity diff.
3. Proxy self-test noise (for example `tokeninfo`) must be excluded from known-good parity scope.
4. Generation endpoint observed in baseline may vary (`streamGenerateContent`, `generateContent`, or `completeCode`) depending exercised UI path.

## Validation Flow

### 1) Run strict parity in Antigravity scope

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/live-google-parity-verify-antigravity.ps1 `
  -ConfigPath "$env:USERPROFILE\.gephyr\config.json" `
  -KnownGoodPath output/known_good.jsonl `
  -OutGephyrPath output/gephyr_google_outbound_headers.jsonl `
  -RequireOAuthRelink
```

### 2) Validate endpoint allowlist explicitly

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-antigravity-allowed-google-endpoints.ps1 `
  -TracePath output/gephyr_google_outbound_headers.jsonl `
  -AllowlistPath scripts/allowlists/antigravity_google_endpoints_default_chat.txt
```

### 3) Validate generation mapping guardrail

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-google-generation-mapping.ps1
```

## Pass Criteria

1. Scoped diff report classifies exercised endpoints as `matched_or_extra_only`.
2. No unexpected Google endpoints outside `scripts/allowlists/antigravity_google_endpoints_default_chat.txt`.
3. Runtime outbound policy reports strict mimic settings in effect.
4. No 401/403/429 or `invalid_grant` spikes in run-window logs.
5. End-user chat behavior remains functional (with strict mimic fail-open only where intended).

Scoped diff interpretation:

1. `extra_endpoint_in_gephyr` on `streamGenerateContent` is acceptable when known-good did not include a stream endpoint in that capture window.
2. Treat this as informational unless stream-specific header parity is explicitly required.
