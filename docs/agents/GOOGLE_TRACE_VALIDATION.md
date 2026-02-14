# Google Trace Validation Runbook

Use this runbook to validate Gephyr's Google-bound request shape against known-good client traces in staging.

## Goal

1. Confirm effective runtime policy is what you intended.
2. Capture outbound header sets from Gephyr (redacted).
3. Diff Gephyr captures against known-good traces.
4. Turn debug capture back off after validation.

## Prerequisites

1. Admin API enabled (`ENABLE_ADMIN_API=true`).
2. Staging environment (not production).
3. A known-good trace set (from your baseline client/environment).

## Step 1: Verify effective runtime policy

```bash
curl -s http://127.0.0.1:8045/api/proxy/google/outbound-policy \
  -H "Authorization: Bearer YOUR_API_KEY" | jq
```

Validate:

1. `mode` is expected (`public_google` or `codeassist_compat`).
2. `headers.send_host_header_effective` matches intent.
3. `identity_metadata` values are correct.
4. `headers.passthrough_policy` is `deny_by_default`.

## Step 2: Enable outbound header debug capture (staging only)

1. Read current config:

```bash
curl -s http://127.0.0.1:8045/api/config \
  -H "Authorization: Bearer YOUR_API_KEY" > /tmp/gephyr-config.json
```

2. Set:
   - `proxy.debug_logging.log_google_outbound_headers=true`
   - (optional for payload files) `proxy.debug_logging.enabled=true`

3. Save config:

```bash
jq '.config.proxy.debug_logging.log_google_outbound_headers=true' /tmp/gephyr-config.json \
| curl -s -X POST http://127.0.0.1:8045/api/config \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @-
```

Runtime note: `POST /api/config` hot-applies Google outbound policy.

## Step 3: Generate representative traffic

Run the same request mix you want to validate:

1. OAuth token refresh path.
2. `loadCodeAssist` path.
3. `fetchAvailableModels` path.
4. Normal upstream generate/stream calls.

## Step 4: Collect Gephyr outbound-header captures

Search logs for the `google_outbound_headers` event:

```bash
rg -n "google_outbound_headers" /path/to/gephyr-logs
```

Each event includes:

1. endpoint
2. mode
3. redacted header map

## Step 5: Diff against known-good traces

Compare, per endpoint:

1. Presence/absence of critical headers.
2. Stable values (`user-agent`, metadata fields).
3. Policy behavior (`Host` only in compat mode when enabled).
4. Absence of blocked categories (`sec-*`, `origin`, `referer`, `cookie`, `x-forwarded-*`).

## Step 6: Disable debug capture

Set `proxy.debug_logging.log_google_outbound_headers=false` and save config via `POST /api/config`.

## Troubleshooting

1. Effective policy mismatch:
   - Re-check `GET /api/proxy/google/outbound-policy` immediately after saving config.
2. No capture events:
   - Ensure runtime log level includes debug events.
3. Unexpected headers:
   - Check caller-provided extras and verify they are in the explicit allowlist path only.
