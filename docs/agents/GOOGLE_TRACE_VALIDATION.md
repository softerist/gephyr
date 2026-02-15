# Google Trace Validation Runbook

Use this runbook to validate Gephyr Google outbound behavior against known-good traces with minimal false drift.

## Goal

1. Validate endpoint and header parity for exercised flows.
2. Use scoped known-good baselines to avoid mixed-client noise.
3. Detect early auth/rate/quota regression signals.

## Recommended Commands

### Interactive launcher (recommended)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/live-google-parity-verify-interactive.ps1
```

Select:

1. `Gephyr scope` for day-to-day parity checks.
2. `Antigravity scope` for strict default Agent Window endpoint allowlist checks.
3. `Raw` only for broad investigation, not pass/fail parity gating.

### Non-interactive Gephyr scope

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/live-google-parity-verify.ps1 `
  -ConfigPath "$env:USERPROFILE\.gephyr\config.json" `
  -Scope Gephyr `
  -KnownGoodSourcePath output/known_good.jsonl `
  -KnownGoodPath output/known_good.gephyr_scope.jsonl `
  -OutGephyrPath output/gephyr_google_outbound_headers.jsonl `
  -StartupTimeoutSeconds 60 `
  -RequireOAuthRelink `
  -NoClaudeProbes
```

### Non-interactive Antigravity scope

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/live-google-parity-verify-antigravity.ps1 `
  -ConfigPath "$env:USERPROFILE\.gephyr\config.json" `
  -KnownGoodPath output/known_good.jsonl `
  -OutGephyrPath output/gephyr_google_outbound_headers.jsonl `
  -RequireOAuthRelink
```

## Scope Guidance

1. `Gephyr` scope: builds a scoped known-good baseline from endpoints actually exercised by Gephyr in the run.
2. `Antigravity` scope: filters known-good by Antigravity endpoint allowlist plus Antigravity user-agent family.
3. `Raw` scope: compares against full known-good file and often reports non-actionable misses.

## Operational Guardrails

1. Run in scoped mode (`Gephyr` or `Antigravity`) for pass/fail confidence.
2. Keep `-NoClaudeProbes` unless Claude `/v1/messages` parity is explicitly in scope.
3. Keep request rate/concurrency conservative and human-like; avoid stress patterns.
4. Re-run parity validation after any Gephyr code/config change touching routing, auth, headers, or token lifecycle.
5. Track early warning patterns continuously: `401`, `403`, `429`, `invalid_grant`, `unauthorized`, `forbidden`, `quota`, `rate`.

## Post-Run Checks

### 1) Confirm diff classification

Check `output/google_trace_diff_report.txt` and confirm scoped runs classify exercised endpoints as `matched_or_extra_only`.

### 2) Scan latest app log for warning/error signals

```powershell
$log = Get-ChildItem "$env:USERPROFILE\.gephyr\logs\app.log*" -File |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1 -ExpandProperty FullName
Select-String -Path $log -Pattern '401|403|429|invalid_grant|unauthorized|forbidden|quota|rate' |
  Select-Object -Last 120
```

### 3) Re-run static route/caller mapping guardrail

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-google-generation-mapping.ps1
```

This enforces:

1. Non-test `call_v1_internal*` callers are only from allowlisted handler files.
2. Expected ingress generation route paths still exist.

## Troubleshooting

1. `Known-good source trace not found`:
   - Generate or restore `output/known_good.jsonl` first.
2. OAuth relink errors:
   - Ensure `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` are set (or present in `.env.local`).
3. Empty outbound capture:
   - Confirm Gephyr is started with debug outbound header logging and run produced request traffic after cutoff.
4. Raw mode reports many missing endpoints:
   - Use `-Scope Gephyr` or `-Scope Antigravity`; raw includes non-exercised baseline traffic.
