# Google Parity Harness (Windows-first)

This runbook covers the parity harness used to align Gephyr outbound Google traffic with official binaries (`Antigravity.exe` and `language_server_windows_x64.exe`).

## Scope

- Capture Gephyr outbound fingerprints (opt-in only).
- Ingest official capture bundles (JSONL/HAR/SAZ).
- Canonicalize volatile fields.
- Diff with strict gate policy (`any_difference_fails`).
- Maintain repo-safe redacted baselines and manifests.

## Runtime Admin API

All routes are under `/api/proxy/parity` and require admin auth.

- `POST /capture/start`
- `POST /capture/stop`
- `GET /capture/status`
- `POST /capture/export`
- `POST /diff/run`
- `GET /diff/latest`

## CLI

Binary: `gephyr-parity`

- `capture-gephyr start|stop|status|export`
- `capture-official --guided [--script <ps1>] [--skip-guided-run] [--known-good-path <jsonl>] [--bundle-out-dir <dir>] [--require-sources <csv>] [--max-unknown-ratio <0..1>]`
- `source-audit --input <jsonl> [--out <json>] [--require-sources <csv>] [--max-unknown-ratio <0..1>]`
- `diff --gephyr <path> --known-good <path> [--rules <path>] [--out <path>]`
- `gate --gephyr <path> --known-good <path> [--rules <path>] [--out <path>]`
- `baseline-redact --input <path> --out <path> [--manifest <path>] [--rules <path>]`
- `refresh-baseline --gephyr <path> --official <path> [--baseline-dir <dir>] [--rules <path>] [--gate]`

## Timeline Correlation (MITM + LS Network)

When generation is missing, correlate MITM captures with `language_server_windows_x64` connection polls to determine whether:
- generation never happened,
- generation happened on a non-Google surface, or
- LS activity likely bypassed MITM.

Windows command:

`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/correlate-mitm-ls-timeline.ps1 -MitmPath output/known_good.discovery.jsonl -ConnectionsCsvPath output/ls_generation_probe.language_server_windows_x64.connections.csv -OutBase output/parity/official/live.timeline_correlation`

Outputs:

- `output/parity/official/live.timeline_correlation.json`
- `output/parity/official/live.timeline_correlation.txt`

Version metadata flags (for manifest quality):

- `--gephyr-version <ver>`
- `--gephyr-exe-path <path>`
- `--antigravity-version <ver>`
- `--antigravity-exe-path <path>`
- `--language-server-version <ver>`
- `--language-server-exe-path <path>`
- `--capture-date YYYY-MM-DD`

If explicit `--*-version` is not provided and `--*-exe-path` is provided, `gephyr-parity` attempts to read `FileVersion` from the Windows executable and writes it into manifest metadata.

## Guided Capture Refresh Workflow

1. Start Gephyr parity capture:
   - `gephyr-parity capture-gephyr start --api-base http://127.0.0.1:8045 --api-key <admin_api_key>`
2. Exercise Gephyr flows (OAuth, userinfo, loadCodeAssist, fetchAvailableModels, mimic flow, generation-adjacent paths).
3. Export Gephyr artifacts:
   - `gephyr-parity capture-gephyr export --raw-path output/parity/raw/gephyr.raw.jsonl --redacted-path output/parity/redacted/gephyr.redacted.jsonl`
4. Stop Gephyr capture:
   - `gephyr-parity capture-gephyr stop`
5. Run official guided capture:
   - `gephyr-parity capture-official --guided --known-good-path output/known_good.jsonl --bundle-out-dir output/parity/official --antigravity-exe-path "<path_to_Antigravity.exe>" --language-server-exe-path "<path_to_language_server_windows_x64.exe>"`
   - By default this reuses existing capture scripts in `scripts/`.
   - This emits source-tagged bundle outputs:
     - `output/parity/official/raw/official.tagged.<source>.jsonl`
     - `output/parity/official/redacted/official.tagged.<source>.jsonl`
     - Per-file manifests in `output/parity/official/redacted/*.manifest.json`
   - Source audit report is emitted at `output/parity/official/source_audit.json`.
   - Default source gate expects both sources:
     - `antigravity_exe`
     - `language_server_windows_x64`
   - To relax or bypass for a partial run:
     - `--require-sources antigravity_exe`
     - `--no-audit-gate`
6. Redact/normalize official bundle for baseline usage:
   - `gephyr-parity baseline-redact --input <official_capture.jsonl> --out output/parity/redacted/known_good.redacted.jsonl --manifest output/parity/redacted/known_good.redacted.manifest.json --source antigravity_exe --platform windows`
7. Run strict gate before proposing baseline update:
   - `gephyr-parity gate --gephyr output/parity/redacted/gephyr.redacted.jsonl --known-good output/parity/redacted/known_good.redacted.jsonl --out output/parity/redacted/gate.report.json`

## One-Command Baseline Refresh

Use `refresh-baseline` to regenerate repo baseline files and manifests from gephyr+official captures:

`gephyr-parity refresh-baseline --gephyr output/parity/redacted/gephyr.redacted.jsonl --official output/parity/official/redacted/official.tagged.combined.jsonl --baseline-dir parity/baselines/redacted/windows/default --gate --gephyr-version 1.16.16 --antigravity-exe-path "<path_to_Antigravity.exe>" --language-server-exe-path "<path_to_language_server_windows_x64.exe>"`

Outputs include:

- `gephyr.reference.jsonl` + manifest
- `known_good.default.jsonl` + manifest
- `known_good.<source>.jsonl` + manifest (for each inferred official source)
- Gate reports under `parity/baselines/redacted/windows/default/reports/` when `--gate` is set.

Windows helper wrapper (runs source-audit + refresh-baseline):

`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/parity-refresh-baseline.ps1 -GephyrPath <gephyr_jsonl> -OfficialPath <official_jsonl> -AntigravityExePath <path_to_Antigravity.exe> -LanguageServerExePath <path_to_language_server_windows_x64.exe> -Gate`

## Baseline Update Procedure

1. Only commit redacted artifacts under `parity/baselines/redacted/**`.
2. Do not commit raw artifacts (`output/parity/raw/**`, `*.raw.jsonl`, `parity/baselines/raw/**`).
3. Every committed baseline file must have a sibling `.manifest.json` with:
   - `schema_version`
   - `generated_at`
   - `capture_mode`
   - `platform`
   - `input_path`
   - `redacted_baseline_path`
   - `record_count`
   - `checksum_sha256`
   - `ruleset_version`
4. Validate before PR:
   - `bash scripts/validate-parity-baseline-manifests.sh`
   - `bash scripts/check-no-raw-parity-artifacts.sh`

## Approval Flow for Baseline Changes

1. Attach diff report JSON from `gephyr-parity gate` in PR artifacts.
2. Explain changed endpoints/headers/body shape/timing/status.
3. Confirm change reason is intentional protocol drift or official client drift.
4. Require reviewer approval for baseline and manifest updates together.

## CI Enforcement

Workflow: `.github/workflows/parity-gate.yml`

CI does all of the following:

- validates baseline manifests/checksums,
- blocks raw artifact commits,
- runs parity-focused test slices,
- runs a passing gate scenario on committed baselines,
- runs an intentional mismatch scenario that must fail.
