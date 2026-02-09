# Defect Discovery Report (Code-Derived)

Date: 2026-02-09  
Scope: `src/` code only (static analysis, no markdown docs used as evidence)

## Summary (Open Findings Only)

- Total findings: 2
- Critical: 0
- High: 0
- Medium: 1
- Low: 1

Fixed findings from the earlier pass were removed from the active list after code updates on 2026-02-09.

## Open Findings

### 1) Model-scoped availability blind spot

- Severity: Medium
- Evidence:
- Fallback availability check evaluates account rate-limit with `model=None`: `src/proxy/token/availability.rs:18`, `src/proxy/token/availability.rs:22`
- Impact:
- Model-specific lockouts can be missed in this path, so availability may be overestimated for a specific target model.
- Recommended fix:
- Pass `Some(target_model)` (or equivalent model-specific key) into the rate-limit check path.

### 2) CIDR matcher is IPv4-only

- Severity: Low
- Evidence:
- CIDR matching is based on dotted-quad parse and 32-bit mask logic only: `src/modules/persistence/security_db.rs:508`
- Impact:
- IPv6 CIDR ranges are unsupported; behavior is limited to IPv4 CIDR inputs.
- Recommended fix:
- Add IPv6-aware CIDR parsing/matching (or explicitly reject/validate unsupported CIDRs in API and config paths).

## Notes

- Findings above are static code findings; runtime behavior may vary by configuration and deployment.
