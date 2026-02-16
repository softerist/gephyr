# Follow-Up Tickets

This file tracks non-critical deferred work that is intentionally outside the current remediation batch.

## Open Deferred Tickets

- None.

## Completed Tickets

### TICKET-001: KDF Algorithm Upgrade (SHA-256 -> PBKDF2)

- Status: Completed (2026-02-16)
- Area: `src/utils/crypto.rs`, `src/commands/crypto.rs`

Delivered:

- new encrypted writes now use PBKDF2-derived keys with versioned ciphertext metadata (`v3:<base64>`)
- ciphertext format now encodes KDF version by prefix (v3 current)
- decrypt path remains backward-compatible with existing `v2:` and unversioned legacy payloads
- one-time migration command (`--reencrypt-secrets`) rewrites persisted secrets into current format

Acceptance Criteria Status:

- Met: new writes use stronger KDF than raw SHA-256
- Met: KDF/ciphertext version metadata is encoded for compatibility
- Met: compatibility path preserved for migration/rollback windows

### TICKET-002: Proxy Pool Capacity Policy Clarification (`max_accounts` vs shared selection)

- Status: Completed (2026-02-16)
- Area: `src/proxy/proxy_pool.rs`

Delivered:

- semantics clarified in docs: `bind_account_to_proxy` enforces `max_accounts` for persistent bindings.
- semantics clarified in docs: `select_proxy_from_pool` shared fallback is request-scoped for unbound accounts.
- observability exposed via metrics: `proxy_pool.shared_fallback_selections_total`.
- observability exposed via metrics: `proxy_pool.strict_rejections_total`.
- runtime logs now emit explicit shared-fallback and strict-rejection events with cumulative totals

Acceptance Criteria Status:

- Met: docs describe binding-cap vs request-routing semantics.
- Met: metrics and logs expose shared-fallback and strict fail-closed behavior.
- Met: default behavior remains unchanged; strict isolation remains opt-in via `allow_shared_proxy_fallback=false`.
