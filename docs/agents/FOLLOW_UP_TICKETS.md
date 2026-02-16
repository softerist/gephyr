# Follow-Up Tickets

This file tracks non-critical deferred work that is intentionally outside the current remediation batch.

## Open Deferred Tickets

### TICKET-001: KDF Algorithm Upgrade (SHA-256 -> PBKDF2/Argon2)

- Priority: Low-Medium
- Status: Partially Completed (migration mechanics delivered on 2026-02-16; algorithm upgrade deferred)
- Area: `src/utils/crypto.rs`, `src/commands/crypto.rs`

Problem:

- Current key derivation uses raw SHA-256 over key source material.
- Stronger KDF options (PBKDF2/Argon2) are not yet used for key derivation.

Delivered:

- startup warning for weak/short `ENCRYPTION_KEY` is implemented
- key-strength requirement documented (`>= 32` high-entropy characters)
- versioned ciphertext writes are implemented (`v2:<base64>`)
- legacy unversioned ciphertext remains decryptable
- one-time migration command exists (`--reencrypt-secrets`) and rewrites persisted secrets

Deferred Scope:

- introduce PBKDF2/Argon2-based key derivation for new writes
- encode/track KDF version metadata to allow multi-KDF decrypt compatibility
- keep existing decrypt compatibility during migration and rollout

Acceptance Criteria:

- Met: weak-key startup warning is emitted with clear remediation guidance
- Met: operator docs state key-strength expectations
- Met: migration trigger and implementation notes are documented (see notes below)
- Met: versioned ciphertext write path and re-encryption command are implemented
- Pending: new writes use a stronger KDF than raw SHA-256

Migration Trigger and Notes:

- trigger: explicit operator command (`--reencrypt-secrets`) after introducing new KDF-versioned writes
- rollout:
- keep legacy decrypt compatibility during transition window
- write new/updated secrets with new KDF version metadata
- run re-encryption utility once per environment with the intended `ENCRYPTION_KEY`
- rollback safety:
- if migration causes issues, keep legacy decrypt path enabled until all critical secrets are rewritten

## Completed Tickets

### TICKET-002: Proxy Pool Capacity Policy Clarification (`max_accounts` vs shared selection)

- Status: Completed (2026-02-16)
- Area: `src/proxy/proxy_pool.rs`

Delivered:

- semantics clarified in docs:
- `bind_account_to_proxy` enforces `max_accounts` for persistent bindings
- `select_proxy_from_pool` shared fallback is request-scoped for unbound accounts
- observability exposed via metrics:
- `proxy_pool.shared_fallback_selections_total`
- `proxy_pool.strict_rejections_total`
- runtime logs now emit explicit shared-fallback and strict-rejection events with cumulative totals

Acceptance Criteria Status:

- Met: docs describe binding-cap vs request-routing semantics.
- Met: metrics and logs expose shared-fallback and strict fail-closed behavior.
- Met: default behavior remains unchanged; strict isolation remains opt-in via `allow_shared_proxy_fallback=false`.
