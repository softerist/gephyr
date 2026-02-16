# Follow-Up Tickets

This file tracks non-critical deferred work that is intentionally outside the current remediation batch.

## Open Deferred Tickets

### TICKET-001: KDF Hardening + Migration Plan

- Priority: Low-Medium
- Status: Partially Completed (near-term guardrails done on 2026-02-16; migration deferred)
- Area: `src/utils/crypto.rs`, `src/commands/crypto.rs`

Problem:

- Current key derivation uses raw SHA-256 over key source material.
- Moving to PBKDF2/Argon2 requires a versioned migration path for existing ciphertext records.

Delivered (Near-term):

- startup warning for weak/short `ENCRYPTION_KEY` is implemented
- key-strength requirement documented (`>= 32` high-entropy characters)

Deferred Scope:

- add versioned KDF metadata for new writes
- preserve legacy decrypt compatibility during migration window
- extend re-encryption flow to upgrade legacy records

Acceptance Criteria:

- Met: weak-key startup warning is emitted with clear remediation guidance
- Met: operator docs state key-strength expectations
- Met: migration trigger and implementation notes are documented (see notes below)

Migration Trigger and Notes:

- trigger: explicit operator command (`--reencrypt-secrets`) after introducing KDF-versioned writes
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
