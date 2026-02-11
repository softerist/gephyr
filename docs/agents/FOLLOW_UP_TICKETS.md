# Follow-Up Tickets (Deferred)

This file tracks deferred engineering work that is intentionally not included in the current remediation batch.

## TICKET-001: KDF Hardening + Migration Plan

- Priority: Low-Medium
- Status: Deferred (threat-model dependent; not urgent)
- Area: `src/utils/crypto.rs`, account/config re-encryption flow in `src/commands/crypto.rs`

Problem:

- Current key derivation uses raw SHA-256 over key source material.
- Upgrading to PBKDF2/Argon2 is a breaking data-format change unless a migration strategy is introduced.
- For current threat model (server-side operator key via `ABV_ENCRYPTION_KEY`), migration complexity is higher than immediate security gain.

Scope:

- Near-term guardrails (do now):
- document that `ABV_ENCRYPTION_KEY` must be high entropy (recommend >= 32 random chars)
- add startup warning for weak/short key material
- keep current versioned ciphertext compatibility behavior unchanged
- Long-term migration (deferred):
- introduce versioned KDF metadata for new ciphertext writes
- keep legacy decrypt compatibility during migration window
- extend `--reencrypt-secrets` flow to re-write legacy records into hardened KDF format

Acceptance Criteria:

- Near-term:
- weak-key startup warning is emitted with clear remediation text
- key-strength requirement is documented in operator-facing docs
- Deferred migration readiness:
- threat-model trigger for migration is defined (e.g., remote/shared DB backup exposure risk)
- migration design notes remain tracked and implementation-ready

## TICKET-002: Proxy Pool Capacity Policy Clarification (`max_accounts` vs Shared Selection)

- Priority: Medium
- Status: Planned (semantics + observability)
- Area: `src/proxy/proxy_pool.rs`

Problem:

- Runtime allows shared proxy selection for unbound accounts when all healthy proxies are already bound.
- This is availability behavior, not a binding-cap violation; `max_accounts` is enforced on explicit binding path.

Scope:

- Clarify and document semantics:
- `bind_account_to_proxy` enforces `max_accounts` for persistent bindings
- `select_proxy_from_pool` shared fallback is per-request selection for unbound accounts
- Add observability:
- counter/metric for shared-selection fallback usage
- operator note for interpreting saturation behavior
- Optional future mode (only if requested): strict isolation mode that disables shared fallback

Acceptance Criteria:

- Docs explicitly describe binding-cap vs request-routing semantics.
- Metrics/logging clearly show when shared-selection fallback is used.
- No behavior change required for current default unless strict isolation mode is explicitly introduced.
