# ADR-0003: Clean-Break Secret Derivation and Memory Zeroization Standard

- **Status**: Accepted
- **Date**: 2026-09-08
- **Authors**: Sigil Architecture & Security Team

## Context

[ADR-0001](0001-zero-compromise-memory-first-security-architecture.md) and
[ADR-0002](0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md)
established a memory-first architecture with envelope key-slots and automated
lifecycle management.

However, several architectural inconsistencies and legacy remnants persisted in the
secret derivation and IPC response pathways:

1. **Legacy Compatibility Derivations**:
   The codebase retained an ad-hoc `derive_portal_secret` function hardcoding
   `aegis.portal.Secret/v1\0` without standard purpose separation. This was an interim
   shim for a predecessor project name, creating a diverging code path from the canonical
   HKDF-SHA256 `derive_app_secret` function.
2. **Un-Zeroized IPC Response Vectors**:
   `IpcResponse::Secret(Vec<u8>)` carried derived secret payloads in standard,
   unprotected heap vectors. While `SecretBytes` was implemented for internal domain
   types, serializing out of an un-zeroized `Vec<u8>` meant secret copies remained
   in heap memory after socket dispatch until overwritten.
3. **Cross-Project Divergence**:
   Integration tests in `sigil-client` still used the deprecated `aegis.portal.Secret/v1`
   namespace, while the production portal (`xdg-desktop-portal-atrium`, ADR-0020 / ADR-0022)
   issues requests against `atrium.portal.Secret/v1`.

## Decision

We execute a complete clean-break update across the derivation pipeline and wire IPC:

1. **Canonical HKDF-SHA256 Derivation**:
   - Retire and remove `derive_portal_secret`.
   - All application and portal secrets are derived exclusively through
     `derive_app_secret(master_key, namespace, subject, purpose)` using RFC 5869
     HKDF-SHA256:
     $$\text{Info} = \text{Namespace} \,||\, \text{0x00} \,||\, \text{Subject} \,||\, \text{0x00} \,||\, \text{Purpose}$$
   - The canonical namespace for the desktop secret portal is `atrium.portal.Secret/v1`.
2. **End-to-End `SecretBytes` Zeroization**:
   - `SecretBytes` implements `Serialize` and `Deserialize` alongside `Zeroize` and
     `ZeroizeOnDrop`.
   - `IpcResponse::Secret` now wraps `SecretBytes` directly:
     ```rust
     pub enum IpcResponse {
         Secret(SecretBytes),
         ...
     }
     ```
   - All secret bytes generated during derivation are scrubbed upon completion of
     frame serialization.
3. **Purge of Legacy Namespace Baggage**:
   - All references to `aegis` in tests and domain documentation are replaced with
     the canonical production namespace `atrium.portal.Secret/v1`.

## Alternatives Considered

- **Retain `derive_portal_secret` for historical compatibility**:
  Rejected. No active production client uses the old `aegis` namespace; retaining
  divergent KDF paths adds audit surface and risks namespace confusion.
- **Keep `Vec<u8>` in `IpcResponse::Secret` and zeroize manually**:
  Rejected. Type-system-enforced zeroization via `SecretBytes` ensures compiler-guaranteed
  erasure without risking forgotten manual scrubbing.

## Consequences

### Positive
- **Provable Memory Hygiene**: Zero un-scrubbed secret copies in the server's heap memory
  during IPC serialization.
- **Unified Cryptographic Surface**: A single, strictly domain-separated HKDF derivation
  function across the entire codebase.
- **End-to-End Alignment**: 100% interoperability with `xdg-desktop-portal-atrium` (ADR-0022).

### Negative / Trade-offs
- Legacy external clients requesting `aegis.portal.Secret/v1` will derive via the standard
  three-part info string rather than the two-part legacy format (a deliberate clean break).
