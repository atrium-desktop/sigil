# System Architecture Governance

This document codifies the workspace topology, subsystem boundaries, and non-negotiable architectural red-lines of Sigil.

---

## 1. Concentric Workspace Topology

Sigil organizes its Cargo workspace into four concentric layers. Dependencies flow strictly from outer layers inward; backward or circular dependencies across layer boundaries are prohibited:

```text
┌──────────────────────────────────────────────────────────────────────┐
│  Layer 4: Host Daemons & Integration Adapters                        │
│  - Primary Daemon Binary: `crates/sigil/`                            │
│  - Native GUI Prompter: `crates/sigil-prompter/`                     │
│  - PAM Authentication Module: `crates/sigil-pam/`                    │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 3: Protocol Adapters & Client SDK                             │
│  - Secret Service D-Bus Adapter: `crates/sigil-secret-service/`       │
│  - Native Async Client SDK: `crates/sigil-client/`                   │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 2: Core Engine & Vault Lifecycle                              │
│  - Domain Models, Cryptographic Core, Vault Storage,                 │
│    and Native IPC Server: `crates/sigil-core/`                       │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 1: Wire Protocol & Framing                                    │
│  - Native IPC Wire Protocol, Codecs & Peer Auth: `crates/sigil-ipc/` │
└──────────────────────────────────────────────────────────────────────┘
```

**Physical layout**: All crates reside within `crates/*`. Zero crates reside directly at the workspace root.

---

## 2. Architectural Red-Lines

### 2.1 Dual-Sovereign Isolation
- **Red-Line**: Sandboxed portal secret derivation (`org.freedesktop.portal.Secret`) must remain mathematically isolated from the host-level encrypted keyring store (`org.freedesktop.secrets`).
- **Enforcement**: Portal applications receive clean-break HKDF-derived keys scoped strictly to their application ID (`app_id`). They never gain access to raw master volume keys or host collection items. The derivation is stateless and mathematical ([ADR-0004](../../adr/0004-dual-sovereign-architecture-and-zero-compromise-hardening.md)).

### 2.2 Memory-First Hardening & Zero Plaintext Resident Memory
- **Red-Line**: Plaintext master keys and secret payloads must NEVER be swapped to disk, exposed via core dumps, or retained indefinitely in heap allocations.
- **Enforcement**:
  1. The daemon process explicitly sets `PR_SET_DUMPABLE = 0` and sets `RLIMIT_CORE = 0` during initialization ([ADR-0001](../../adr/0001-zero-compromise-memory-first-security-architecture.md)).
  2. All structures holding raw key material or decrypted secrets must implement `zeroize::Zeroize` and execute zeroization on drop (`#[zeroize(drop)]`).
  3. Decrypted secrets are kept ephemeral: decrypted on demand, streamed to authorized callers, and zeroized immediately.

### 2.3 Socket IPC vs. D-Bus Isolation
- **Red-Line**: Privileged lifecycle operations (vault unlock, key slot rotation, raw portal master derivation) must NEVER be exposed over the public session D-Bus.
- **Enforcement**: High-privilege lifecycle and administrative operations are routed exclusively through the dedicated Unix domain socket (`/run/user/<uid>/sigil/native.sock`). Peer authentication is enforced via kernel-level `SO_PEERCRED` checks verifying caller UID ([ADR-0001](../../adr/0001-zero-compromise-memory-first-security-architecture.md), [ADR-0004](../../adr/0004-dual-sovereign-architecture-and-zero-compromise-hardening.md)).

### 2.4 Envelope Multi-Slot Storage & Non-Destructive Password Rotation
- **Red-Line**: Password changes or unlock credential modifications must NEVER require re-encrypting stored secret items or modifying application secret stability.
- **Enforcement**: The vault payload is encrypted with an independent 256-bit `VolumeKey`. Changing a password or rotating an unlock slot only re-encrypts the envelope key slot, executing in $O(1)$ time with zero risk to existing secrets ([ADR-0002](../../adr/0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md)).

### 2.5 Session-Bound Automatic Eviction
- **Red-Line**: Master key material must NEVER remain resident in memory when the user locks their screen or switches sessions.
- **Enforcement**: The daemon subscribes to `org.freedesktop.login1` signals (`Session.Lock`, `Active=false`). The master key is immediately zeroized upon receipt of lock or deactivation signals, requiring transparent PAM or prompter re-unlock on return.

---

## 3. Crate Addition and Dependency Rules

1. **Acyclic Dependency Invariant**: No lower-layer crate (`sigil-ipc`, `sigil-core`) may ever depend on an upper-layer crate (`sigil`, `sigil-secret-service`, `sigil-prompter`, `sigil-pam`).
2. **Core Independence**: `sigil-core` must remain independent of GTK, Wayland, or interactive UI presentation libraries.
3. **Headless Operability**: All core cryptographic and vault operations must execute in purely headless environments.
