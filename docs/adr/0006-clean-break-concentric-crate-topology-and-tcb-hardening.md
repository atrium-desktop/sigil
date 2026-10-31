---
id: ADR-0006
title: "Clean-Break Concentric Crate Topology, TCB Hardening, and Deprecated Shim Elimination"
status: accepted
date: 2026-10-31
scope: core/architecture, core/security, crypto/derivation, desktop/lifecycle
superseded_by: null
negative_knowledge: true
---

# 0006. Clean-Break Concentric Crate Topology, TCB Hardening, and Deprecated Shim Elimination

- Status: Accepted
- Date: 2026-10-31
- Deciders: Sigil Architecture & Security Working Group
- Amends: [ADR-0001](0001-zero-compromise-memory-first-security-architecture.md), [ADR-0002](0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md), [ADR-0004](0004-dual-sovereign-architecture-and-zero-compromise-hardening.md)

---

## Context and Problem Statement

Sigil was designed with a multi-layer concentric workspace topology to provide memory-first credential security and dual-sovereign credential routing. However, an uncompromising architectural audit identified structural compromises and legacy burdens in the codebase:

1. **Domain-Transport Inversion**: Foundational types (`SecretBytes`, `LockState`) were defined inside the wire-framing crate (`sigil-ipc`), and re-exported backwards by the core crate. Concurrently, domain identifiers (`Namespace`, `Subject`, `Purpose`) were trapped in the core crate, forcing `sigil-ipc` to degrade request arguments to raw strings.
2. **Cryptographic Smear (Legacy Shim Bleed)**: Deprecated 1024-bit Diffie-Hellman (RFC 2631) and AES-128-CBC PKCS#7 encryption—mandated strictly by the legacy `org.freedesktop.secrets` D-Bus transport specification—were bundled into vault cryptography. This contaminated the core vault crypto audit perimeter with obsolete primitives (`aes`, `cbc`, `num-bigint`, `num-traits`).
3. **TCB Bloat & Asynchronous Contagion**: `sigil-ipc` unconditionally depended on Tokio network runtime features (`tokio/{net, io-util}`). Consequently, `pam_sigil.so` (`sigil-pam`), which runs inside high-privilege host processes (`sshd`, `login`, `sudo`, display managers), pulled Tokio and asynchronous reactor dependencies into its dynamically linked `.so` image. Similarly, `sigil-prompter` pulled in full Tokio dependencies despite running a pure synchronous GUI loop.
4. **Junk Drawer Core & Transport Coupling**: `sigil-core` functioned as an unbounded junk drawer, conflating domain types, cryptographic primitives, disk storage, lifecycle services, and `NativeIpcServer` (the Unix domain socket listener and systemd socket-activation handler).
5. **Legacy v1 Format Shims**: The storage layer still carried deprecated single-file v1 migration code (`vault.enc`, `vault.kdf`, `vault.salt`, `migrate_legacy_v1_vault`) and unencrypted secret fields (`legacy_secret`), contradicting the pure envelope multi-slot persistence architecture.

## Decision Drivers

- **Zero-Compromise TCB Minimization**: High-privilege shared library targets (`pam_sigil.so`) and lightweight UI dialogs (`sigil-prompter`) must have zero async runtime footprint, zero cryptographic dependencies, and minimal assembly surface.
- **Strict Concentric Dependency Flow**: Outer layers must strictly depend on inner layers; inner layers must have zero awareness or imports of outer transports.
- **Auditable Cryptographic Sovereign Boundaries**: Core vault encryption (`XChaCha20-Poly1305`, `Argon2id`, `HKDF-SHA256`, `mlock`ed `LockedKeyBox`) must be fully decoupled from legacy D-Bus session transport workarounds.
- **Abolition of the "Core" Junk Drawer**: Decouple domain types, vault persistence, and server adapters into focused, single-responsibility crates.
- **Clean Break from Legacy Persistence Burden**: Deprecated pre-envelope single-file formats and unencrypted item fields must be completely eliminated.

## Considered Options

- **Option 1: In-Place Patching (Partial Feature Gates)**: Retain 7 crates, add feature flags to `sigil-ipc`, move `server.rs` into `crates/sigil`, but keep `sigil-core` as a junk drawer.
- **Option 2: Uncompromising 5-Layer Concentric Topology**:
  - Introduce `sigil-types` (Layer 0, zero I/O domain types & memory safety containers).
  - Introduce `sigil-crypto` (Layer 1, modern vault crypto and locked memory boxes).
  - Introduce `sigil-vault` (Layer 2, envelope multi-slot vault store and service state machine, zero socket code).
  - Decouple `sigil-ipc-server` (Layer 3, native IPC Unix domain socket adapter).
  - Decouple `sigil-dbus-secrets` (Layer 3, encapsulating legacy DH/AES session cryptography).
  - Feature-gate `sigil-ipc` and `sigil-client` into pure `sync` and `async` tracks.
  - Purge all legacy v1 format shims and `legacy_secret` fields.

## Decision Outcome

Chosen option: **Option 2: Uncompromising 5-Layer Concentric Topology**, making a definitive, clean break from legacy debt.

### Concentric Layer Topology

```text
┌────────────────────────────────────────────────────────────────────────────────┐
│ Layer 4: Executables & System Entrypoints (二进制与系统集成入口层)             │
│   ├── crates/sigil            (守护进程宿主二进制：组装 Runtime、Hardening、   │
│   │                            systemd 信号监听、挂载 IPC 与 D-Bus 适配器)     │
│   ├── crates/sigil-prompter   (Optics GUI 弹窗二进制：纯同步、零 Tokio 依赖)   │
│   └── crates/sigil-pam        (pam_sigil.so：纯同步、零 Crypto、零 Tokio 依赖) │
├────────────────────────────────────────────────────────────────────────────────┤
│ Layer 3: Inbound & Outbound Protocol Adapters (协议适配器与客户端 SDK 层)      │
│   ├── crates/sigil-ipc-server (Native Unix Socket 服务端适配器 + systemd 激活) │
│   ├── crates/sigil-dbus-secrets (org.freedesktop.secrets 适配器 + DH/AES 会话) │
│   └── crates/sigil-client     (Native IPC 客户端 SDK：支持 sync 与 async 特性) │
├────────────────────────────────────────────────────────────────────────────────┤
│ Layer 2: Vault Engine & Wire Framing (核心金库引擎与传输帧协议层 - 互不依赖)   │
│   ├── crates/sigil-vault      (多槽位信封存储 FileStore + 内存态 SigilService) │
│   └── crates/sigil-ipc        (纯 Wire 协议、帧编解码、SO_PEERCRED、路径解析)  │
├────────────────────────────────────────────────────────────────────────────────┤
│ Layer 1: Vault Cryptography (现代金库密码学内核层)                             │
│   └── crates/sigil-crypto     (LockedKeyBox/mlock, XChaCha20, Argon2id, HKDF)  │
├────────────────────────────────────────────────────────────────────────────────┤
│ Layer 0: Foundational Domain & Memory Types (零 I/O 基础领域与安全内存原语层)  │
│   └── crates/sigil-types      (SecretBytes, LockState, Namespace, Subject,     │
│                                Purpose, CredentialMetadata, 标准错误语义)      │
└────────────────────────────────────────────────────────────────────────────────┘
```

### Invariants Established

- `[INV-ARCH-03] Zero Asynchronous Runtime in PAM and Prompter`: `sigil-pam` and `sigil-prompter` must NEVER link or transitively depend on Tokio, Mio, or asynchronous reactor engines.
- `[INV-ARCH-04] D-Bus Session Cryptography Isolation`: Legacy RFC 2631 Diffie-Hellman and AES-128-CBC session crypto must remain strictly encapsulated inside `sigil-dbus-secrets`. They are forbidden from appearing in `sigil-crypto` or `sigil-vault`.
- `[INV-ARCH-05] Vault Engine Socket Independence`: `sigil-vault` must never depend on `sigil-ipc`, `tokio::net`, or host socket activation. Transport listeners belong exclusively in Layer 3 adapters (`sigil-ipc-server`).
- `[INV-STORE-03] Pure Envelope Persistence`: The storage engine strictly persists per-item AEAD encrypted envelopes. Plaintext secret fields (`legacy_secret`) and deprecated v1 single-file migration paths are permanently purged.

## Positive Consequences

- **Minimal Attack Surface in PAM**: The compiled `pam_sigil.so` image is stripped of asynchronous runtimes and cryptographic libraries, preventing symbol collisions and runtime overhead in login managers.
- **Clean Epistemic Flow**: Domain types reside at Layer 0; both IPC wire protocols and vault engines share identical strongly-typed definitions without backward imports.
- **Independent Cryptographic Auditing**: `sigil-crypto` contains only modern, constant-time, authenticated cryptographic primitives.
- **Symmetric Architecture**: Inbound Native IPC (`sigil-ipc-server`) and Inbound D-Bus (`sigil-dbus-secrets`) operate symmetrically as Layer 3 adapters over `sigil-vault`.

## Negative Consequences & Trade-offs

- **Workspace Crate Expansion**: The Cargo workspace grows to 10 crates, requiring disciplined boundary management in `Cargo.toml`.
  - *Mitigation*: Workspace-level dependency inheritance (`workspace = true`) ensures uniform dependency versioning without configuration drift.
- **Breaking Clean-Break on Persistence**: Pre-envelope v1 single-file vaults (`vault.enc`) will no longer auto-migrate on load.
  - *Mitigation*: Envelope multi-slot storage has been standard since v1.2.0 (ADR-0002 / ADR-0004); this cleanly sheds legacy technical debt.

## Rejected Alternatives & Negative Knowledge

### 1. Retaining a Monolithic `sigil-core` Junk Drawer
- **Why considered**: Avoided crate fragmentation.
- **Why rejected**: Conflated domain definitions, crypto, storage, and socket listeners, creating circular/inverted dependencies and expanding the TCB for all callers.

### 2. Monolithic Crate with Compile-Time Feature Flags
- **Why considered**: Keeps the crate count low.
- **Why rejected**: Rust feature flags are additive within a compilation unit. Building tests or downstream tools would silently activate features and contaminate `pam_sigil.so` with unwanted runtime code. Physical crate boundaries provide ironclad compiler-enforced guarantees.

---

## Links

- Architecture Governance: [System Architecture Governance](../dev/standards/architecture.md)
- Living Blueprint: [Subsystem Architecture: Sigil System Blueprint](../dev/subsystems.md)
- ADR Index: [ADR Index](index.md)
