# System Architecture Governance

This document codifies the workspace topology, subsystem boundaries, and non-negotiable architectural red-lines of Sigil.

---

## 1. Concentric Workspace Topology

Sigil organizes its Cargo workspace into five concentric layers ([ADR-0006](../../adr/0006-clean-break-concentric-crate-topology-and-tcb-hardening.md)). Dependencies flow strictly from outer layers inward; backward or circular dependencies across layer boundaries are prohibited:

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

1. **Acyclic Dependency Invariant**: No lower-layer crate (`sigil-types`, `sigil-crypto`, `sigil-vault`, `sigil-ipc`) may ever depend on an upper-layer crate (`sigil`, `sigil-ipc-server`, `sigil-dbus-secrets`, `sigil-prompter`, `sigil-pam`).
2. **Vault Independence**: `sigil-vault` must remain independent of GTK, Wayland, or interactive UI presentation libraries.
3. **Headless Operability**: All core cryptographic and vault operations must execute in purely headless environments.
4. **Zero-Async PAM & Prompter ([INV-ARCH-03])**: `sigil-pam` and `sigil-prompter` must never link or depend on Tokio or asynchronous reactor engines.
5. **D-Bus Session Crypto Isolation ([INV-ARCH-04])**: Legacy D-Bus RFC 2631 Diffie-Hellman and AES-128-CBC session cryptography must remain strictly encapsulated inside `sigil-dbus-secrets`.
6. **Transport Decoupling ([INV-ARCH-05])**: `sigil-vault` and `sigil-crypto` must never depend on network socket runtimes (`tokio::net`) or wire framing (`sigil-ipc`). Listening sockets belong exclusively in Layer 3 adapters (`sigil-ipc-server`).
