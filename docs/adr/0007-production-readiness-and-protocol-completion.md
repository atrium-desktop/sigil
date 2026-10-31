---
id: ADR-0007
title: "Production Readiness Hardening, Protocol Lifecycle Completion, and Defense in Depth"
status: accepted
date: 2026-10-31
scope: core/architecture, core/security, dbus/secrets, store/concurrency
superseded_by: null
negative_knowledge: true
---

# 0007. Production Readiness Hardening, Protocol Lifecycle Completion, and Defense in Depth

- Status: Accepted
- Date: 2026-10-31
- Deciders: Sigil Architecture & Security Working Group
- Amends: [ADR-0002](0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md), [ADR-0004](0004-dual-sovereign-architecture-and-zero-compromise-hardening.md), [ADR-0006](0006-clean-break-concentric-crate-topology-and-tcb-hardening.md)

---

## Context and Problem Statement

Following the concentric crate topology restructuring in ADR-0006, an exhaustive production-readiness audit identified five architectural gaps that prevent Sigil from running safely as the canonical, system-wide Secret Service provider on production desktops:

1. **Incomplete Prompt Lifecycle in `org.freedesktop.Secret.Prompt`**: The D-Bus `Unlock` operation returned empty prompts on lock, and `Prompt.Prompt()` was a no-op stub that failed to spawn the graphical prompter or emit `Completed` signals, breaking all graphical applications (Chrome, VS Code, KeePassXC) requesting secrets while the session is locked.
2. **D-Bus Object Lifecycle & Metadata Anomalies**: Deleting a Collection or Item removed data in memory and disk but left dangling, undeleted D-Bus object paths on the session bus. Calling `set_label` on collections erroneously called `create_collection`, crashing with `AlreadyExists`. Created and modified timestamps were hardcoded to zero.
3. **Cross-Process Race Conditions**: While `SigilService` uses in-process `tokio::sync::RwLock` protection, storage writes lacked inter-process synchronization. Running CLI commands or duplicate instances risked concurrent data file clobbering.
4. **Memory Cleanliness in Transient Buffers**: `LockedKeyBox` and `DhSession` heap/mapped allocations lacked compiler-fenced volatile zeroization guarantees on drop.
5. **Absence of Disaster Recovery**: Users had no native facility to export or import authenticated encrypted backups of their credentials.

---

## Decision Drivers

- **Zero-Friction Desktop Compatibility**: Comply 100% with Freedesktop Secret Service specifications so standard Linux applications work out of the box without manual workarounds.
- **Defense in Depth**: Protect keys not just against passive theft, but against compiler optimization elision, dangling object references, and concurrent file tampering.
- **Clean-Break Best Practice**: Eliminate stub code, fix bugs at the architectural root cause, and introduce no backward compatibility compromises or legacy cruft.

---

## Considered Options

1. **Option 1: Minimal Patches**: Add quick fixes to `set_label` and leave `Prompt` as a stub with manual CLI instructions.
2. **Option 2: Uncompromising Production Readiness (Clean Break)**:
   - Implement complete asynchronous `org.freedesktop.Secret.Prompt` orchestration with dynamic prompter spawning and signal emission.
   - Enforce explicit D-Bus object deregistration on deletion and in-place metadata updates with persistent UNIX timestamps.
   - Introduce cross-process file-locking (`flock`) on `.vault.lock`.
   - Apply volatile zeroization barriers to memory-locked containers and ephemeral DH key material.
   - Provide CLI backup/export commands using authenticated envelope encryption.

---

## Decision Outcome

Chosen Option: **Option 2: Uncompromising Production Readiness (Clean Break)**.

### Architectural Invariants Enforced

- `[INV-PROMPT-01] Complete Prompt Lifecycle`: `org.freedesktop.Secret.Prompt` must asynchronously manage the prompter lifecycle. If a vault is locked when `Unlock` is requested, a unique Prompt object path is registered. Upon `Prompt.Prompt()`, `sigil-prompter` is spawned, completion is awaited via IPC state inspection, the `Completed` signal is emitted with the unlocked objects, and the prompt object is deregistered from the D-Bus ObjectServer.
- `[INV-DBUS-02] Object Server Deregistration`: Whenever a Collection or Item is deleted, its exported path must be explicitly removed from the zbus `ObjectServer`. Collection label updates must modify existing records in-place. Timestamps (`created_at`, `modified_at`) must reflect actual UTC seconds.
- `[INV-STORE-04] Cross-Process Mutual Exclusion`: All mutating operations in `FileVaultStore` (`save`, `seal_slot`, `rotate_password`, `initialize`) must acquire an exclusive POSIX `flock` on `.vault.lock` before touching file descriptors.
- `[INV-MEM-03] Volatile Zeroization Barrier`: Drop implementations for `LockedKeyBox`, ephemeral DH keys, and PAM memory callbacks must invoke volatile memory writes coupled with a `compiler_fence(Ordering::SeqCst)` to eliminate compiler elision risks.
- `[INV-CLI-01] Disaster Recovery`: The `sigil` CLI must provide `export-vault` and `import-vault` commands using Argon2id + XChaCha20-Poly1305 envelope archives for safe offline backup and disaster recovery.

---

## Positive Consequences

- Standard applications (browsers, editors, Git credential managers) seamlessly trigger GUI prompts and successfully retrieve credentials after lock screen events.
- Zero dangling D-Bus object references or ghost collections on the session bus.
- Robust cross-process concurrency guarantees between the daemon and any CLI maintenance utilities.
- Cryptographically verified offline backup and recovery eliminates the risk of unrecoverable data loss.

---

## Negative Consequences & Trade-offs

- Spawning the prompter process requires locating `sigil-prompter` in the system path or matching binary directory.
  - *Mitigation*: Fallback lookup sequence: `SIGIL_PROMPTER` environment variable -> daemon executable directory -> `/usr/bin/sigil-prompter`.

---

## Links

- System Architecture: [System Architecture Governance](../dev/standards/architecture.md)
- Threat Model: [Threat Model](../explanation/threat-model.md)
- ADR Index: [ADR Index](index.md)
