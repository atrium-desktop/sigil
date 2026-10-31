---
id: ADR-0008
title: "Terminal Parity, Emergency Recovery Keys, and Diagnostic Governance"
status: accepted
date: 2026-10-31
scope: core/architecture, cli/client, crypto/recovery, diagnostics
superseded_by: null
negative_knowledge: true
---

# 0008. Terminal Parity, Emergency Recovery Keys, and Diagnostic Governance

- Status: Accepted
- Date: 2026-10-31
- Deciders: Sigil Architecture & Security Working Group
- Amends: [ADR-0002](0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md), [ADR-0006](0006-clean-break-concentric-crate-topology-and-tcb-hardening.md), [ADR-0007](0007-production-readiness-and-protocol-completion.md)

---

## Context and Problem Statement

Following the production hardening in ADR-0007, an operational gap analysis for real-world desktop and server administration revealed three key limitations:

1. **Terminal Disconnection from Running Daemon**: While `sigil` operated seamlessly as a user daemon, command-line users (SSH, TTY, headless sessions) had no CLI mechanism to query daemon status, unlock credentials, or lock the vault without launching a conflicting background daemon or running GUI prompters.
2. **Fragility of Single-Slot Password Storage**: If an out-of-band administrative password change or token corruption occurred on Slot 0, users without an active PAM sync faced catastrophic credential lockout without an out-of-band recovery avenue.
3. **Blackbox Deployment Failures**: Downstream package installation issues—such as bus name conflicts with `gnome-keyring`, missing `pam_sigil.so` libraries, or unconfigured `systemd` user sockets—resulted in cryptic `NameTaken` errors without guided remediation.

---

## Decision Drivers

- **Zero-Compromise Terminal Parity**: A headless administrator or terminal user must have full parity with graphical desktop users without compromising memory hygiene.
- **Fail-Safe Disaster Resilience**: The envelope vault must support multi-slot key enrollment (Slot 1 for recovery keys) to eliminate permanent data loss scenarios.
- **Actionable Diagnostic Transparency**: System operators must be able to run automated health checks that pinpoint conflicting daemons, broken permissions, or missing libraries with exact remediation commands.

---

## Decision Outcome

Chosen Solution: **Industrial-Grade Terminal Parity & Diagnostic Suite (Clean Break)**.

### Architectural Invariants Enforced

- `[INV-CLI-02] Native IPC Command Line Parity`: The `sigil` binary functions as both the infrastructure daemon and the IPC client. Commands `sigil status`, `sigil lock`, and `sigil unlock` interact directly with the running user daemon over `/run/user/<uid>/sigil/native.sock`. Terminal password prompts must suppress echo and guarantee volatile memory zeroization on drop.
- `[INV-CRYPTO-03] Slot 1 Recovery Key Enrollment`: Slot 1 is officially allocated for emergency recovery keys. Recovery keys generate 160 bits of CSPRNG entropy encoded in Crockford Base32 (`SIGIL-RKEY-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`) with automatic typo correction (`O->0`, `I/L->1`). Recovery keys can be enrolled via `sigil recovery-key generate` and used to unlock or recover desynchronized vaults.
- `[INV-PROMPT-02] Headless Display Fast-Fail`: If `org.freedesktop.Secret.Prompt` is invoked when neither `WAYLAND_DISPLAY` nor `DISPLAY` is configured in the daemon environment, it must fast-fail immediately, emit `Completed(dismissed=true)`, and log actionable instructions to unlock via `sigil unlock`.
- `[INV-DOCTOR-01] Pre-Flight Diagnostic Health Check`: The `sigil doctor` command must comprehensively audit D-Bus bus name ownership (identifying conflicting keyrings like `gnome-keyring` or `kwallet`), native socket permissions, vault storage manifests, and PAM library presence, emitting structured `[PASS]`, `[WARN]`, and `[FAIL]` statuses with one-line remediation commands.
- `[INV-MIGRATE-01] Universal Credential Ingestion`: The `sigil import-credentials` command supports importing external credentials from JSON and CSV streams directly into any specified collection under exclusive POSIX `flock` protection.

---

## Consequences

- Terminal users and SSH administrators have complete operational autonomy over the credential vault.
- Recovery key enrollment in Slot 1 provides an unassailable insurance policy against user password desynchronization.
- Setup conflicts with GNOME Keyring and KWallet are instantly diagnosed and resolved via `sigil doctor`.
- Zero compiler warnings, 100% test pass rate, and full lockstep versioning at `v1.4.0`.
