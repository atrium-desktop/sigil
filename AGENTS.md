# Agent Directives

## 1. Operational Guardrails (Hard Constraints)
- **Prohibited Git Commands**: NEVER execute `git stash`, `git branch`, or `git reset`.
- **Command Termination**: All commands MUST be finite and self-terminating. Never start background daemons or unbounded loops without a strict timeout.

## 2. Core Mental Model & Subsystem Boundaries
- **Concentric Architecture**: Sigil organizes its workspace into five concentric layers (`sigil-types` -> `sigil-crypto` -> `sigil-vault` / `sigil-ipc` -> `sigil-ipc-server` / `sigil-dbus-secrets` / `sigil-client` -> `sigil` / `sigil-prompter` / `sigil-pam`). Dependencies flow strictly inward.
- **Dual-Sovereign Architecture**: Decouples sandboxed portal secret derivation (`org.freedesktop.portal.Secret`) from native host collaboration (`org.freedesktop.secrets`). Portal callers receive clean-break mathematical HKDF derivations and must never access the master volume key or keyring collection items.
- **Memory-First Hardening**: Process dumpability is explicitly disabled (`PR_SET_DUMPABLE = 0`, `RLIMIT_CORE = 0`). Any struct holding secret keys or plaintext buffers MUST implement `zeroize::Zeroize` and trigger zeroization on drop (`#[zeroize(drop)]`).
- **Native IPC vs. D-Bus Isolation**: High-privilege lifecycle operations (unlock, slot rotation, portal master secret derivation) are routed exclusively through `/run/user/<uid>/sigil/native.sock`. The socket enforces kernel-level `SO_PEERCRED` checks on every connection.
- **Envelope Multi-Slot Storage**: The vault payload is encrypted by an independent 256-bit `VolumeKey` wrapped in envelope slots. Password rotation is strictly an $O(1)$ envelope slot update and must never re-encrypt stored items.
- **Session-Bound Eviction**: Keys are wiped in memory immediately upon receiving systemd-logind lock or deactivation signals (`Session.Lock`, `Active=false`).

## 3. Engineering Discipline
- **Mechanisms Over Exhortations**: Rely on Rust compiler typestates, private visibility, RAII guards, `Zeroize` implementations, and automated tests to guarantee invariants. Never rely on natural-language comments alone.
- **Anti-Inflation**: Do not mint pseudo-invariant tags. Adhere to the canonical registry (`[INV-SEC-*]`, `[INV-ARCH-*]`). State transitions belong in named Rust enums.
- **Atomic Verification**: Always verify code changes with `cargo check --workspace` and relevant crate test suites (`cargo test --workspace`) before declaring tasks complete.
- **Clean Epistemic Lineage**: References must resolve to canonical in-repo ADRs (`docs/adr/0001`+). Never reference non-existent external legacy numbers.

## 4. On-Demand Standards Routing
Do not guess repository rules or rely on stale assumptions. Consult authoritative specifications as needed:
- Subsystem Topology & Living Blueprint: `docs/dev/subsystems.md`
- Documentation Standards Suite: `docs/dev/standards/README.md`
  - System Architecture Governance: `docs/dev/standards/architecture.md`
  - Invariant & Constraint Policy: `docs/dev/standards/invariants.md`
  - ADR Authoring & Lifecycle: `docs/dev/standards/adr.md`
  - RFC Standards: `docs/dev/standards/rfc.md`
  - Documentation Taxonomy & Layout: `docs/dev/standards/taxonomy.md`
  - Markdown & Hyperlink Style: `docs/dev/standards/style.md`
  - Engineering Workflow & Gates: `docs/dev/standards/workflow.md`
  - Blameless Incident Postmortems: `docs/dev/standards/postmortems.md`
- Testing Strategy & Execution: `docs/dev/testing.md`
- Acceptance Validation Runbook: `docs/dev/acceptance.md`
- Coding & Sensitive Data Conventions: `docs/dev/conventions.md`
- Companion Optics Worktree: `docs/dev/optics-dev-worktree.md`
