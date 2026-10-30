# Invariant & Constraint Governance

This document codifies the definition, categorization, and lifecycle of invariants in Sigil. It establishes an uncompromising policy against pseudo-invariant tag proliferation, ensuring that invariants remain high-value architectural anchors rather than ceremonial comments.

---

## 1. Core Principle: Mechanisms Over Exhortations

In software engineering, an invariant is a condition that must unconditionally hold across all valid states of a system. Historically, projects suffer from "invariant inflation" when mundane UI styles, layout heuristics, or ephemeral flags are labeled as invariants without verification mechanics.

**The Golden Rule**:
> **If a rule has neither a compiler-level proof nor an automated test assertion, it is NOT an invariant — it is merely an aspiration.**

---

## 2. Constraint Admissibility Matrix

Every architectural and operational rule maps deterministically into one of four categories:

| Category | Definition & Scope | Identifier Policy | Mandatory Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| **System Invariant** | Non-negotiable structural and security red-lines with cross-boundary blast radius (subsystem isolation, cryptographic bounds, memory zeroization). Max ~20 total repository-wide. | Formally ratified in ADRs (`[INV-SEC-*]`, `[INV-ARCH-*]`) | 1. Package dependency firewalls<br>2. Dedicated regression test suite (`test_inv_*` or integration tests)<br>3. Compiler typestates & `Zeroize` drop |
| **Domain Contract** | State-machine transitions and behavioral rules within a single module or subsystem (e.g. `LockState`, envelope slot states). | **NO global `INV-` tag**.<br>Expressed as named types. | 1. Typed `enum` variants & private field encapsulation<br>2. RAII Guard patterns<br>3. Unit tests |
| **Design Specification** | UI layout, dialog geometries, prompt margins, CSS styles. | **NO `INV-` tag**.<br>Expressed as design constants. | 1. UI constants and theme tokens<br>2. Snapshot or visual tests |
| **Implementation Note** | Transient workarounds, compiler bug workarounds, localized edge-case guards. | **NO `INV-` tag**.<br>Standard code comments. | Direct regression unit test |

---

## 3. The 3-Condition Gate for System Invariants

A rule may be elevated to a **System Invariant** if and only if it satisfies all three criteria:

1. **High Blast Radius**: Violation results in secret leakage, process memory compromise, vault corruption, or security bypass.
2. **Durable Architecture**: It represents a foundational security or architectural pillar that will not become obsolete due to routine feature iterations.
3. **Mechanically Enforced**: It specifies an automated enforcement mechanism (compiler type check, dependency rule, kernel isolation flag, or deterministic automated test).

---

## 4. Canonical System Invariants Registry

The following authoritative system invariants are binding across the repository:

- `[INV-SEC-MEMDUMP]`: Process dumpability must be explicitly disabled (`PR_SET_DUMPABLE=0`) and core dump size limited to 0 ([ADR-0001](../../adr/0001-zero-compromise-memory-first-security-architecture.md)).
- `[INV-SEC-ZEROIZE]`: All structs containing raw master keys, derived sub-keys, or decrypted secret buffers must implement `zeroize::Zeroize` and execute zeroize on drop ([ADR-0001](../../adr/0001-zero-compromise-memory-first-security-architecture.md), [ADR-0003](../../adr/0003-clean-break-secret-derivation-and-memory-zeroization.md)).
- `[INV-SEC-PEERCRED]`: All native IPC socket connections must verify caller UID using `SO_PEERCRED` before processing requests ([ADR-0001](../../adr/0001-zero-compromise-memory-first-security-architecture.md), [ADR-0004](../../adr/0004-dual-sovereign-architecture-and-zero-compromise-hardening.md)).
- `[INV-ARCH-DUALSOV]`: Portal secret derivation must remain purely mathematical HKDF derivation isolated from the host collection keyring ([ADR-0004](../../adr/0004-dual-sovereign-architecture-and-zero-compromise-hardening.md)).
- `[INV-ARCH-ENVELOPE]`: The volume key must be stored in independent envelope key slots; password rotation must be an $O(1)$ operation without re-encrypting vault items ([ADR-0002](../../adr/0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md)).

---

## 5. Degazetting & Retirement Policy

1. **Pseudo-Invariants**:
   - Ad-hoc or localized tags outside the canonical registry are prohibited.
   - Code comments should use standard Rust doc-comments or domain types rather than inventing pseudo-invariants.
2. **True Invariants**:
   - When a system invariant evolves or is superseded, it follows the **In-Place Lifecycle**:
     - `Active`: Bound and verified in current releases.
     - `Superseded`: Formally superseded by a successor invariant via an ADR (`superseded_by: ADR-NNNN`), retaining documented failure modes.
     - `Deprecated`: Retired due to subsystem removal, with historical context preserved in the ADR registry.
