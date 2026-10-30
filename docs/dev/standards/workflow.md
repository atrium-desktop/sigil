# Engineering Workflow & Verification Gates

This document codifies the operational workflows, PR review gates, and verification criteria for changes to Sigil.

---

## 1. Pull Request Review Gates

Before any pull request is merged into `main`, it must clear the following verification gates:

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. Compilation Gate: `cargo check --workspace`              │
│    Zero warnings, zero unresolved symbols, all crates green │
├─────────────────────────────────────────────────────────────┤
│ 2. Automated Test Gate: `cargo test --workspace`            │
│    All unit, integration, and security tests pass           │
├─────────────────────────────────────────────────────────────┤
│ 3. Architecture Gate: Subsystem Boundary Compliance         │
│    No reverse dependencies; strict layer separation         │
├─────────────────────────────────────────────────────────────┤
│ 4. Code-to-Doc Synchronization Gate                         │
│    API/protocol changes matched with documentation updates  │
├─────────────────────────────────────────────────────────────┤
│ 5. Formatting & Lints: `cargo fmt` & `cargo clippy`         │
│    Format verified, `-D warnings` clean across all targets  │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Code-to-Doc Synchronization (Atomic Commits)

Any pull request that introduces or modifies developer-visible or operator-facing surfaces must update the corresponding documentation within the **same atomic pull request**:

| Modified Surface | Required Documentation Synchronization |
| :--- | :--- |
| CLI commands, arguments, or environment variables (`sigil`, `sigil-cli`) | `docs/reference/cli.md` |
| Native IPC wire protocol (`crates/sigil-ipc`) | `docs/reference/native-ipc.md` and relevant ADR |
| On-disk storage format or envelope slots (`crates/sigil-core`) | `docs/reference/storage-format.md` |
| Secret Service or Portal D-Bus interfaces | `docs/explanation/freedesktop-spec.md` |
| Major architectural restructuring or security policy changes | New or amended ADR in `docs/adr/` |

---

## 3. Pre-Release Quality Checklist

Prior to creating a release tag:

1. **Workspace Compilation**: Run `cargo check --workspace` and verify zero errors.
2. **Full Test Suite**: Run `cargo test --workspace` across all crates.
3. **Formatting & Lints**:
   - `cargo fmt --all -- --check` clean.
   - `cargo clippy --workspace --all-targets -- -D warnings` clean.
4. **Security-Sensitive Review**: Changes touching cryptographic primitives (`sigil-core/src/crypto`), memory wiping (`zeroize`), or PAM authentication (`sigil-pam`) require dedicated review against security invariants.
5. **Changelog Integrity**: Ensure user-facing features, security fixes, and breaking changes are documented in `CHANGELOG.md`.
6. **Clean Git State**: Verify no untracked experimental files or temporary debug assets remain in the tree.
7. **Release Artifacts**: Verify that release build succeeds: `cargo build --workspace --release`.
