---
id: ADR-0005
title: "DocGov Decoupling, Flat Standards Suite, and Documentation Topology Modernization"
status: accepted
date: 2026-10-30
scope: architecture/governance, docs/dev, agent/directives
superseded_by: null
negative_knowledge: true
---

# 0005. DocGov Decoupling, Flat Standards Suite, and Documentation Topology Modernization

- Status: Accepted
- Date: 2026-10-30
- Deciders: Sigil Architecture & Security Working Group
- Amends: [ADR-0001](0001-zero-compromise-memory-first-security-architecture.md), [ADR-0002](0002-industrial-grade-zero-friction-desktop-lifecycle-and-envelope-vault.md)

---

## Context and Problem Statement

The repository was previously burdened with external documentation governance bureaucracy:

1. **Invasive Upstream Tooling (`docgov`)**:
   An external meta-framework tool (`docgov`) was introduced alongside a deep mirror directory `docs/governance/documentation/{core,profiles}/`. This imported pseudo-academic taxonomies, rigid linter restrictions, and artificial comment-block boundaries (`<!-- BEGIN/END DOCGOV DIRECTIVES -->`) in `AGENTS.md`.
2. **The "Junk Drawer" Hierarchy**:
   The multi-layered `docs/governance/documentation/core/` and `profiles/` directory structure acted as an over-engineered junk drawer, adding navigation friction while offering zero value to Sigil's core desktop credential infrastructure.
3. **Incomplete Diátaxis Layout**:
   While `docs/how-to/`, `docs/reference/`, and `docs/explanation/` existed, `docs/tutorials/` was absent, leaving new users without a guided, hands-on path to their first successful vault session.
4. **Fragmented Contributor Guidance**:
   Contributor documentation in `docs/dev/` was fragmented across overlapping guides (`setup.md` vs `development.md`) and lacked an authoritative living subsystem blueprint.

---

## Decision Drivers

1. **Decouple and Unvendor Governance Overhead**: Eliminate `.docgov.yml`, `.docgov.lock`, and `docs/governance/`. Return to native, idiomatic Rust toolchains (`cargo check --workspace`, `cargo test --workspace`, `clippy`).
2. **Flatten Documentation Topology**: Maintain clean, direct documentation surfaces in `docs/dev/standards/`, `docs/dev/`, and `docs/adr/`.
3. **Complete Diátaxis Four-Quadrant Layout**: Introduce `docs/tutorials/` for guided onboarding.
4. **Mechanisms Over Exhortations**: Invariants must be enforced by concrete mechanisms: Rust type systems, module visibility, `Zeroize` traits, or automated tests. Natural-language "swearing" in comments is abolished.
5. **Enforce Audience Firewall**: Public documentation surfaces (`tutorials/`, `how-to/`, `reference/`, `explanation/`) must never link into internal developer guides (`docs/dev/**`).

---

## Architectural Decisions

### 1. Complete Decoupling from `docgov` and Unification into `docs/dev/standards/`
- Remove `.docgov.yml` and `.docgov.lock`.
- Completely abolish the external and over-nested `docs/governance/` directory.
- Re-home all engineering, architectural, and quality standards directly into `docs/dev/standards/` as a flat, high-cohesion, native suite.
- Re-architect `docs/dev/` with a living subsystem blueprint (`docs/dev/subsystems.md`), consolidated development guides, and incident postmortem standards.

### 2. Streamlining `AGENTS.md`
- Strip the artificial `<!-- BEGIN DOCGOV DIRECTIVES -->` boundaries.
- Re-architect `AGENTS.md` into direct, actionable engineering guidelines prioritizing workspace boundaries, memory-first hardening, type-driven correctness, and testing discipline.

### 3. Establishing `docs/tutorials/`
- Introduce `docs/tutorials/getting-started.md` and `docs/tutorials/index.md` to complete the Diátaxis four-quadrant information architecture.

### 4. Audience Firewall and Root Whitelist
- Enforce the one-way visibility boundary: public user documentation never links into `docs/dev/**`.
- Restrict repository root markdown files strictly to `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `AGENTS.md`, `LICENSE`, and `SECURITY.md`.

---

## Consequences

### Positive
- **Zero External Governance Drag**: Eliminates dependency on `docgov` and fragile delimiter comments.
- **Flat, Readable Documentation**: No more nested "junk drawer" hierarchies under `docs/governance/`.
- **Complete Diátaxis Layout**: Full four-quadrant coverage (Tutorials, How-To, Reference, Explanation).
- **Self-Contained Epistemic Integrity**: Zero dead links, clean ADR registry, and direct standards routing.

### Negative & Trade-offs
- Verification of documentation changes is now guided by developer discipline and native Rust CI checks rather than an external AST linter.

---

## Rejected Alternatives & Negative Knowledge

### 1. Retaining `docgov` While Pruning Rules
- **Why considered**: Attempting to keep the external binary while disabling rules in `.docgov.yml`.
- **Why rejected**: Perpetuates dependency on an external protocol tool that mandates invasive boundary comments in `AGENTS.md` and generates redundant mirror directories. Native Rust toolchains already provide sufficient verification.

### 2. Renaming `docs/governance/documentation/core` to `docs/governance/core`
- **Why considered**: Reducing directory depth while keeping the governance structure.
- **Why rejected**: Still preserves the "junk drawer" anti-pattern. Architecture decisions belong in `docs/adr/`; developer guidelines belong in `docs/dev/`. A separate "governance" drawer is superfluous.

---

## Links

- Related Standards: [Standards Suite](../dev/standards/README.md), [Taxonomy](../dev/standards/taxonomy.md), [Architecture](../dev/standards/architecture.md)
- Related Agent Directives: [AGENTS.md](../../AGENTS.md)
- ADR Index: [ADR Index](index.md)
