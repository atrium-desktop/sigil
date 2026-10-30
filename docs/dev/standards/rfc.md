# Request for Comments (RFC) Standards

This document defines the process for authoring, reviewing, and ratifying Request for Comments (RFC) proposals in Sigil.

---

## 1. When to Author an RFC

While an **ADR** records an accepted architectural decision and its negative knowledge, an **RFC** is an upfront exploratory proposal used during early deliberation when:
- The problem space has multiple competing technical or cryptographic solutions with divergent trade-offs.
- The proposed change affects multiple workspace crates or security-critical subsystem boundaries.
- Cross-component coordination (e.g. between `sigil-pam`, `sigil-core`, and `xdg-desktop-portal-atrium`) is required before implementation begins.

---

## 2. RFC Lifecycle

```text
  [ Proposed ] ──► [ Under Review ] ──► [ Approved ] ──► [ Migrated to ADR ]
                          │
                          └──► [ Closed / Withdrawn ]
```

1. **Proposed**: Draft RFC submitted for peer feedback.
2. **Under Review**: Active review period with architectural deliberation.
3. **Approved**: Consensus achieved; implementation may proceed.
4. **Migrated to ADR**: Once implementation lands and the decision is ratified in code, the RFC's conclusions are synthesized into a formal Architectural Decision Record in `docs/adr/`.
5. **Closed / Withdrawn**: Proposal rejected or superseded prior to implementation.

---

## 3. RFC Structure

An effective RFC must address:

1. **Motivation & Problem Statement**: What security, architectural, or desktop integration issue requires this change?
2. **Detailed Design**: Proposed interfaces, cryptographic mechanisms, data models, and concurrency semantics.
3. **Security Analysis & Threat Model**: How does the design impact memory safety, dumpability, privilege boundaries, or key residency?
4. **Migration & Backward Compatibility**: How do existing on-disk vaults, key slots, or client integrations transition smoothly?
5. **Unresolved Questions**: Known unknowns explicitly listed for reviewer deliberation.
