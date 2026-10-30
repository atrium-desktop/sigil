# Architectural Decision Records (ADR) Standards

This document establishes the qualification criteria, lifecycle progression, frontmatter schema, and canonical template for Architectural Decision Records (ADRs) in Sigil.

---

## 1. Intent & Qualification (The 3-Question Test)

To prevent ADR inflation and maintain a high-signal registry, author an ADR only if a proposal meets **at least two** of these criteria:

1. **High Reversal Cost**: Would reversing this decision require multi-week refactoring, breaking vault formats, or breaking client IPC protocols?
2. **Cross-Boundary Blast Radius**: Does it alter crate boundaries, cryptographic algorithms, on-disk serialization formats, or security threat models?
3. **Generates Binding Red-Lines**: Does it establish non-negotiable security boundaries or system invariants that developers and AI assistants must follow?

### Anti-Patterns to Reject
- **The Triviality Smear**: Authoring ADRs for routine implementation choices (e.g. internal helper refactoring).
- **The Ephemeral Workaround**: Recording temporary bug fixes or development hacks.
- **The Toothless Declaration**: Vague prose lacking enforceable constraints or clear behavioral boundaries.
- **The Post-Hoc Justification**: Authoring an ADR after code is merged with zero genuine consideration of discarded alternatives.

---

## 2. In-Place Lifecycle & Frontmatter Schema

ADRs evolve strictly in-place through YAML frontmatter transitions. Files are never physically moved to an `archive/` directory:

```text
       [ draft ] ───► [ accepted ] ───► [ superseded ]
           │
           └───► [ rejected ]
```

- **draft**: Proposal under active deliberation.
- **accepted**: Ratified invariant or architectural contract binding on the repository.
- **superseded**: Formally replaced by a subsequent ADR (`superseded_by: ADR-NNNN`).
- **rejected**: Discarded alternative preserved in-place for negative knowledge audit.

### Frontmatter Schema
```yaml
---
id: ADR-NNNN
title: "[Title of Decision]"
status: accepted # [draft | accepted | superseded | rejected]
date: YYYY-MM-DD
scope: [subsystems or modules affected]
superseded_by: null # e.g., ADR-0002 (mandatory when status is superseded)
negative_knowledge: true
---
```

---

## 3. Authoritative ADR Template

```markdown
---
id: ADR-NNNN
title: "[Title of Decision]"
status: draft
date: YYYY-MM-DD
scope: [comma-separated domain/component scopes]
superseded_by: null
negative_knowledge: true
---

# NNNN. [Title of Decision]

- Status: Draft | Accepted | Superseded by ADR-NNNN | Rejected
- Date: YYYY-MM-DD
- Deciders: [Core Engineering, Security Architecture]
- Amends: [Optional links to amended ADRs]

---

## Context and Problem Statement

Describe the context and motivation in concise, precise terms. What architectural bottleneck, security risk, or boundary violation requires resolution?

## Decision Drivers

- Driver 1: [Primary security or technical driver]
- Driver 2: [Operational, desktop lifecycle, or performance requirement]

## Architectural Decisions

Detail the chosen technical approach, module responsibilities, and structural changes.

### Subsystem Boundaries & Structural Changes
Explain the exact changes to workspace members, modules, and contracts.

### Normative Invariants Established (Optional)
If a non-negotiable architectural red-line is created, specify it with its enforcement mechanism:
- `[INV-XXX-01] Name`: Mandatory constraint backed by automated integration test or compiler typestate.

## Consequences

- **Positive**: Expected architectural, security, and operational benefits.
- **Negative & Trade-offs**: Incurred operational complexity and mitigation strategy.

## Rejected Alternatives & Negative Knowledge

### 1. Discarded Approach A
- **Why considered**: ...
- **Why rejected**: ...

---

## Links

- Related Standards: [Architecture Standards](architecture.md)
- ADR Index: [ADR Index](../../adr/index.md)
```

---

## 4. Epistemic Lineage Integrity

All `ADR-NNNN` citations across code comments and Markdown files must resolve strictly to canonical records in `docs/adr/`. Referencing ghost numbers or non-existent external registries is prohibited.
