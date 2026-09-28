---
id: ADR-NNNN
title: "[Title of Decision]"
status: draft # [draft | accepted | superseded | rejected | deprecated]
date: YYYY-MM-DD
scope: [core/security | desktop/lifecycle | crypto/derivation | core/architecture | api]
superseded_by: null # e.g., ADR-0042
negative_knowledge: true
---

# NNNN. [Title of Decision]

- Status: Draft | Accepted | Rejected | Deprecated | Superseded by [ADR-NNNN](NNNN-slug.md)
- Date: YYYY-MM-DD
- Deciders: [Names / GitHub handles]
- Consulted: [Names / GitHub handles]
- Informed: [Names / GitHub handles]

---

## Context and Problem Statement

[Describe the context and problem statement in a few sentences. What problem are we solving, and why does it matter now?]

## Decision Drivers

- Driver 1: [e.g., Security boundary isolation, zero-allocation memory constraints]
- Driver 2: [e.g., Backward compatibility with existing desktop ecosystem]

## Considered Options

- Option 1: [Title of option 1]
- Option 2: [Title of option 2]
- Option 3: [Title of option 3]

## Decision Outcome

Chosen option: "[Option 1]", because [detailed justification].

### Invariants & Behavioral Boundaries

List the non-negotiable architectural rules resulting from this decision:
- Invariant 1: Mandatory behavioral constraint for human contributors and AI coding assistants.
- Invariant 2: Permitted or prohibited cross-boundary dependencies.

### Positive Consequences

- [Positive consequence 1]
- [Positive consequence 2]

### Negative Consequences & Trade-offs

- [Negative consequence / trade-off]
- [Mitigation strategy]

## Rejected Alternatives & Negative Knowledge

Detail why alternative options were discarded:

### Option 2 (Rejected)
- Why considered: [e.g., Lower initial implementation cost]
- Why rejected: [e.g., Introduced race window or unbounded memory persistence]
