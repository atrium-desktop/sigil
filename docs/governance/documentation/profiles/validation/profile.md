# Validation Profile

This profile defines the dual-tier product validation model for engineering
repositories: **Outside-In Delivery Acceptance (`acceptance.md`)** and **Inside-Out Implementation Testing (`testing.md`)**.

```text
       +-------------------------------------------------------+
       |                     acceptance.md                     |
       |  Outside-In / Deliverable & Stakeholder View          |
       |  - End-to-end user journeys from normal entry points  |
       |  - Acceptance scenario matrix & edge-case validation  |
       +-------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |                      testing.md                       |
       |  Inside-Out / Engineering & Automation View           |
       |  - Unit, integration, contract, and E2E test suites   |
       |  - Fixtures, linters, types, and CI verification      |
       +-------------------------------------------------------+
```

---

## The Dual-Tier Boundaries

| Document | Validation Target | Core Question | Concise Maxim |
|----------|-------------------|---------------|---------------|
| `docs/dev/acceptance.md` | Deliverables, user journeys & acceptance matrix | Can users and stakeholders achieve goals and pass critical acceptance scenarios? | **Acceptance validates what was delivered and how it satisfies requirements.** |
| `docs/dev/testing.md` | Code & system implementation | Does the codebase function correctly across automated test suites? | **Testing validates why the implementation can be trusted.** |

---

## Core Invariants

### 1. `acceptance.md` — Delivery Acceptance & User Journeys
- **Primary Focus**: Validates deliverables against business and user requirements from an outside-in perspective.
- **Core User Journeys**: End-to-end flows mirroring real user interaction from cold start without test backdoors.
- **Acceptance Scenario Matrix**: Explicit coverage of critical states, edge cases, error conditions, and their expected outcomes (optionally documenting fast-entry fixtures or reproduction commands for manual verification).
- **Scope**: Cold-start prerequisites, normal launch, real user entry point, step-by-step journeys, scenario matrix, observable outputs, explicit pass/fail criteria, and formal acceptance checklist.

### 2. `testing.md` — Implementation Correctness & Automation
- **Primary Focus**: Programmatic, reproducible verification of algorithms, interfaces, modules, and system internals.
- **Scope**: Unit, integration, component, API contract, and automated E2E test suites, linters, type-checkers, test fixtures, local test commands, and CI matrices.
- **Non-Goals**: Manual human onboarding narratives or product sign-off checklists (belong in `acceptance.md`).

---

## Non-Substitution Principle

The two tiers are complementary, not interchangeable:
```text
Implementation Correctness (testing.md)
              +
Delivery Acceptance & Journeys (acceptance.md)
```

- Automated test suites passing (`testing.md`) does not guarantee end-to-end workflow usability or deliverable satisfaction.
- A passing happy path or manual sign-off (`acceptance.md`) does not replace rigorous automated regression protection.

---

## Patterns in this Profile

- [Acceptance Pattern](acceptance.pattern.md)
- [Testing Pattern](testing.pattern.md)
