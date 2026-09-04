# Pattern: `docs/dev/acceptance.md`

Intent: demonstrate how an authentic user or stakeholder starts from the normal
entry point and validates that deliverables, core user journeys, and critical
acceptance scenarios meet specification.

---

## Should Include

- **Scope & Prerequisites**: Which user journeys and deliverables are validated; required environment, credentials, or setup.
- **Launch & Entry**: Normal installation, launch commands, and authentic login/entry URLs.
- **Core User Journeys**: Step-by-step human operations executing the happy path and primary workflows from a cold start.
- **Acceptance Scenario Matrix**: Key states, edge cases, error conditions, and their expected outcomes (including quick reproduction or fast-entry instructions where applicable).
- **Verification per Step / Scenario**: Observable results and feedback expected after each action.
- **Pass / Fail Criteria**: Explicit success thresholds and failure conditions.
- **Final Acceptance Checklist**: Itemized checklist for formal acceptance sign-off.

---

## Should Not Include

- Headless unit or internal component test instructions (belongs in `testing.md`).
- Static analysis, linting, or CI pipeline setup details (belongs in `testing.md`).
- Fake UI mocks substituting for actual interactive deliverable behavior.

---

## Recommended Template

```markdown
# Acceptance

This document defines the real, end-to-end acceptance procedure for [Product Name].

It answers: **Can an authentic user launch, configure, and complete core journeys and critical acceptance scenarios through standard product interfaces?**

---

## Scope & Prerequisites

- **Scope**: Core workflows and deliverable acceptance criteria validated in this release.
- **Prerequisites**: Minimum environment, credentials, or accounts required.

---

## Launch & User Entry Point

1. Start the application using standard commands:
   ```bash
   npm start
   ```
2. Navigate to `http://localhost:3000` in a standard browser.

---

## Core User Journeys

### Journey 1: [Primary User Journey]

#### Steps
1. Step 1: [Action taken by user]
2. Step 2: [Action taken by user]

#### Expected Outcome
- Observable state rendered on screen or returned by service.

#### Pass / Fail Criteria
- **Pass**: Expected output appears and meets criteria.
- **Fail**: Error screen or blocked workflow.

---

## Acceptance Scenario Matrix

| Scenario / State | Verification Path / Trigger | Expected Result | Status |
|------------------|-----------------------------|-----------------|--------|
| Normal Execution | Follow Journey 1 steps | Deliverable complete, zero errors | Pass |
| Empty State | Launch with empty workspace / database | Clean onboarding prompt displayed | Pass |
| Invalid Input | Submit form with malformed data | Clear validation error banner | Pass |
| Permission Denied | Log in with read-only credentials | Mutation buttons disabled / 403 banner | Pass |

---

## Final Acceptance Checklist

- [ ] Core journey executes from cold start without manual intervention.
- [ ] Critical acceptance scenarios and edge cases in matrix pass.
- [ ] Observable deliverables meet product requirements.
- [ ] No test-only shortcuts substitute for actual deliverable functionality.
```
