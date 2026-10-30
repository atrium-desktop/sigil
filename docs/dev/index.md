# Developer Portal

Welcome to the `sigil` developer and contributor documentation. This section forms the **Engineering Surface** behind the contributor firewall, containing developer workflows, testing guides, living blueprints, and engineering standards.

---

## 1. Developer Workflows & Guides

| Guide | Description |
| :--- | :--- |
| **[Developer Setup](setup.md)** | Quick-start dependency installation and environment setup. |
| **[Development Guide](development.md)** | Full build workflows, daemon execution, environment variables, and `secret-tool` debugging. |
| **[Testing Guide](testing.md)** | Automated test pyramid, unit/integration tiers, and cargo test execution. |
| **[Acceptance Testing](acceptance.md)** | End-to-end human and system verification procedures for user journeys and releases. |
| **[Coding Conventions](conventions.md)** | Rust style, cross-layer error handling, concurrency rules, and zeroize-on-drop requirements. |
| **[Optics Worktree Workflow](optics-dev-worktree.md)** | Dual Git worktree workflow when developing alongside companion UI engine Optics. |

---

## 2. System Architecture Blueprint

- **[Subsystem Architecture](subsystems.md)**: The authoritative living blueprint of all seven crates in the workspace (`sigil-core`, `sigil-ipc`, `sigil-client`, `sigil-secret-service`, `sigil`, `sigil-prompter`, `sigil-pam`), domain data flows, and security lifecycles.

---

## 3. Engineering Standards Suite

Authoritative standards live flatly in [`docs/dev/standards/`](standards/README.md):

- **[Standards Overview](standards/README.md)**: Index and governance philosophy.
- **[System Architecture](standards/architecture.md)**: Concentric workspace topology, dual-sovereign boundaries, and memory hardening red-lines.
- **[Invariants & Constraints](standards/invariants.md)**: Constraint admissibility matrix and mechanisms over exhortations.
- **[ADR Standards](standards/adr.md)**: The 3-Question Test, frontmatter schema, and canonical template.
- **[RFC Standards](standards/rfc.md)**: RFC proposal and review lifecycle.
- **[Documentation Taxonomy](standards/taxonomy.md)**: Four-quadrant Diátaxis layout, audience boundaries, and root whitelist.
- **[Documentation Style](standards/style.md)**: Hyperlink hygiene, relative path rules, and markdown conventions.
- **[Engineering Workflow](standards/workflow.md)**: PR review gates, code-to-doc synchronization, and pre-release checklist.
- **[Incident Postmortems](standards/postmortems.md)**: Blameless postmortem structure and systemic defense analysis.

---

## 4. Architectural Decisions & Incidents

- **[Architecture Decision Records (ADRs)](../adr/index.md)**: The immutable decision registry (`ADR-0001` through current).
- **[Postmortems](postmortems/README.md)**: Incident root-cause analyses and systemic defense retrospectives.
