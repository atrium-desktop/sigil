# Documentation Taxonomy & Information Architecture

This document defines the organization, scope boundaries, and classification of all documentation assets in the repository.

---

## 1. The Four-Quadrant System (Diátaxis)

Public documentation in `docs/` follows the Diátaxis information architecture:

```text
               PRACTICAL                   THEORETICAL
          ┌─────────────────────────┬─────────────────────────┐
          │  Tutorials              │  How-To Guides          │
LEARNING  │  (Learning-Oriented)    │  (Task-Oriented)        │
          │  `docs/tutorials/`      │  `docs/how-to/`         │
          ├─────────────────────────┼─────────────────────────┤
          │  Reference              │  Explanation            │
WORKING   │  (Information-Oriented) │  (Understanding-Orient) │
          │  `docs/reference/`      │  `docs/explanation/`    │
          └─────────────────────────┴─────────────────────────┘
```

- **`docs/tutorials/`**: Guided, hands-on lessons taking a new reader through their first successful experience with Sigil. Focuses on learning and building confidence.
- **`docs/how-to/`**: Step-by-step problem-solving recipes for specific administrator or user goals (e.g., configuring PAM unlock, setting up desktop autostart, distro packaging). Focuses on accomplishing a practical task.
- **`docs/reference/`**: Precise technical descriptions of APIs, native IPC wire protocols, on-disk storage formats, and CLI tooling without tutorial narrative. Focuses on precision and completeness.
- **`docs/explanation/`**: Conceptual deep dives, threat models, cryptographic rationale, and freedesktop specification background. Focuses on understanding the system and its security architecture.

---

## 2. Documentation Spaces & Audiences

Documentation is structured into two surfaces separated by a one-way visibility boundary:

```text
┌─────────────────────────────────────────────────────────────┐
│ Public Surface (Users, Desktop Integrators, App Developers) │
│ `docs/tutorials/`, `how-to/`, `reference/`, `explanation/`  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ Scope Boundary: public docs must
                               │ never link into internal dev space.
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Engineering Surface (Contributors, Maintainers, Agents)     │
│ `docs/dev/` (internals, standards, testing runbooks)        │
│ `docs/adr/` (canonical architectural decision records)      │
└─────────────────────────────────────────────────────────────┘
```

1. **User Surface**: Addressed to desktop users, sysadmins, and application developers. Emphasizes workflows, API specifications, and integration guides.
2. **Engineering Surface**: Addressed to contributors, security auditors, and development agents. Emphasizes internal subsystem blueprints, architecture decisions, and development standards.
3. **Audience Firewall**: Public documentation surfaces (`docs/{tutorials,how-to,reference,explanation}/`) must never contain relative links pointing into the internal maintainer space (`docs/dev/**`). Links into `docs/adr/` remain permitted: a public reader may follow a decision record, but not a contributor setup guide.
4. **Reverse Linking Permitted**: Internal documents may freely link outward to public reference and how-to guides.

---

## 3. Repository Root Whitelist

To keep the repository root clean, professional, and clutter-free, only canonical top-level documentation files are permitted at the root:
- `README.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `AGENTS.md`
- `LICENSE`
- `SECURITY.md`

All other documentation must reside within organized directories under `docs/`. External meta-configuration files (e.g. `.docgov.yml`) and nested governance directories are strictly prohibited.
