# Architecture Decision Records

This directory records the significant, durable decisions behind Egide: the ones
that shape the architecture, the security posture, or the project's contract with
its users, and that would be expensive or confusing to revisit without context.

An ADR captures a single decision. It is short on purpose. If a decision needs
pages of justification it usually needs a design document instead, linked from
the ADR.

## Conventions

- One file per decision, named `NNNN-short-kebab-title.md` with a zero padded
  sequential number (`0001`, `0002`, ...).
- Each ADR states a **Status**, the **Context** that forced the decision, the
  **Decision** itself, and its **Consequences** (good and bad).
- Statuses: `Proposed`, `Accepted`, `Superseded by NNNN`. An `Accepted` ADR is
  immutable. To change a decision, write a new ADR that supersedes it rather than
  editing the old one, so the reasoning trail stays intact.

## Index

- [0001 - Relicense from BSL-1.1 to MIT OR Apache-2.0](0001-relicense-from-bsl-to-mit-or-apache-2.0.md)
