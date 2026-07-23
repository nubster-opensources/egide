# 0001 - Relicense from BSL-1.1 to MIT OR Apache-2.0

- Status: Accepted (2026-06-11, PR #12)

## Context

Egide was first published under the Business Source License 1.1 (BSL-1.1). BSL is
a source available license, not an open source one: it restricts production use
and carries a time delayed conversion clause to an open license.

Egide is part of an open source ecosystem whose goal is adoption without lock-in.
The prevailing convention across the Rust ecosystem and crates.io is a permissive
dual license, MIT OR Apache-2.0, chosen by the consumer at their option. The MIT
term is short and widely understood; the Apache-2.0 term adds an explicit patent
grant. A source available license is incompatible with that positioning: it deters
adoption, blocks redistribution, and forces every consumer to track a conversion
date.

## Decision

Relicense the entire repository to `MIT OR Apache-2.0`, effective from the change
onward. Concretely:

- Remove the `LICENSE` (BSL-1.1) file; add `LICENSE-MIT` and `LICENSE-APACHE`.
- Set `license = "MIT OR Apache-2.0"` in the workspace manifest.
- Re-enable the license allowlist check in `deny.toml` so a non-conforming
  dependency license fails CI.

## Consequences

- Consumers may use, redistribute, and build on Egide under either license, with
  no production use restriction and no conversion date to track. This aligns Egide
  with the rest of the ecosystem and with crates.io publication.
- A relicense is irreversible for any version already published: code released
  under a license stays available under it. This relicense (2026-06-11) predates
  the first and only tagged release, v0.1.0 (2026-07-10), whose manifest already
  declares `MIT OR Apache-2.0`. No tagged or published version of Egide carries
  BSL-1.1, so there is no BSL-licensed release in circulation to fork from.
- Contributions from this point are accepted under the dual license. Contributors
  grant the Apache-2.0 patent license by contributing.
- CI now enforces license conformance on the dependency tree, catching a
  disallowed transitive license at build time rather than at release time.
