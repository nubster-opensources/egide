# Roadmap

This page summarises the planned features and milestones for egide. The full
detailed roadmap, including acceptance criteria per feature, lives in
[ROADMAP.md](../../ROADMAP.md) at the repository root.

## Milestones at a glance

| Version | Theme | Status |
| --- | --- | --- |
| 0.1.0 | Foundation: crypto core, secrets engine, seal/unseal, REST and gRPC, SQLite and PostgreSQL | released |
| 0.2.0 | Auth and policies: token management, YAML ACLs, AppRole, audit log | planned |
| 0.3.0 | KMS and Transit: named keys, rotation, encryption as a service | planned |
| 0.4.0 | PKI: internal CA, certificate issuance and revocation | planned |
| 1.0.0 | Production-ready: HA, metrics, stable API | planned |

## Design principles

1. **Security first.** Secure by default, with no shortcuts.
2. **Simplicity.** Easy to understand, easy to operate.
3. **No lock-in.** Plain REST and gRPC, hierarchical paths, YAML policies.
4. **Memory safety.** Rust with zeroization for all sensitive data.
5. **Observability.** Logs, metrics, and traces built in.

## Future considerations

Items not yet scheduled, to be evaluated based on community feedback:

- Dynamic secrets (database credential rotation)
- Cloud KMS integration as a backend seal provider
- LDAP and OIDC authentication methods
- Multi-tenant namespaces
- HSM support
- Web administration UI
