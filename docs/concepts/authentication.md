# Authentication

Egide authenticates every API call with a bearer token: `Authorization: Bearer <token>`. There is no `egide token`, `egide auth`, or `egide policy` CLI subcommand today; token management is done through the CLI's `operator`/`secrets` commands plus the REST API shown below.

## Overview

| Method | Status | Use Case |
|--------|--------|----------|
| **Root token** | Implemented | Administrative operations (init, seal, unseal, transit key management, service token management) |
| **Service tokens** | Implemented | Machine-to-machine authentication for applications |
| **AppRole** | Planned for 0.2.0, not implemented | Machine-to-machine, credential-based login |
| **OIDC** | Planned, not implemented | Human users, SSO integration |
| **mTLS** | Planned, not implemented | Certificate-based, zero-trust |

## Root Token

Generated once during initialization and never shown again:

```bash
egide operator init
# Output includes: Root Token: <hex-token>
```

> **Warning**: The root token has unlimited privileges. There is no root token revocation or rotation endpoint today; provision service tokens for day-to-day application access and keep the root token for administrative operations only. See [Production Deployment](../guides/production.md).

## Service Tokens

Native tokens (`egst_<id>.<secret>`) for machine-to-machine authentication, created and managed only by the root token.

### Create

```bash
curl -s -X POST http://localhost:8200/v1/auth/service-tokens \
  -H "Authorization: Bearer <root-token>" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "my-service"}'
# Returns: { "token_id": "...", "token": "egst_..." }
```

### List

```bash
curl -s http://localhost:8200/v1/auth/service-tokens \
  -H "Authorization: Bearer <root-token>"
```

### Revoke

```bash
curl -s -X DELETE http://localhost:8200/v1/auth/service-tokens/<token_id> \
  -H "Authorization: Bearer <root-token>"
```

### Use a Token

```bash
# Environment variable (CLI client)
export EGIDE_TOKEN="egst_..."
egide secrets get myapp/database

# Command line flag
egide --token "egst_..." secrets get myapp/database

# HTTP header (any client)
curl -H "Authorization: Bearer egst_..." \
  http://localhost:8200/v1/secrets/myapp/database
```

Service tokens can read and write secrets and use existing Transit keys, but cannot manage other tokens or perform operator actions such as sealing the server or managing Transit keys.

## AppRole, OIDC and mTLS

> **Status: planned, not implemented yet.** AppRole is tracked for 0.2.0 (see the [roadmap](../explanation/roadmap.md)); OIDC and mTLS have no committed target version. Today, root token and service tokens (above) are the only authentication methods.

## Policies

> **Status: planned, not implemented yet.** There is no policy engine, no YAML/HCL policy syntax, and no `egide policy` command. Authorization today is a binary distinction: operations are either root-only or open to any authenticated token (root or service). See the per-endpoint authorization notes in the [API reference](../api/overview.md).

## Best Practices

### Token Management

1. **Provision per application**: create one service token per consuming application, not a shared token.
2. **Least Privilege**: service tokens already cannot perform operator actions; do not share the root token with applications.
3. **Revoke Unused**: revoke service tokens for decommissioned applications via `DELETE /v1/auth/service-tokens/{token_id}`.

## Next Steps

- [Security Model](../security/model.md): Security architecture
- [API Overview](../api/overview.md): API authentication
