# Authentication

Egide supports multiple authentication methods to accommodate different use cases.

## Overview

| Method | Use Case | Best For |
|--------|----------|----------|
| **Token** | Direct API access | Scripts, CI/CD, testing |
| **AppRole** | Machine-to-machine | Services, applications |
| **OIDC** | Human users | SSO integration |
| **mTLS** | Certificate-based | Service mesh, zero-trust |

## Token Authentication

The simplest method. Tokens are passed in requests to authenticate.

### Root Token

Generated during initialization:

```bash
egide operator init
# Output includes: Initial Root Token: s.XXXX...
```

> **Warning**: The root token has unlimited privileges. Revoke it after creating other tokens.

### Create Token

```bash
# Create token with policies
egide token create --policies=read-secrets,write-logs

# Create token with TTL
egide token create --policies=read-secrets --ttl=1h

# Create token with limited uses
egide token create --policies=read-secrets --use-limit=10
```

### Use Token

```bash
# Environment variable
export EGIDE_TOKEN="s.XXXX..."
egide secrets get myapp/database

# Command line flag
egide --token "s.XXXX..." secrets get myapp/database

# HTTP header
curl -H "Authorization: Bearer s.XXXX..." \
  https://egide.example.com/v1/secrets/myapp/database
```

### Revoke Token

```bash
egide token revoke s.XXXX...
```

## AppRole Authentication

Designed for machines and applications. Uses Role ID + Secret ID.

### Enable AppRole

```bash
egide auth enable approle
```

### Create Role

```bash
egide auth approle create my-app \
  --policies=app-secrets \
  --token-ttl=1h \
  --secret-id-ttl=24h
```

### Get Credentials

```bash
# Get Role ID (stable, can be embedded in config)
egide auth approle role-id my-app

# Generate Secret ID (rotate regularly)
egide auth approle secret-id my-app
```

### Login

```bash
# Login and get token
egide auth approle login \
  --role-id=ROLE_ID \
  --secret-id=SECRET_ID
```

### Application Integration

```python
# Application startup
role_id = os.environ["EGIDE_ROLE_ID"]
secret_id = os.environ["EGIDE_SECRET_ID"]

# Login to get token
token = egide.auth.approle.login(role_id, secret_id)

# Use token for requests
secrets = egide.secrets.get("myapp/database", token=token)
```

## OIDC Authentication

Integrate with identity providers (Azure AD, Google, Okta, etc.).

### Enable OIDC

```bash
egide auth enable oidc
```

### Configure Provider

```bash
egide auth oidc configure \
  --issuer="https://login.example.com" \
  --client-id="egide-app" \
  --client-secret="secret" \
  --redirect-uri="https://egide.example.com/v1/auth/oidc/callback"
```

### Map Claims to Policies

```bash
# Map groups to policies
egide auth oidc map-group "engineering" --policies=dev-secrets
egide auth oidc map-group "security" --policies=admin
```

### Login Flow

1. User visits: `https://egide.example.com/v1/auth/oidc/login`
2. Redirected to identity provider
3. After authentication, redirected back with token
4. Token has policies based on group membership

## mTLS Authentication

Certificate-based authentication for zero-trust environments.

### Enable mTLS

```bash
egide auth enable mtls
```

### Configure CA

```bash
# Trust certificates signed by this CA
egide auth mtls configure --ca-cert=@ca.crt
```

### Map Certificates to Policies

```bash
# Map by CN (Common Name)
egide auth mtls map-cn "api-service" --policies=api-secrets

# Map by OU (Organizational Unit)
egide auth mtls map-ou "engineering" --policies=dev-secrets
```

### Client Configuration

```bash
# Connect with client certificate
curl --cert client.crt --key client.key \
  https://egide.example.com/v1/secrets/myapp/database
```

## Policies

Policies define what authenticated entities can do.

### Policy Syntax

```hcl
# Allow read access to myapp secrets
path "secrets/myapp/*" {
  capabilities = ["read", "list"]
}

# Allow full access to team secrets
path "secrets/team-a/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Deny access to admin secrets
path "secrets/admin/*" {
  capabilities = ["deny"]
}
```

### Capabilities

| Capability | HTTP Methods |
|------------|--------------|
| `create` | POST |
| `read` | GET |
| `update` | PUT, PATCH |
| `delete` | DELETE |
| `list` | GET (list) |
| `deny` | Explicitly deny |

### Create Policy

```bash
egide policy write my-policy @policy.hcl
```

### Attach Policy to Token

```bash
egide token create --policies=my-policy
```

## Best Practices

### Token Management

1. **Short TTLs**: Use short-lived tokens when possible
2. **Least Privilege**: Grant only necessary permissions
3. **Revoke Unused**: Revoke tokens that are no longer needed
4. **Audit**: Monitor token usage

### AppRole Security

1. **Rotate Secret IDs**: Generate new Secret IDs regularly
2. **CIDR Binding**: Restrict login by IP address
3. **Use Limit**: Set maximum uses for Secret IDs

### OIDC Integration

1. **Group Mapping**: Use groups, not individual users
2. **Least Privilege**: Map groups to minimal policies
3. **Review Regularly**: Audit group membership

### mTLS

1. **Certificate Lifecycle**: Automate certificate renewal
2. **Revocation**: Check CRL/OCSP for revoked certificates
3. **Separate CAs**: Use dedicated CA for Egide authentication

## Audit Logging

All authentication events are logged:

```json
{
  "time": "2025-01-15T10:30:00Z",
  "type": "auth",
  "method": "approle",
  "role": "my-app",
  "client_ip": "10.0.0.5",
  "success": true,
  "policies": ["app-secrets"]
}
```

## Next Steps

- [Security Model](../security/model.md) — Security architecture
- [API Overview](../api/overview.md) — API authentication
