# Production Deployment

Best practices for deploying Egide in production.

## Checklist

Before going to production, ensure:

- [ ] TLS is enabled
- [ ] Dev mode is disabled
- [ ] Unseal keys are stored securely
- [ ] Root token is revoked
- [ ] Backup strategy is in place
- [ ] Monitoring is configured
- [ ] Audit logging is enabled
- [ ] Resource limits are set

## Security Hardening

### Disable Dev Mode

Never use dev mode in production:

```toml
[server]
dev_mode = false
```

### Enable TLS

Always use TLS:

```toml
[server]
tls_enabled = true
tls_cert_file = "/etc/egide/tls/server.crt"
tls_key_file = "/etc/egide/tls/server.key"
```

Use certificates from a trusted CA or your internal PKI.

### Secure Unseal Keys

1. **Split custody**: Give each key share to a different person
2. **Secure storage**: Use hardware security modules (HSM) or secure vaults
3. **Geographic distribution**: Store keys in different locations
4. **Regular rotation**: Rotate unseal keys periodically

### Revoke Root Token

After initial setup:

1. Create admin policies and tokens
2. Revoke the root token:

```bash
egide token revoke <root-token>
```

3. Generate new root token only when needed

### Network Security

1. **Firewall**: Restrict access to port 8200
2. **Private network**: Deploy in private subnet
3. **Load balancer**: Terminate TLS at load balancer or Egide
4. **mTLS**: Use mutual TLS for service-to-service communication

## Storage

### PostgreSQL (Recommended)

Use PostgreSQL for production:

```toml
[storage]
backend = "postgres"

[storage.postgres]
host = "postgres.internal"
port = 5432
database = "egide"
username = "egide"
password = "${POSTGRES_PASSWORD}"
ssl_mode = "require"
```

### Database Security

1. **Encryption at rest**: Enable disk encryption
2. **Network encryption**: Use SSL connections
3. **Access control**: Restrict database access
4. **Regular backups**: Automated backup schedule

## High Availability

See [High Availability Guide](high-availability.md) for detailed HA setup.

### Stateless Deployment

Deploy multiple Egide instances behind a load balancer:

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │ Egide 1 │         │ Egide 2 │         │ Egide 3 │
    └────┬────┘         └────┬────┘         └────┬────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
                    ┌────────▼────────┐
                    │   PostgreSQL    │
                    └─────────────────┘
```

### Health Checks

Configure health checks for your load balancer:

- **Endpoint**: `GET /v1/sys/health`
- **Healthy**: 200 OK
- **Unhealthy**: 5xx or timeout

## Monitoring

### Metrics

Enable Prometheus metrics:

```toml
[telemetry]
metrics_enabled = true
metrics_path = "/metrics"
```

Key metrics:
- `egide_requests_total` — Total requests by endpoint
- `egide_request_duration_seconds` — Request latency
- `egide_secrets_total` — Number of stored secrets
- `egide_seal_status` — Seal status (0=unsealed, 1=sealed)

### Logging

Configure structured logging:

```toml
[logging]
level = "info"
format = "json"
output = "/var/log/egide/egide.log"
```

Ship logs to your log aggregation system (ELK, Loki, etc.).

### Alerts

Set up alerts for:

- Egide sealed unexpectedly
- High error rate
- Certificate expiration
- Storage capacity
- High latency

## Backup & Recovery

### Backup Strategy

1. **Database**: Regular PostgreSQL backups
2. **Configuration**: Version control config files
3. **Unseal keys**: Secure offline storage
4. **Test restores**: Regularly test recovery

### Disaster Recovery

Document and test:

1. Database restoration
2. Egide deployment
3. Unseal process
4. Verification steps

## Resource Planning

### Sizing Guidelines

| Workload | CPU | Memory | Storage |
|----------|-----|--------|---------|
| Light (< 100 secrets) | 0.5 vCPU | 256 MB | 1 GB |
| Medium (100-1000 secrets) | 1 vCPU | 512 MB | 10 GB |
| Heavy (1000+ secrets) | 2+ vCPU | 1+ GB | 50+ GB |

### Resource Limits

Set container resource limits:

```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 1G
    reservations:
      cpus: '0.5'
      memory: 256M
```

## Audit & Compliance

### Audit Logging

All operations are logged:

```json
{
  "time": "2025-01-15T10:30:00Z",
  "type": "request",
  "path": "/v1/secrets/myapp/database",
  "method": "GET",
  "client_ip": "10.0.0.5",
  "user": "admin",
  "policies": ["admin-policy"],
  "success": true
}
```

### Compliance Features

- **GDPR**: Data sovereignty, audit trails, right to erasure
- **SOC 2**: Access controls, audit logging, encryption
- **ISO 27001**: Security controls, documentation

## Maintenance

### Updates

1. Test updates in staging
2. Plan maintenance window
3. Backup before update
4. Update one instance at a time (rolling update)
5. Verify functionality
6. Monitor for issues

### Certificate Renewal

1. Generate new certificates before expiration
2. Update configuration
3. Reload or restart Egide
4. Verify TLS is working

### Key Rotation

Rotate encryption keys periodically:

```bash
# Rotate KMS keys
egide kms rotate <key-name>

# Rewrap secrets with new key
egide transit rewrap <key-name> --all
```

## Next Steps

- [High Availability](high-availability.md) — HA deployment patterns
- [Backup & Recovery](backup.md) — Backup strategies
