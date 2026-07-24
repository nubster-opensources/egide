# Production Deployment

Best practices for deploying Egide in production.

## Checklist

Before going to production, ensure:

- [ ] TLS is terminated in front of Egide (a reverse proxy or load balancer; Egide does not terminate TLS itself, see below)
- [ ] Dev mode is not enabled (refused by release builds by design; confirm `EGIDE_UNSAFE_DEV_MODE` is unset and `EGIDE_ENV=production`)
- [ ] Unseal keys are stored securely
- [ ] Additional service tokens are provisioned and the root token's plaintext is discarded after setup (see below; there is no root token revocation endpoint today)
- [ ] Backup strategy is in place
- [ ] Monitoring is configured
- [ ] Resource limits are set

## Security Hardening

### Dev Mode

Release builds, including the published Docker image, refuse dev mode by design: there is no configuration flag to disable, because it cannot be enabled in the first place. Dev mode exists only in debug builds and requires both `EGIDE_UNSAFE_DEV_MODE=1` and the absence of `EGIDE_ENV=production`. As defense in depth in production, set `EGIDE_ENV=production` and ensure `EGIDE_UNSAFE_DEV_MODE` is not set.

### TLS

> **Status: planned, not implemented yet.** Egide does not terminate TLS itself; `egide-server` binds to a plain HTTP address (`--bind` / `EGIDE_BIND_ADDRESS`). Put a reverse proxy or load balancer (nginx, Traefik, HAProxy, a cloud load balancer) in front of it and terminate TLS there, using certificates from a trusted CA or your internal PKI.

### Secure Unseal Keys

1. **Split custody**: Give each key share to a different person
2. **Secure storage**: Use hardware security modules (HSM) or secure vaults
3. **Geographic distribution**: Store keys in different locations
4. **Regular rotation**: Rotate unseal keys periodically

### Limit Root Token Usage

After initial setup:

1. Create a service token for each consuming application (root-only operation):

```bash
curl -s -X POST http://localhost:8200/v1/auth/service-tokens \
  -H "Authorization: Bearer <root-token>" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "my-service"}'
```

2. Use service tokens for day-to-day secrets and Transit access; keep the root token for administrative operations only (init, seal, transit key management).

> **Status: planned, not implemented yet.** There is no root token revocation or rotation endpoint today; `POST /v1/sys/init` issues the root token exactly once. Service tokens, in contrast, can be listed and revoked individually via `GET` / `DELETE /v1/auth/service-tokens/{token_id}` (root-only).

### Network Security

1. **Firewall**: Restrict access to port 8200
2. **Private network**: Deploy in private subnet
3. **Load balancer**: Terminate TLS at the load balancer or reverse proxy (Egide itself does not terminate TLS, see above)
4. **mTLS**: Use mutual TLS between the load balancer and consuming services

## Storage

### PostgreSQL

> **Status: planned, not implemented yet.** An `egide-storage-postgres` crate exists in the workspace and is exercised by its own test suite, but `egide-server` does not yet expose a flag or environment variable to select it at startup. The running server always uses the bundled SQLite backend today (see [Configuration](../getting-started/configuration.md#storage-backend)). Track the roadmap for the runtime storage-selection work.

### Database Security

1. **Encryption at rest**: Enable disk encryption
2. **Network encryption**: Use SSL connections
3. **Access control**: Restrict database access
4. **Regular backups**: Automated backup schedule

## High Availability

See [High Availability Guide](high-availability.md) for detailed HA setup.

> Multi-instance HA needs a storage backend shared across instances. Today Egide always uses its bundled SQLite backend (one file per node); the PostgreSQL backend exists in the workspace but is not yet wired into `egide-server` startup (see [Storage](#storage) above). The diagram below shows the target topology.

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
- **Always returns**: `200 OK` with a JSON body (`{"status": "ok", "initialized": ..., "sealed": ..., "version": ..., "uptime_secs": ...}`); the HTTP status code does not vary with seal state today. Inspect the `sealed` and `initialized` fields in the body if the load balancer needs to distinguish an unsealed-and-ready instance from a sealed one.
- **Unhealthy**: connection refused, timeout, or non-200 (process crash)

## Monitoring

### Metrics

> **Status: planned, not implemented yet.** Egide does not expose a Prometheus `/metrics` endpoint or any metrics configuration today. See [Observability](../deployment/overview.md) for the roadmap.

### Logging

Egide logs to stderr using `tracing`, controlled by the standard `RUST_LOG` environment variable (for example `RUST_LOG=info,egide=debug`, which is also the built-in default). There is no `[logging]` configuration section or output-file setting: redirect stderr or capture it with your container runtime / process supervisor, and ship it to your log aggregation system (ELK, Loki, etc.). Stdout carries a single startup line, `EGIDE_LISTEN_ADDR=<ip>:<port>`, the actual bound listen address, useful when the port is ephemeral.

### Alerts

Set up alerts for:

- Egide sealed unexpectedly
- High error rate
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

> **Status: planned for 0.2.0, not implemented yet.** An append-only, HMAC-signed audit log is on the roadmap. Today, `tracing` request logs (see [Logging](#logging) above) are the only operational log output; they are not a tamper-evident audit trail.

### Security Features

- **Data residency**: deploy in any infrastructure you control, no external data export
- **Access controls**: root token and native service tokens (`egst_<id>.<secret>`), both authenticated via `Authorization: Bearer`
- **Encryption**: secrets and key material encrypted at rest (AES-256-GCM); encryption in transit depends on a TLS-terminating reverse proxy in front of Egide (see [TLS](#tls) above)

## Maintenance

### Updates

1. Test updates in staging
2. Plan maintenance window
3. Backup before update
4. Update one instance at a time (rolling update)
5. Verify functionality
6. Monitor for issues

### Certificate Renewal

TLS certificates are managed by whatever reverse proxy or load balancer terminates TLS in front of Egide (see [TLS](#tls) above), not by Egide itself:

1. Generate new certificates before expiration
2. Update the reverse proxy configuration
3. Reload or restart the reverse proxy
4. Verify TLS is working

### Key Rotation

Rotate Transit keys individually through the REST API (root token required), then rewrap stored ciphertext with the new version:

```bash
# Rotate a Transit key to a new version
curl -s -X POST http://localhost:8200/v1/transit/keys/<key-name>/rotate \
  -H "Authorization: Bearer <root-token>"

# Rewrap a stored ciphertext to the latest version
curl -s -X POST http://localhost:8200/v1/transit/rewrap/<key-name> \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "egide:v1:..."}'
```

There is no bulk `--all` rewrap operation: rewrap each stored ciphertext individually.

## Next Steps

- [High Availability](high-availability.md): HA deployment patterns
- [Backup & Recovery](backup.md): Backup strategies
