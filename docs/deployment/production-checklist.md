# Production Checklist

Use this checklist before deploying Egide to production.

## Security

### Authentication & Access

- [ ] **Dev mode is refused by design**: release builds, including this Docker image, refuse dev mode categorically. As defense in depth, ensure `EGIDE_UNSAFE_DEV_MODE` is not set and set `EGIDE_ENV=production`
- [ ] **Limit root token exposure** : provision service tokens for consuming applications and keep the root token for administrative operations only (there is no root token revocation endpoint today)
- [ ] **Enable authentication** : root token and native service tokens are implemented today; AppRole is planned for 0.2.0

### Encryption & TLS

- [ ] **Terminate TLS in front of Egide** : Egide does not terminate TLS itself (planned, not implemented yet); place a reverse proxy or load balancer in front of it
- [ ] **Use valid certificates** : Not self-signed in production
- [ ] **Configure TLS version** : Minimum TLS 1.2, enforced at the reverse proxy
- [ ] **Secure private keys** : Restrict file permissions (600)

### Secrets Management

- [ ] **Secure unseal keys** : Store in separate secure locations
- [ ] **Implement key ceremony** : Multi-person authorization
- [ ] **Consider auto-unseal** : HSM or cloud KMS for automation
- [ ] **Rotate root credentials** : Regular rotation schedule

## Infrastructure

### High Availability

- [ ] **Multiple instances** : At least 3 for HA (requires the PostgreSQL backend to be wired in; see Storage below)
- [ ] **Load balancer** : Distribute traffic
- [ ] **Health checks** : Automated failover

### Storage

- [ ] **PostgreSQL for multi-instance deployments** : planned, not implemented yet; `egide-server` always uses its bundled SQLite backend today, so each instance has its own local data directory (see [Configuration](../getting-started/configuration.md#storage-backend))
- [ ] **Configure backups** : Regular automated backups of the data directory
- [ ] **Test restores** : Verify backup integrity

### Networking

- [ ] **Firewall rules** : Allow only necessary ports
- [ ] **Network segmentation** : Egide in secure zone
- [ ] **No public exposure** : Use reverse proxy if needed
- [ ] **Rate limiting** : Protect against abuse

## Operations

### Monitoring

- [ ] **Health endpoint** : `/v1/sys/health` monitored
- [ ] **Metrics collection** : Prometheus or similar
- [ ] **Alerting** : Critical alerts configured
- [ ] **Log aggregation** : Centralized logging

### Backup & Recovery

- [ ] **Automated backups** : Daily minimum
- [ ] **Offsite storage** : Backups in different location
- [ ] **Encryption** : Backups encrypted at rest
- [ ] **Tested recovery** : Regular restore tests
- [ ] **RPO/RTO defined** : Recovery objectives documented

### Documentation

- [ ] **Runbook** : Operational procedures documented
- [ ] **Architecture diagram** : Current setup documented
- [ ] **Contact list** : On-call and escalation paths
- [ ] **Disaster recovery plan** : Tested and documented

## Configuration

Egide has no configuration file; it is configured through CLI flags and environment variables only (see [Configuration](../getting-started/configuration.md)).

### Recommended Environment Variables

```bash
EGIDE_DATA_DIR=/var/lib/egide
EGIDE_BIND_ADDRESS=0.0.0.0:8200
EGIDE_GRPC_BIND=0.0.0.0:8201
RUST_LOG=info
```

TLS is not implemented by Egide itself; terminate it at a reverse proxy in front of the server (see [Production Deployment](../guides/production.md#tls)). PostgreSQL storage selection does not exist yet either (see [Configuration](../getting-started/configuration.md#storage-backend)).

## Compliance

### Data Protection

- [ ] **Data classification** : Identify sensitive data
- [ ] **Encryption at rest** : All data encrypted (AES-256-GCM, implemented today)
- [ ] **Encryption in transit** : TLS at the reverse proxy (Egide does not terminate TLS itself)
- [ ] **Access logging** : `tracing` request logs shipped to your log aggregation system; a tamper-evident audit trail is planned for 0.2.0, not implemented yet
- [ ] **Data retention** : Policies defined and enforced

### Security Controls

- [ ] **Encryption at rest verified** : Storage backend uses AES-256-GCM
- [ ] **Data residency** : Deployment region chosen and documented

## Pre-Launch Verification

### Functional Tests

- [ ] **Health check passes** : `/v1/sys/health` returns healthy
- [ ] **Authentication works** : root token and service tokens tested
- [ ] **Secrets CRUD** : Create, read, update, delete tested
- [ ] **Encryption/decryption** : Transit operations verified

### Security Tests

- [ ] **Penetration test** : External security assessment
- [ ] **Vulnerability scan** : Automated scanning
- [ ] **Access review** : service token inventory reviewed
- [ ] **Secret rotation** : Process tested

### Performance Tests

- [ ] **Load test** : Expected traffic simulated
- [ ] **Stress test** : Peak load handled
- [ ] **Latency acceptable** : Response times within SLA
- [ ] **Resource utilization** : CPU/memory monitored

## Post-Launch

### First Week

- [ ] **Monitor closely** : Extra attention to metrics
- [ ] **Review logs** : Check for anomalies
- [ ] **Gather feedback** : User experience
- [ ] **Document issues** : Track and resolve

### Ongoing

- [ ] **Regular audits** : Quarterly security reviews
- [ ] **Update schedule** : Patch management plan
- [ ] **Backup verification** : Monthly restore tests
- [ ] **Capacity planning** : Growth projections

## Quick Reference

### Critical Ports

| Port | Service | Access |
|------|---------|--------|
| 8200 | REST API | Internal/LB only |
| 8201 | gRPC API | Internal/LB only |

### Key Files

| Path | Description | Permissions |
|------|-------------|-------------|
| `/var/lib/egide/` | Data directory (SQLite database files) | 700 |

### Emergency Procedures

1. **Service down** : Check health, restart, unseal
2. **Compromised key** : Rotate immediately, revoke access
3. **Data breach** : Follow incident response plan
4. **Full outage** : Execute disaster recovery

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security | | | |
| Operations | | | |
| Development | | | |
| Management | | | |

---

**Reminder:** This checklist should be reviewed and updated regularly as requirements change.
