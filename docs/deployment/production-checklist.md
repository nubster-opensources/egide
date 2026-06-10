# Production Checklist

Use this checklist before deploying Egide to production.

## Security

### Authentication & Access

- [ ] **Disable dev mode** — `EGIDE_DEV_MODE=false`
- [ ] **Change root token** — Revoke initial root token after setup
- [ ] **Enable authentication** — Configure auth methods (Token, AppRole, OIDC)
- [ ] **Set up policies** — Define least-privilege access policies
- [ ] **Enable audit logging** — Track all access and operations

### Encryption & TLS

- [ ] **Enable TLS** — All traffic must be encrypted
- [ ] **Use valid certificates** — Not self-signed in production
- [ ] **Configure TLS version** — Minimum TLS 1.2
- [ ] **Secure private keys** — Restrict file permissions (600)

### Secrets Management

- [ ] **Secure unseal keys** — Store in separate secure locations
- [ ] **Implement key ceremony** — Multi-person authorization
- [ ] **Consider auto-unseal** — HSM or cloud KMS for automation
- [ ] **Rotate root credentials** — Regular rotation schedule

## Infrastructure

### High Availability

- [ ] **Multiple instances** — At least 3 for HA
- [ ] **Load balancer** — Distribute traffic
- [ ] **Health checks** — Automated failover
- [ ] **Database replication** — PostgreSQL HA setup

### Storage

- [ ] **Use PostgreSQL** — Not SQLite for production
- [ ] **Enable connection pooling** — PgBouncer or similar
- [ ] **Configure backups** — Regular automated backups
- [ ] **Test restores** — Verify backup integrity

### Networking

- [ ] **Firewall rules** — Allow only necessary ports
- [ ] **Network segmentation** — Egide in secure zone
- [ ] **No public exposure** — Use reverse proxy if needed
- [ ] **Rate limiting** — Protect against abuse

## Operations

### Monitoring

- [ ] **Health endpoint** — `/v1/sys/health` monitored
- [ ] **Metrics collection** — Prometheus or similar
- [ ] **Alerting** — Critical alerts configured
- [ ] **Log aggregation** — Centralized logging

### Backup & Recovery

- [ ] **Automated backups** — Daily minimum
- [ ] **Offsite storage** — Backups in different location
- [ ] **Encryption** — Backups encrypted at rest
- [ ] **Tested recovery** — Regular restore tests
- [ ] **RPO/RTO defined** — Recovery objectives documented

### Documentation

- [ ] **Runbook** — Operational procedures documented
- [ ] **Architecture diagram** — Current setup documented
- [ ] **Contact list** — On-call and escalation paths
- [ ] **Disaster recovery plan** — Tested and documented

## Configuration

### Server Settings

```toml
[server]
bind_address = "0.0.0.0:8200"
tls_enabled = true
tls_cert = "/etc/egide/tls.crt"
tls_key = "/etc/egide/tls.key"
tls_min_version = "1.2"

[storage]
type = "postgresql"

[storage.postgresql]
host = "postgres.internal"
port = 5432
database = "egide"
username = "egide"
password_env = "EGIDE_DB_PASSWORD"
ssl_mode = "verify-full"
pool_max = 50

[log]
level = "info"
format = "json"

[audit]
enabled = true
log_requests = true
log_responses = false  # Sensitive data
```

### Environment Variables

```bash
# Required
EGIDE_DB_PASSWORD=<secure-password>

# Recommended
EGIDE_CONFIG=/etc/egide/egide.toml
EGIDE_LOG_LEVEL=info
```

## Compliance

### Data Protection

- [ ] **Data classification** — Identify sensitive data
- [ ] **Encryption at rest** — All data encrypted
- [ ] **Encryption in transit** — TLS everywhere
- [ ] **Access logging** — Complete audit trail
- [ ] **Data retention** — Policies defined and enforced

### Regulatory

- [ ] **GDPR compliance** — If handling EU data
- [ ] **SOC 2 readiness** — Controls documented
- [ ] **ISO 27001 alignment** — Security framework
- [ ] **Industry specific** — PCI-DSS, HIPAA as applicable

## Pre-Launch Verification

### Functional Tests

- [ ] **Health check passes** — `/v1/sys/health` returns healthy
- [ ] **Authentication works** — All auth methods tested
- [ ] **Secrets CRUD** — Create, read, update, delete tested
- [ ] **Encryption/decryption** — Transit operations verified
- [ ] **Certificate issuance** — PKI tested if enabled

### Security Tests

- [ ] **Penetration test** — External security assessment
- [ ] **Vulnerability scan** — Automated scanning
- [ ] **Access review** — Policies reviewed
- [ ] **Secret rotation** — Process tested

### Performance Tests

- [ ] **Load test** — Expected traffic simulated
- [ ] **Stress test** — Peak load handled
- [ ] **Latency acceptable** — Response times within SLA
- [ ] **Resource utilization** — CPU/memory monitored

## Post-Launch

### First Week

- [ ] **Monitor closely** — Extra attention to metrics
- [ ] **Review logs** — Check for anomalies
- [ ] **Gather feedback** — User experience
- [ ] **Document issues** — Track and resolve

### Ongoing

- [ ] **Regular audits** — Quarterly security reviews
- [ ] **Update schedule** — Patch management plan
- [ ] **Backup verification** — Monthly restore tests
- [ ] **Capacity planning** — Growth projections

## Quick Reference

### Critical Ports

| Port | Service | Access |
|------|---------|--------|
| 8200 | HTTPS API | Internal/LB only |
| 5432 | PostgreSQL | Egide servers only |

### Key Files

| Path | Description | Permissions |
|------|-------------|-------------|
| `/etc/egide/egide.toml` | Configuration | 640 |
| `/etc/egide/tls.key` | TLS private key | 600 |
| `/var/lib/egide/` | Data directory | 700 |

### Emergency Procedures

1. **Service down** — Check health, restart, unseal
2. **Compromised key** — Rotate immediately, revoke access
3. **Data breach** — Follow incident response plan
4. **Full outage** — Execute disaster recovery

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security | | | |
| Operations | | | |
| Development | | | |
| Management | | | |

---

**Reminder:** This checklist should be reviewed and updated regularly as requirements change.
