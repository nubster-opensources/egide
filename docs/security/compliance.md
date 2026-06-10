# Compliance

Egide is designed to help organizations meet regulatory compliance requirements.

## Overview

| Standard | Status | Key Features |
|----------|--------|--------------|
| **GDPR** | Supported | Data sovereignty, audit trails, encryption |
| **SOC 2** | Supported | Access controls, audit logging, encryption |
| **ISO 27001** | Supported | Security controls, documentation |
| **SecNumCloud** | Ready | French security certification |
| **PCI DSS** | Partial | Encryption, access control |
| **HIPAA** | Partial | Encryption, audit trails |

## GDPR (General Data Protection Regulation)

### Relevant Articles

| Article | Requirement | Egide Feature |
|---------|-------------|---------------|
| Art. 5 | Data minimization | Store only necessary secrets |
| Art. 25 | Privacy by design | Encryption by default |
| Art. 30 | Records of processing | Audit logging |
| Art. 32 | Security of processing | Encryption, access control |
| Art. 33 | Breach notification | Audit logs for forensics |
| Art. 17 | Right to erasure | Secret deletion |

### Data Sovereignty

Egide supports data sovereignty requirements:

- **Self-hosted**: Deploy in your own infrastructure
- **EU hosting**: Deploy in EU data centers
- **No data export**: Data never leaves your control

### Data Subject Rights

| Right | Implementation |
|-------|----------------|
| Access | Audit logs show who accessed data |
| Erasure | Hard delete secrets permanently |
| Portability | Export secrets (if allowed by policy) |

## SOC 2

### Trust Service Criteria

| Criteria | Egide Controls |
|----------|----------------|
| **Security** | Authentication, authorization, encryption |
| **Availability** | HA deployment, health monitoring |
| **Confidentiality** | Encryption at rest and in transit |
| **Processing Integrity** | Audit logging, versioning |
| **Privacy** | Access controls, audit trails |

### Control Objectives

#### CC6.1 - Logical Access

- Policy-based access control
- Token-based authentication
- Multi-factor via OIDC integration
- Role separation (admin, operator, user)

#### CC6.2 - System Operations

- Audit logging of all operations
- Monitoring and alerting
- Incident response procedures

#### CC6.3 - Change Management

- Version control for configurations
- Key rotation with versioning
- Audit trail of changes

### Audit Evidence

Egide provides:

- Complete audit logs
- Access reports
- Key usage statistics
- Authentication events

## ISO 27001

### Annex A Controls

| Control | Implementation |
|---------|----------------|
| A.9 Access Control | Policies, authentication |
| A.10 Cryptography | AES-256, key management |
| A.12 Operations Security | Logging, monitoring |
| A.13 Communications | TLS encryption |
| A.18 Compliance | Audit logs, reports |

### Documentation

Egide supports ISO 27001 documentation requirements:

- Security policies (in policy engine)
- Access control matrix (policies)
- Audit records (logs)
- Change logs (versioning)

## SecNumCloud (French)

### Requirements

| Requirement | Egide Support |
|-------------|---------------|
| Data localization | Self-hosted in France |
| Encryption | AES-256-GCM |
| Key management | Shamir's Secret Sharing |
| Access control | Policy-based authorization |
| Audit | Complete audit logging |

### Certification Path

1. Deploy Egide self-hosted in France
2. Configure according to SecNumCloud requirements
3. Implement organizational controls
4. Undergo certification audit

## PCI DSS

### Relevant Requirements

| Requirement | Implementation |
|-------------|----------------|
| 3.4 | Encryption of cardholder data |
| 3.5 | Key management procedures |
| 3.6 | Key rotation |
| 8.1 | User identification |
| 10.1 | Audit trails |

### Scope Reduction

Using Egide for secrets management can reduce PCI DSS scope:

- Encrypt cardholder data with Transit Engine
- Store encryption keys in KMS
- Centralize access logging

## HIPAA

### Security Rule Requirements

| Requirement | Implementation |
|-------------|----------------|
| Access Control | Authentication, authorization |
| Audit Controls | Comprehensive logging |
| Integrity | Encryption, versioning |
| Transmission Security | TLS encryption |

### PHI Protection

- Encrypt PHI with Transit Engine
- Control access with policies
- Audit all PHI access
- Support breach forensics

## Compliance Features

### Audit Logging

All operations are logged:

```json
{
  "time": "2025-01-15T10:30:00Z",
  "type": "request",
  "operation": "read",
  "path": "secrets/patient/record-123",
  "user": "dr.smith",
  "client_ip": "10.0.0.5",
  "success": true
}
```

### Access Reports

Generate compliance reports:

```bash
egide audit report \
  --start "2025-01-01" \
  --end "2025-01-31" \
  --format json
```

### Encryption Evidence

Document encryption controls:

- Algorithm: AES-256-GCM
- Key length: 256 bits
- Key rotation: Automatic with versioning
- Key protection: Shamir's Secret Sharing

### Access Control Matrix

Export policy documentation:

```bash
egide policy export --format markdown
```

## Compliance Checklist

### Before Deployment

- [ ] Choose compliant hosting location
- [ ] Configure TLS certificates
- [ ] Plan key ceremony
- [ ] Define access policies
- [ ] Set up audit log forwarding

### During Operation

- [ ] Monitor audit logs
- [ ] Rotate keys on schedule
- [ ] Review access policies quarterly
- [ ] Conduct access reviews
- [ ] Test disaster recovery

### For Audits

- [ ] Export audit logs
- [ ] Generate access reports
- [ ] Document key management procedures
- [ ] Provide policy documentation
- [ ] Demonstrate encryption controls

## Compliance Limitations

Egide helps with technical controls but does not address:

- **Organizational policies**: You must create and enforce policies
- **Physical security**: Protect your infrastructure
- **Personnel security**: Background checks, training
- **Business continuity**: Full DR planning
- **Third-party risk**: Vendor management

## Next Steps

- [Security Model](model.md) — Technical security details
- [Production Deployment](../guides/production.md) — Secure deployment
