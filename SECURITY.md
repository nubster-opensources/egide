# Security Policy

## Reporting a Vulnerability

We take security seriously at Nubster. If you discover a security vulnerability in Egide, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email us at: **<security@nubster.com>**

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity (critical: ASAP, high: 30 days, medium: 90 days)

### Scope

The following are in scope:

- `egide-server` binary
- `egide-cli` tool
- All `egide-*` crates
- Official Docker images
- Official documentation (if it leads to security issues)

Out of scope:

- Third-party integrations
- Social engineering attacks
- Physical security

## Security Best Practices

When deploying Egide:

1. **Never run in dev mode in production** (release builds, including the published Docker image, refuse dev mode by design)
2. **Use TLS for all connections**
3. **Rotate unseal keys regularly**
4. **Enable audit logging**
5. **Use least privilege for policies**
6. **Keep Egide updated**
7. **Backup sealed data regularly**

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Advisories

Security advisories will be published through GitHub Security Advisories on the [Egide repository](https://github.com/nubster-opensources/egide/security/advisories).

## Bug Bounty

We do not currently have a formal bug bounty program. However, we recognize and thank security researchers who responsibly disclose vulnerabilities.
