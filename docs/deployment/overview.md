# Deployment Overview

This guide covers the different ways to deploy Nubster Egide.

## Deployment Options

| Option | Best For | Complexity |
|--------|----------|------------|
| [Docker](#docker) | Quick start, development | ⭐ |
| [Docker Compose](#docker-compose) | Small production | ⭐⭐ |
| [Kubernetes](#kubernetes) | Enterprise, scaling | ⭐⭐⭐ |
| [Binary](#binary) | Bare metal, custom | ⭐⭐ |

## Docker

The fastest way to get started.

```bash
docker run -d \
  --name egide \
  -p 8200:8200 \
  -e EGIDE_DEV_MODE=true \
  nubster/egide:latest
```

**Use case:** Development, testing, evaluation.

➡️ [Docker Deployment Guide](./docker.md)

## Docker Compose

Production-ready with PostgreSQL.

```yaml
services:
  egide:
    image: nubster/egide:latest
    ports:
      - "8200:8200"
    environment:
      - EGIDE_STORAGE_TYPE=postgresql
      - EGIDE_DB_HOST=postgres
    depends_on:
      - postgres

  postgres:
    image: postgres:16
    volumes:
      - egide_data:/var/lib/postgresql/data
```

**Use case:** Small to medium production deployments.

➡️ [Docker Compose Guide](./docker-compose.md)

## Kubernetes

Scalable deployment with Helm.

```bash
helm repo add nubster https://charts.nubster.com
helm install egide nubster/egide \
  --set persistence.enabled=true \
  --set ha.enabled=true
```

**Use case:** Enterprise, high availability, auto-scaling.

➡️ [Kubernetes Deployment Guide](./kubernetes.md)

## Binary

Direct installation from release binaries.

```bash
# Download
curl -LO https://github.com/nubster-opensources/egide/releases/latest/download/egide-linux-amd64.tar.gz

# Extract
tar -xzf egide-linux-amd64.tar.gz

# Install
sudo mv egide-server egide /usr/local/bin/
```

**Use case:** Bare metal servers, air-gapped environments.

➡️ [Binary Installation Guide](./binary.md)

## Architecture Decision

### Single Node vs. Cluster

| Aspect | Single Node | Cluster |
|--------|-------------|---------|
| Setup | Simple | Complex |
| Availability | No redundancy | High availability |
| Scaling | Vertical only | Horizontal |
| Use case | Dev, small prod | Enterprise |

### Storage Backend

| Backend | Use Case |
|---------|----------|
| SQLite | Development, standalone |
| PostgreSQL | Production, clustering |

## Quick Comparison

```text
                    ┌─────────────────────────────────────┐
                    │         DEPLOYMENT COMPLEXITY        │
                    │                                     │
     Simple ◄───────┼──────────────────────────────►Complex
                    │                                     │
     ┌──────────┐   │   ┌──────────────┐   ┌───────────┐│
     │  Docker  │   │   │Docker Compose│   │Kubernetes ││
     │(Dev mode)│   │   │ + PostgreSQL │   │  + Helm   ││
     └──────────┘   │   └──────────────┘   └───────────┘│
         │         │          │                  │      │
         ▼         │          ▼                  ▼      │
     Development   │    Small/Medium          Enterprise│
                    │      Production                    │
                    └─────────────────────────────────────┘
```

## System Requirements

### Minimum (Development)

- CPU: 1 core
- RAM: 128 MB
- Disk: 100 MB

### Recommended (Production)

- CPU: 2+ cores
- RAM: 512 MB - 2 GB
- Disk: 10 GB+ (depends on data volume)
- Network: Low latency to storage backend

### Operating Systems

| OS | Support |
|----|---------|
| Linux (x86_64) | ✅ Recommended |
| macOS (x86_64, ARM64) | ✅ Supported |
| Windows (x86_64) | ✅ Supported |

## Next Steps

1. Choose your deployment method
2. Follow the specific guide
3. [Initialize and unseal](../getting-started/quick-start.md)
4. [Configure authentication](../concepts/authentication.md)
5. [Set up backups](../guides/backup.md)

## Related

- [Production Checklist](./production-checklist.md)
- [High Availability](../guides/high-availability.md)
- [Backup & Recovery](../guides/backup.md)
