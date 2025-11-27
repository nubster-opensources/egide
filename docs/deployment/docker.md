# Docker Deployment

Deploy Egide using Docker for quick setup and development.

## Quick Start

### Development Mode

```bash
docker run -d \
  --name egide \
  -p 8200:8200 \
  -e EGIDE_DEV_MODE=true \
  nubster/egide:latest
```

In dev mode:
- Automatically initialized and unsealed
- Root token printed to logs
- In-memory storage (data lost on restart)
- **Not for production!**

### Get Root Token

```bash
docker logs egide 2>&1 | grep "Root Token"
```

## Production Mode

### With Persistent Storage

```bash
docker run -d \
  --name egide \
  -p 8200:8200 \
  -v egide_data:/var/lib/egide \
  -e EGIDE_STORAGE_TYPE=sqlite \
  -e EGIDE_STORAGE_PATH=/var/lib/egide/egide.db \
  nubster/egide:latest
```

### Initialize and Unseal

```bash
# Initialize (first time only)
docker exec egide egide operator init

# Unseal (after every restart)
docker exec egide egide operator unseal
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `EGIDE_DEV_MODE` | Enable development mode | `false` |
| `EGIDE_LOG_LEVEL` | Logging level | `info` |
| `EGIDE_BIND_ADDRESS` | Server bind address | `0.0.0.0:8200` |
| `EGIDE_STORAGE_TYPE` | Storage backend | `sqlite` |
| `EGIDE_STORAGE_PATH` | SQLite database path | `/var/lib/egide/egide.db` |
| `EGIDE_TLS_ENABLED` | Enable TLS | `false` |
| `EGIDE_TLS_CERT` | TLS certificate path | - |
| `EGIDE_TLS_KEY` | TLS private key path | - |

### Using Config File

```bash
docker run -d \
  --name egide \
  -p 8200:8200 \
  -v ./egide.toml:/etc/egide/egide.toml:ro \
  -v egide_data:/var/lib/egide \
  nubster/egide:latest
```

## Volumes

| Path | Description |
|------|-------------|
| `/var/lib/egide` | Data directory (SQLite, files) |
| `/etc/egide` | Configuration directory |
| `/var/log/egide` | Log files |

## Networking

### Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 8200 | TCP | HTTP/HTTPS API |
| 8201 | TCP | Cluster (future) |

### With Custom Network

```bash
# Create network
docker network create egide-net

# Run with network
docker run -d \
  --name egide \
  --network egide-net \
  -p 8200:8200 \
  nubster/egide:latest
```

## TLS Configuration

### Self-Signed Certificate

```bash
# Generate certificate
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout egide.key \
  -out egide.crt \
  -subj "/CN=egide"

# Run with TLS
docker run -d \
  --name egide \
  -p 8200:8200 \
  -v $(pwd)/egide.crt:/etc/egide/tls.crt:ro \
  -v $(pwd)/egide.key:/etc/egide/tls.key:ro \
  -e EGIDE_TLS_ENABLED=true \
  -e EGIDE_TLS_CERT=/etc/egide/tls.crt \
  -e EGIDE_TLS_KEY=/etc/egide/tls.key \
  nubster/egide:latest
```

### With Let's Encrypt

Use a reverse proxy (Traefik, Caddy, nginx) for automatic TLS.

## Health Check

```bash
# Check health
curl http://localhost:8200/v1/sys/health

# Response
{
  "initialized": true,
  "sealed": false,
  "version": "0.1.0-alpha"
}
```

### Docker Health Check

The image includes a built-in health check:

```bash
docker inspect --format='{{.State.Health.Status}}' egide
```

## Logging

### View Logs

```bash
docker logs egide
docker logs -f egide  # Follow
```

### JSON Logging

```bash
docker run -d \
  --name egide \
  -e EGIDE_LOG_FORMAT=json \
  nubster/egide:latest
```

## Resource Limits

```bash
docker run -d \
  --name egide \
  --memory=512m \
  --cpus=1 \
  -p 8200:8200 \
  nubster/egide:latest
```

## Backup

### SQLite Backup

```bash
# Stop container (recommended)
docker stop egide

# Copy database
docker cp egide:/var/lib/egide/egide.db ./backup/

# Restart
docker start egide
```

### Online Backup (WAL mode)

```bash
docker exec egide egide operator backup --output /var/lib/egide/backup.enc
docker cp egide:/var/lib/egide/backup.enc ./backup/
```

## Upgrade

```bash
# Pull new image
docker pull nubster/egide:latest

# Stop current container
docker stop egide

# Remove container (data persisted in volume)
docker rm egide

# Start new container
docker run -d \
  --name egide \
  -p 8200:8200 \
  -v egide_data:/var/lib/egide \
  nubster/egide:latest

# Unseal
docker exec egide egide operator unseal
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs egide

# Check permissions
docker exec egide ls -la /var/lib/egide
```

### Cannot Connect

```bash
# Check if port is exposed
docker port egide

# Check if container is running
docker ps -a | grep egide

# Test connectivity
curl -v http://localhost:8200/v1/sys/health
```

### Sealed After Restart

This is expected. Egide must be unsealed after every restart:

```bash
docker exec egide egide operator unseal
```

## Next Steps

- [Docker Compose Deployment](./docker-compose.md) for production
- [Production Checklist](./production-checklist.md)
- [Backup & Recovery](../guides/backup.md)
