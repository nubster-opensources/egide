# Docker Deployment

Deploy Egide using Docker for quick setup and development.

## Quick Start

Start Egide with a persistent volume. The published image is a release build, so it always starts sealed and refuses dev mode by design.

```bash
docker run -d \
  --name egide \
  -p 8200:8200 \
  -v egide_data:/var/lib/egide \
  -e EGIDE_DATA_DIR=/var/lib/egide \
  nubster/egide:latest
```

### Initialize and Unseal

```bash
# Initialize (first time only)
docker exec egide egide operator init

# Unseal (after every restart)
docker exec egide egide operator unseal
```

> Dev mode is a development convenience for contributors running a debug build locally: `EGIDE_UNSAFE_DEV_MODE=1 cargo run -p egide-server -- --dev`. It stores the master key in cleartext and is refused categorically by release builds, including this image. See the [production checklist](./production-checklist.md).

## Configuration

Egide is configured via CLI flags or environment variables only; there is no configuration file (see [Configuration](../getting-started/configuration.md)).

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `EGIDE_DEV_MODE` | Enable development mode (also requires `EGIDE_UNSAFE_DEV_MODE=1`; refused by release builds, including this image) | `false` |
| `RUST_LOG` | Log filter (e.g. `info`, `info,egide=debug`) | `info,egide=debug` |
| `EGIDE_BIND_ADDRESS` | REST bind address | `0.0.0.0:8200` |
| `EGIDE_GRPC_BIND` | gRPC bind address | `0.0.0.0:8201` |
| `EGIDE_DATA_DIR` | Data directory (SQLite database files) | `./data` |

> Egide always uses its bundled SQLite backend today; there is no environment variable to select PostgreSQL at runtime (see [Configuration](../getting-started/configuration.md#storage-backend)).

## Volumes

| Path | Description |
|------|-------------|
| `/var/lib/egide` | Data directory (SQLite database files) |

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

## TLS

> **Status: planned, not implemented yet.** Egide does not terminate TLS itself; the container listens on plain HTTP. Put a reverse proxy (Traefik, Caddy, nginx) in front of the container and terminate TLS there. Let's Encrypt certificates work the same way, through the reverse proxy's own ACME support.

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

### Log Filtering

```bash
docker run -d \
  --name egide \
  -e RUST_LOG=info,egide=debug \
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

The data directory holds one SQLite file per internal engine (for example `system.db`, `transit.db`, and one file per secrets tenant). Back up the whole directory:

```bash
# Stop container (recommended)
docker stop egide

# Copy the data directory
docker cp egide:/var/lib/egide ./backup/

# Restart
docker start egide
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
