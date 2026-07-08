# Docker Deployment

This guide covers deploying Egide with Docker and Docker Compose.

## Quick Start

```bash
docker run -d \
  --name egide \
  -p 8200:8200 \
  -v egide-data:/var/lib/egide \
  nubster/egide:latest
```

## Docker Compose

### Development Setup

Create `docker-compose.yml`:

```yaml
services:
  egide:
    image: nubster/egide:latest
    container_name: egide-dev
    ports:
      - "8200:8200"
    environment:
      - EGIDE_LOG_LEVEL=debug
    volumes:
      - egide-data:/var/lib/egide

volumes:
  egide-data:
```

Start:

```bash
docker compose up -d
```

The container starts sealed. Initialize and unseal it once:

```bash
docker compose exec egide egide operator init
docker compose exec egide egide operator unseal
```

Dev mode (`EGIDE_DEV_MODE`) is a debug-build-only convenience for contributors and is refused by this release image regardless. See the [production checklist](../deployment/production-checklist.md) for the guard semantics.

### Production Setup

Create `docker-compose.prod.yml`:

```yaml
services:
  egide:
    image: nubster/egide:latest
    container_name: egide
    ports:
      - "8200:8200"
    environment:
      - EGIDE_DATA_DIR=/var/lib/egide
      - RUST_LOG=info
    volumes:
      - egide-data:/var/lib/egide
    healthcheck:
      test: ["CMD", "egide", "status"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 128M

volumes:
  egide-data:
```

Start:

```bash
docker compose -f docker-compose.prod.yml up -d
```

## Configuration

Egide is configured via CLI flags or environment variables only; there is no configuration file (see [Configuration](../getting-started/configuration.md)).

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `EGIDE_DATA_DIR` | Data directory (SQLite database files) | `./data` |
| `EGIDE_DEV_MODE` | Enable dev mode (also requires `EGIDE_UNSAFE_DEV_MODE=1`; refused by release builds, including this image) | `false` |
| `RUST_LOG` | Log filter (e.g. `info`, `info,egide=debug`) | `info,egide=debug` |
| `EGIDE_BIND_ADDRESS` | REST bind address | `0.0.0.0:8200` |
| `EGIDE_GRPC_BIND` | gRPC bind address | `0.0.0.0:8201` |

### Volumes

| Path | Purpose |
|------|---------|
| `/var/lib/egide` | Data storage (SQLite database files) |

## TLS

> **Status: planned, not implemented yet.** Egide does not terminate TLS itself. Put a reverse proxy (Traefik, nginx, Caddy) in front of the container and terminate TLS there.

Generate a self-signed certificate for the reverse proxy in local testing:

```bash
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -subj "/CN=egide.local"
```

### Let's Encrypt with Traefik

```yaml
services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt

  egide:
    image: nubster/egide:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.egide.rule=Host(`egide.example.com`)"
      - "traefik.http.routers.egide.tls.certresolver=letsencrypt"
      - "traefik.http.services.egide.loadbalancer.server.port=8200"
    environment:
      - EGIDE_DATA_DIR=/var/lib/egide
    volumes:
      - egide_data:/var/lib/egide

volumes:
  letsencrypt:
  egide_data:
```

## PostgreSQL Backend

> **Status: planned, not implemented yet.** `egide-server` always uses its bundled SQLite backend today; there is no environment variable or flag that switches it to PostgreSQL, even though the `egide-storage-postgres` crate exists in the workspace. See [Configuration](../getting-started/configuration.md#storage-backend).

## Initialization

### First Start

1. Start Egide:

```bash
docker compose up -d
```

2. Initialize:

```bash
docker exec -it egide egide operator init
```

3. Save the unseal keys and root token securely.

4. Unseal:

```bash
docker exec -it egide egide operator unseal KEY1
docker exec -it egide egide operator unseal KEY2
docker exec -it egide egide operator unseal KEY3
```

### Auto-Unseal Script

Create `init.sh`:

```bash
#!/bin/bash
# Wait for Egide to be ready
until docker exec egide egide status 2>/dev/null | grep -q "Sealed: true"; do
  sleep 1
done

# Unseal with stored keys
docker exec egide egide operator unseal "$UNSEAL_KEY_1"
docker exec egide egide operator unseal "$UNSEAL_KEY_2"
docker exec egide egide operator unseal "$UNSEAL_KEY_3"
```

## Monitoring

### Health Check

```bash
docker exec egide egide status
```

### Logs

```bash
# Follow logs
docker logs -f egide

# JSON logs with jq
docker logs egide | jq .
```

### Prometheus Metrics

> **Status: planned, not implemented yet.** Egide does not expose a `/metrics` endpoint today.

## Backup

### SQLite

The data directory holds one SQLite file per internal engine (for example `system.db`, `transit.db`, and one file per secrets tenant). Back up the whole directory:

```bash
# Stop Egide
docker compose stop egide

# Backup the data directory
docker run --rm \
  -v egide-data:/data \
  -v $(pwd)/backups:/backup \
  alpine \
  sh -c "cp -r /data /backup/egide-$(date +%Y%m%d)"

# Start Egide
docker compose start egide
```

## Upgrade

1. Pull new image:

```bash
docker compose pull
```

2. Restart:

```bash
docker compose up -d
```

3. Unseal (if sealed on restart):

```bash
docker exec egide egide operator unseal KEY1
docker exec egide egide operator unseal KEY2
docker exec egide egide operator unseal KEY3
```

## Next Steps

- [Production Deployment](production.md): Production best practices
- [High Availability](high-availability.md): HA deployment
