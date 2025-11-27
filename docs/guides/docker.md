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
      - EGIDE_DEV_MODE=true
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
      - EGIDE_CONFIG=/etc/egide/egide.toml
      - EGIDE_LOG_LEVEL=info
    volumes:
      - egide-data:/var/lib/egide
      - egide-logs:/var/log/egide
      - ./config:/etc/egide:ro
      - ./certs:/etc/egide/tls:ro
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
  egide-logs:
```

Start:

```bash
docker compose -f docker-compose.prod.yml up -d
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `EGIDE_CONFIG` | Config file path | `/etc/egide/egide.toml` |
| `EGIDE_DEV_MODE` | Enable dev mode | `false` |
| `EGIDE_LOG_LEVEL` | Log level | `info` |
| `EGIDE_BIND_ADDRESS` | Bind address | `0.0.0.0:8200` |

### Volumes

| Path | Purpose |
|------|---------|
| `/var/lib/egide` | Data storage (SQLite database) |
| `/var/log/egide` | Log files |
| `/etc/egide` | Configuration files |
| `/etc/egide/tls` | TLS certificates |

### Configuration File

Mount a configuration file:

```yaml
volumes:
  - ./egide.toml:/etc/egide/egide.toml:ro
```

Example `egide.toml`:

```toml
[server]
bind = "0.0.0.0:8200"
tls_enabled = true
tls_cert_file = "/etc/egide/tls/server.crt"
tls_key_file = "/etc/egide/tls/server.key"

[storage]
backend = "sqlite"

[storage.sqlite]
path = "/var/lib/egide/egide.db"

[logging]
level = "info"
format = "json"
```

## TLS Configuration

### Self-Signed Certificate

Generate certificates:

```bash
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -subj "/CN=egide.local"
```

Mount certificates:

```yaml
volumes:
  - ./certs:/etc/egide/tls:ro
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
      - EGIDE_CONFIG=/etc/egide/egide.toml

volumes:
  letsencrypt:
```

## PostgreSQL Backend

For production, use PostgreSQL:

```yaml
services:
  egide:
    image: nubster/egide:latest
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      - EGIDE_STORAGE_BACKEND=postgres
      - EGIDE_POSTGRES_HOST=postgres
      - EGIDE_POSTGRES_DATABASE=egide
      - EGIDE_POSTGRES_USERNAME=egide
      - EGIDE_POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=egide
      - POSTGRES_USER=egide
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U egide"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres-data:
```

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

Egide exposes metrics at `/metrics`:

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  egide:
    # ... existing config
```

`prometheus.yml`:

```yaml
scrape_configs:
  - job_name: egide
    static_configs:
      - targets: ['egide:8200']
```

## Backup

### SQLite

```bash
# Stop Egide
docker compose stop egide

# Backup database
docker run --rm \
  -v egide-data:/data \
  -v $(pwd)/backups:/backup \
  alpine \
  cp /data/egide.db /backup/egide-$(date +%Y%m%d).db

# Start Egide
docker compose start egide
```

### PostgreSQL

```bash
docker exec postgres pg_dump -U egide egide > backup.sql
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

- [Production Deployment](production.md) — Production best practices
- [High Availability](high-availability.md) — HA deployment
