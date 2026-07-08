# Docker Compose Deployment

Production-ready deployment with Docker Compose.

## Quick Start

### Basic Setup

Create `docker-compose.yml`:

```yaml
services:
  egide:
    image: nubster/egide:latest
    container_name: egide
    restart: unless-stopped
    ports:
      - "8200:8200"
    volumes:
      - egide_data:/var/lib/egide
    environment:
      - EGIDE_DATA_DIR=/var/lib/egide
      - RUST_LOG=info
    healthcheck:
      test: ["CMD", "egide", "status"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  egide_data:
```

```bash
docker compose up -d
```

## Production Setup with PostgreSQL

> **Status: planned, not implemented yet.** `egide-server` always uses its bundled SQLite backend today; there is no environment variable or configuration file to switch it to PostgreSQL, even though the `egide-storage-postgres` crate exists in the workspace and is unit-tested. See [Configuration](../getting-started/configuration.md#storage-backend). The compose file below shows the target shape for when runtime storage selection ships.

### docker-compose.yml

```yaml
services:
  egide:
    image: nubster/egide:latest
    container_name: egide
    restart: unless-stopped
    ports:
      - "8200:8200"
    volumes:
      - egide_data:/var/lib/egide
    environment:
      - EGIDE_DATA_DIR=/var/lib/egide
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "egide", "status"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:16-alpine
    container_name: egide-postgres
    restart: unless-stopped
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-db.sql:/docker-entrypoint-initdb.d/init.sql:ro
    environment:
      - POSTGRES_USER=egide
      - POSTGRES_PASSWORD=${EGIDE_DB_PASSWORD}
      - POSTGRES_DB=egide
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U egide"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  egide_data:
  postgres_data:
```

### .env

```env
EGIDE_DB_PASSWORD=your-secure-password-here
```

### init-db.sql

```sql
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE egide TO egide;
```

## With TLS (Let's Encrypt)

### Using Traefik

```yaml
services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    restart: unless-stopped
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt

  egide:
    image: nubster/egide:latest
    container_name: egide
    restart: unless-stopped
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.egide.rule=Host(`egide.example.com`)"
      - "traefik.http.routers.egide.entrypoints=websecure"
      - "traefik.http.routers.egide.tls.certresolver=letsencrypt"
      - "traefik.http.services.egide.loadbalancer.server.port=8200"
    volumes:
      - egide_data:/var/lib/egide
    environment:
      - EGIDE_DATA_DIR=/var/lib/egide
    depends_on:
      - traefik

volumes:
  egide_data:
  letsencrypt:
```

## High Availability Setup

> **Status: planned, not implemented yet.** Multiple Egide instances sharing one datastore requires the PostgreSQL backend to be wired into `egide-server`, which is not the case today (see [Configuration](../getting-started/configuration.md#storage-backend)). The compose file below shows the target shape.

### Multi-instance with Load Balancer

```yaml
services:
  nginx:
    image: nginx:alpine
    container_name: egide-lb
    restart: unless-stopped
    ports:
      - "8200:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - egide-1
      - egide-2

  egide-1:
    image: nubster/egide:latest
    container_name: egide-1
    restart: unless-stopped
    environment:
      - EGIDE_DB_PASSWORD=${EGIDE_DB_PASSWORD}
    depends_on:
      - postgres

  egide-2:
    image: nubster/egide:latest
    container_name: egide-2
    restart: unless-stopped
    environment:
      - EGIDE_DB_PASSWORD=${EGIDE_DB_PASSWORD}
    depends_on:
      - postgres

  postgres:
    image: postgres:16-alpine
    container_name: egide-postgres
    restart: unless-stopped
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=egide
      - POSTGRES_PASSWORD=${EGIDE_DB_PASSWORD}
      - POSTGRES_DB=egide

volumes:
  postgres_data:
```

### nginx.conf

```nginx
events {
    worker_connections 1024;
}

http {
    upstream egide {
        least_conn;
        server egide-1:8200;
        server egide-2:8200;
    }

    server {
        listen 80;

        location / {
            proxy_pass http://egide;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /v1/sys/health {
            proxy_pass http://egide;
            proxy_connect_timeout 5s;
            proxy_read_timeout 5s;
        }
    }
}
```

## Operations

### Start

```bash
docker compose up -d
```

### Stop

```bash
docker compose down
```

### View Logs

```bash
docker compose logs -f egide
```

### Initialize (First Time)

```bash
docker compose exec egide egide operator init
```

### Unseal (After Restart)

```bash
docker compose exec egide egide operator unseal
```

### Backup

```bash
# PostgreSQL (once the backend is wired in, see above)
docker compose exec postgres pg_dump -U egide egide > backup.sql

# SQLite (the backend used today): copy the data directory
docker compose stop egide
docker compose cp egide:/var/lib/egide ./backup/
docker compose start egide
```

### Upgrade

```bash
# Pull new images
docker compose pull

# Recreate containers
docker compose up -d

# Unseal
docker compose exec egide egide operator unseal
```

## Monitoring

> **Status: planned, not implemented yet.** Egide does not expose a Prometheus metrics endpoint today. Until it does, monitor the `GET /v1/sys/health` endpoint and the container's `tracing` logs.

## Security Hardening

### Read-only Root Filesystem

```yaml
services:
  egide:
    image: nubster/egide:latest
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - egide_data:/var/lib/egide
```

### Non-root User

The official image runs as non-root by default (UID 1000).

### Network Isolation

```yaml
services:
  egide:
    networks:
      - frontend
      - backend

  postgres:
    networks:
      - backend

networks:
  frontend:
  backend:
    internal: true
```

## Next Steps

- [Kubernetes Deployment](./kubernetes.md)
- [Production Checklist](./production-checklist.md)
- [High Availability Guide](../guides/high-availability.md)
