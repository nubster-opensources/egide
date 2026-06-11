# High Availability

This guide covers deploying Egide in a highly available configuration.

## Overview

Egide supports high availability through:

1. **Stateless deployment** with external PostgreSQL
2. **Multiple instances** behind a load balancer
3. **Database replication** for data redundancy

## Architecture

```text
                         ┌──────────────────┐
                         │  Load Balancer   │
                         │  (HAProxy/NGINX) │
                         └────────┬─────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
       ┌────▼─────┐          ┌────▼─────┐          ┌────▼─────┐
       │ Egide 1  │          │ Egide 2  │          │ Egide 3  │
       │ (Active) │          │ (Active) │          │ (Active) │
       └────┬─────┘          └────┬─────┘          └────┬─────┘
            │                     │                     │
            └─────────────────────┼─────────────────────┘
                                  │
                         ┌────────▼────────┐
                         │   PostgreSQL    │
                         │    Primary      │
                         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │   PostgreSQL    │
                         │    Replica      │
                         └─────────────────┘
```

## Requirements

- PostgreSQL 16+ (primary + replica)
- Load balancer (HAProxy, NGINX, or cloud LB)
- Shared storage for configuration (optional)
- 3+ Egide instances (recommended)

## PostgreSQL Setup

### Primary

```sql
-- Create database
CREATE DATABASE egide;

-- Create user
CREATE USER egide WITH PASSWORD 'secure-password';
GRANT ALL PRIVILEGES ON DATABASE egide TO egide;

-- Enable replication
ALTER SYSTEM SET wal_level = replica;
ALTER SYSTEM SET max_wal_senders = 3;
```

### Replica

Configure streaming replication to the replica for failover.

## Egide Configuration

All instances use the same configuration:

```toml
[server]
bind = "0.0.0.0:8200"
tls_enabled = true
tls_cert_file = "/etc/egide/tls/server.crt"
tls_key_file = "/etc/egide/tls/server.key"

[storage]
backend = "postgres"

[storage.postgres]
host = "postgres-primary.internal"
port = 5432
database = "egide"
username = "egide"
password = "${POSTGRES_PASSWORD}"
ssl_mode = "require"
# Connection pool
max_connections = 20
min_connections = 5

[logging]
level = "info"
format = "json"
```

## Load Balancer

### HAProxy

```haproxy
frontend egide_front
    bind *:443 ssl crt /etc/haproxy/certs/egide.pem
    default_backend egide_back

backend egide_back
    balance roundrobin
    option httpchk GET /v1/sys/health
    http-check expect status 200

    server egide1 10.0.1.10:8200 check ssl verify none
    server egide2 10.0.1.11:8200 check ssl verify none
    server egide3 10.0.1.12:8200 check ssl verify none
```

### NGINX

```nginx
upstream egide {
    least_conn;
    server 10.0.1.10:8200 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8200 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8200 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl;
    server_name egide.example.com;

    ssl_certificate /etc/nginx/certs/egide.crt;
    ssl_certificate_key /etc/nginx/certs/egide.key;

    location / {
        proxy_pass https://egide;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /v1/sys/health {
        proxy_pass https://egide;
        proxy_ssl_verify off;
    }
}
```

## Docker Compose (HA)

```yaml
services:
  egide1:
    image: nubster/egide:latest
    hostname: egide1
    environment:
      - EGIDE_CONFIG=/etc/egide/egide.toml
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - ./config:/etc/egide:ro
      - ./certs:/etc/egide/tls:ro
    networks:
      - egide-net
    deploy:
      replicas: 1
      resources:
        limits:
          cpus: '1'
          memory: 512M

  egide2:
    image: nubster/egide:latest
    hostname: egide2
    environment:
      - EGIDE_CONFIG=/etc/egide/egide.toml
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - ./config:/etc/egide:ro
      - ./certs:/etc/egide/tls:ro
    networks:
      - egide-net
    deploy:
      replicas: 1
      resources:
        limits:
          cpus: '1'
          memory: 512M

  egide3:
    image: nubster/egide:latest
    hostname: egide3
    environment:
      - EGIDE_CONFIG=/etc/egide/egide.toml
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - ./config:/etc/egide:ro
      - ./certs:/etc/egide/tls:ro
    networks:
      - egide-net
    deploy:
      replicas: 1
      resources:
        limits:
          cpus: '1'
          memory: 512M

  haproxy:
    image: haproxy:2.8
    ports:
      - "443:443"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
      - ./certs:/etc/haproxy/certs:ro
    networks:
      - egide-net
    depends_on:
      - egide1
      - egide2
      - egide3

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=egide
      - POSTGRES_USER=egide
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - egide-net

networks:
  egide-net:

volumes:
  postgres-data:
```

## Unsealing in HA

When Egide restarts, each instance needs to be unsealed:

### Manual Unseal

```bash
# Unseal each instance
for host in egide1 egide2 egide3; do
  egide --addr "https://$host:8200" operator unseal KEY1
  egide --addr "https://$host:8200" operator unseal KEY2
  egide --addr "https://$host:8200" operator unseal KEY3
done
```

### Auto-Unseal (Future Feature)

Auto-unseal with external KMS is planned for future releases.

## Health Checks

### Endpoint

`GET /v1/sys/health`

### Response Codes

| Code | Status |
|------|--------|
| 200 | Unsealed, active |
| 429 | Unsealed, standby |
| 472 | Disaster recovery standby |
| 473 | Performance standby |
| 501 | Not initialized |
| 503 | Sealed |

### Health Check Script

```bash
#!/bin/bash
response=$(curl -s -o /dev/null -w "%{http_code}" https://egide:8200/v1/sys/health)
if [ "$response" = "200" ]; then
  exit 0
else
  exit 1
fi
```

## Failover Scenarios

### Instance Failure

1. Load balancer detects failed health check
2. Traffic routed to healthy instances
3. Replace failed instance
4. Unseal new instance

### Database Failover

1. Primary PostgreSQL fails
2. Promote replica to primary
3. Update Egide configuration (or use DNS)
4. Egide reconnects automatically

### Complete Cluster Failure

1. Restore PostgreSQL from backup
2. Deploy Egide instances
3. Unseal all instances
4. Verify data integrity

## Monitoring HA

### Metrics to Monitor

- Number of healthy instances
- Request distribution across instances
- Database connection pool usage
- Replication lag (PostgreSQL)

### Alerts

- Instance count below threshold
- Health check failures
- Database connection errors
- High replication lag

## Next Steps

- [Backup & Recovery](backup.md) — Backup strategies
- [Production Deployment](production.md) — Production best practices
