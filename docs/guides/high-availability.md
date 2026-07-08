# High Availability

This guide covers deploying Egide in a highly available configuration.

> **Status: planned, not implemented yet.** Multi-instance HA needs a storage backend shared across instances. `egide-server` always uses its bundled SQLite backend today (one file per node); the `egide-storage-postgres` crate exists in the workspace but is not wired into the server's startup yet (no flag or environment variable selects it). This page describes the target architecture. See [Configuration](../getting-started/configuration.md#storage-backend).

## Overview

Egide's planned high availability model relies on:

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

All instances would use the same flags and environment variables (see [Configuration](../getting-started/configuration.md)):

```bash
EGIDE_BIND_ADDRESS=0.0.0.0:8200
EGIDE_GRPC_BIND=0.0.0.0:8201
RUST_LOG=info
```

TLS is terminated at the load balancer, not by Egide (see [Production Deployment](production.md#tls)). PostgreSQL connection settings (`host`, `port`, `database`, credentials) have no environment variable today, since the backend is not yet selectable at runtime.

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
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
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
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
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
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
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

Always responds `200 OK`; the HTTP status code does not vary with seal or initialization state today. Inspect the JSON body's `sealed` and `initialized` fields to distinguish an unsealed-and-ready instance from a sealed one:

```json
{"status": "ok", "initialized": true, "sealed": false, "version": "0.1.0", "uptime_secs": 42}
```

### Health Check Script

```bash
#!/bin/bash
body=$(curl -s https://egide:8200/v1/sys/health)
sealed=$(echo "$body" | jq -r .sealed)
if [ "$sealed" = "false" ]; then
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

- [Backup & Recovery](backup.md): Backup strategies
- [Production Deployment](production.md): Production best practices
