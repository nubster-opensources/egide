# Backup & Recovery

This guide covers backup strategies and disaster recovery for Egide.

## What to Backup

| Component | Location | Backup Method |
|-----------|----------|---------------|
| **Data directory** | `/var/lib/egide` (`--data-dir` / `EGIDE_DATA_DIR`), SQLite files today | Directory copy |
| **Unseal Keys** | Offline storage | Secure vault |

Egide has no configuration file and does not terminate TLS itself (see [Configuration](../getting-started/configuration.md)), so there is nothing to back up under those headings. PostgreSQL as a backend is planned, not implemented yet (see [Configuration](../getting-started/configuration.md#storage-backend)); the PostgreSQL sections below describe the target procedure once it ships.

## Backup Procedures

### SQLite Backup (the backend used today)

The data directory holds one SQLite file per internal engine (for example `system.db`, `transit.db`, and one file per secrets tenant).

#### Online Backup

```bash
# Backup each database file individually with the SQLite backup command
for db in /var/lib/egide/*.db; do
  sqlite3 "$db" ".backup '/backup/$(basename "$db" .db)-$(date +%Y%m%d).db'"
done
```

#### Docker Volume Backup

```bash
# Stop Egide (for consistency)
docker compose stop egide

# Backup volume
docker run --rm \
  -v egide-data:/data:ro \
  -v $(pwd)/backups:/backup \
  alpine \
  tar czf /backup/egide-data-$(date +%Y%m%d).tar.gz -C /data .

# Start Egide
docker compose start egide
```

### PostgreSQL Backup

> **Status: planned, not implemented yet.** See the note at the top of this page.

#### pg_dump

```bash
# Full backup
pg_dump -h postgres -U egide -d egide > backup-$(date +%Y%m%d).sql

# Compressed backup
pg_dump -h postgres -U egide -d egide | gzip > backup-$(date +%Y%m%d).sql.gz
```

#### Docker

```bash
docker exec postgres pg_dump -U egide egide > backup-$(date +%Y%m%d).sql
```

#### Continuous Archiving

For point-in-time recovery, configure WAL archiving:

```sql
ALTER SYSTEM SET archive_mode = on;
ALTER SYSTEM SET archive_command = 'cp %p /backup/wal/%f';
```

### Unseal Keys

Store unseal keys securely:

1. **Split custody**: Different keys to different people
2. **Secure storage**: Hardware security module (HSM) or secure vault
3. **Encrypted storage**: Encrypt keys at rest
4. **Geographic distribution**: Store in different locations
5. **Documentation**: Document key holders and recovery process

## Automated Backups

### Cron Job

```bash
# /etc/cron.d/egide-backup
0 2 * * * root /opt/egide/backup.sh
```

### Backup Script

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/backup/egide"
DATE=$(date +%Y%m%d)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup the data directory (SQLite, the backend used today)
tar czf "$BACKUP_DIR/data-$DATE.tar.gz" /var/lib/egide

# Remove old backups
find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete

# Verify backup
if [ -f "$BACKUP_DIR/data-$DATE.tar.gz" ]; then
  echo "Backup completed successfully"
else
  echo "Backup failed" >&2
  exit 1
fi
```

## Restore Procedures

### SQLite Restore

```bash
# Stop Egide
docker compose stop egide

# Restore the data directory
docker run --rm \
  -v egide-data:/data \
  -v $(pwd)/backups:/backup:ro \
  alpine \
  sh -c "rm -rf /data/* && cp -r /backup/egide-data-20250115/. /data/"

# Start Egide
docker compose start egide

# Unseal
egide operator unseal KEY1
egide operator unseal KEY2
egide operator unseal KEY3
```

### PostgreSQL Restore

> **Status: planned, not implemented yet.** See the note at the top of this page.

```bash
# Drop and recreate database
psql -h postgres -U postgres -c "DROP DATABASE IF EXISTS egide;"
psql -h postgres -U postgres -c "CREATE DATABASE egide OWNER egide;"

# Restore
gunzip -c backup-20250115.sql.gz | psql -h postgres -U egide -d egide

# Restart Egide
docker compose restart egide

# Unseal all instances
```

## Disaster Recovery

### Recovery Plan

1. **Assess damage**: Determine what was lost
2. **Provision infrastructure**: Deploy new servers/containers
3. **Restore database**: From most recent backup
4. **Restore configuration**: From backup or version control
5. **Deploy Egide**: Start Egide instances
6. **Unseal**: Unseal with stored keys
7. **Verify**: Test functionality
8. **Update DNS**: Point to new deployment

### Recovery Time Objectives

| Component | RTO | RPO |
|-----------|-----|-----|
| Single instance failure | < 5 min | 0 (HA) |
| Database failure | < 15 min | < 1 hour |
| Complete cluster failure | < 1 hour | Last backup |
| Data center failure | < 4 hours | Last offsite backup |

### Testing Recovery

Regularly test your recovery procedures:

1. **Monthly**: Test backup restoration to staging
2. **Quarterly**: Full disaster recovery drill
3. **Annually**: Review and update procedures

## Backup Storage

### Local Storage

- Fast recovery
- Risk of loss with server failure
- Use for short-term retention

### Remote Storage

- Protection against local failures
- Higher latency for recovery
- Use for long-term retention

### Cloud Storage

```bash
# Upload to S3-compatible storage
aws s3 cp backup-20250115.sql.gz s3://egide-backups/

# Upload to Azure Blob
az storage blob upload --file backup-20250115.sql.gz \
  --container-name egide-backups \
  --name backup-20250115.sql.gz
```

### Encryption

Always encrypt backups:

```bash
# Encrypt backup
gpg --symmetric --cipher-algo AES256 backup-20250115.sql.gz

# Decrypt backup
gpg --decrypt backup-20250115.sql.gz.gpg > backup-20250115.sql.gz
```

## Verification

### Backup Verification

```bash
# Verify PostgreSQL backup
gunzip -c backup.sql.gz | head -n 100

# Verify SQLite backup
sqlite3 backup.db "SELECT count(*) FROM kv_store;"
```

### Restore Verification

After restoration:

1. Check Egide status: `egide status`
2. List secrets: `egide secrets list`
3. Test read/write: Create and retrieve a test secret

## Next Steps

- [Production Deployment](production.md): Production best practices
- [High Availability](high-availability.md): HA deployment
