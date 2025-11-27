# Binary Installation

Install Egide directly from release binaries for bare metal or custom deployments.

## Download

### Linux (x86_64)

```bash
# Download latest release
curl -LO https://github.com/nubster-opensources/egide/releases/latest/download/egide-linux-amd64.tar.gz

# Verify checksum
curl -LO https://github.com/nubster-opensources/egide/releases/latest/download/checksums.txt
sha256sum -c checksums.txt --ignore-missing

# Extract
tar -xzf egide-linux-amd64.tar.gz

# Move to PATH
sudo mv egide-server egide /usr/local/bin/
```

### macOS

```bash
# Intel
curl -LO https://github.com/nubster-opensources/egide/releases/latest/download/egide-darwin-amd64.tar.gz

# Apple Silicon
curl -LO https://github.com/nubster-opensources/egide/releases/latest/download/egide-darwin-arm64.tar.gz

# Extract and install
tar -xzf egide-darwin-*.tar.gz
sudo mv egide-server egide /usr/local/bin/
```

### Windows

```powershell
# Download
Invoke-WebRequest -Uri "https://github.com/nubster-opensources/egide/releases/latest/download/egide-windows-amd64.zip" -OutFile "egide.zip"

# Extract
Expand-Archive -Path "egide.zip" -DestinationPath "C:\egide"

# Add to PATH
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\egide", "Machine")
```

## Directory Structure

Create the directory structure:

```bash
sudo mkdir -p /etc/egide
sudo mkdir -p /var/lib/egide
sudo mkdir -p /var/log/egide
```

## Configuration

### /etc/egide/egide.toml

```toml
[server]
bind_address = "0.0.0.0:8200"
tls_enabled = false

[storage]
type = "sqlite"

[storage.sqlite]
path = "/var/lib/egide/egide.db"
journal_mode = "WAL"

[log]
level = "info"
format = "text"
file = "/var/log/egide/egide.log"
```

## Systemd Service

### /etc/systemd/system/egide.service

```ini
[Unit]
Description=Egide Secrets Manager
Documentation=https://egide.nubster.com/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=egide
Group=egide
ExecStart=/usr/local/bin/egide-server --config /etc/egide/egide.toml
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitMEMLOCK=infinity

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/egide /var/log/egide
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
# Create user
sudo useradd --system --home /var/lib/egide --shell /bin/false egide

# Set permissions
sudo chown -R egide:egide /var/lib/egide
sudo chown -R egide:egide /var/log/egide
sudo chown -R egide:egide /etc/egide

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable egide
sudo systemctl start egide

# Check status
sudo systemctl status egide
```

## Initialize and Unseal

### Initialize

```bash
egide operator init

# Output:
# Unseal Key 1: xxxx
# Unseal Key 2: xxxx
# Unseal Key 3: xxxx
# Unseal Key 4: xxxx
# Unseal Key 5: xxxx
#
# Initial Root Token: s.xxxxx
#
# Store these keys securely!
```

### Unseal

```bash
# Requires 3 of 5 keys by default
egide operator unseal
# Enter key 1

egide operator unseal
# Enter key 2

egide operator unseal
# Enter key 3

# Server is now unsealed
```

### Auto-Unseal Script

For automated environments (use with caution):

```bash
#!/bin/bash
# /usr/local/bin/egide-unseal.sh

UNSEAL_KEYS=(
  "key1"
  "key2"
  "key3"
)

for key in "${UNSEAL_KEYS[@]}"; do
  egide operator unseal "$key"
done
```

## TLS Configuration

### Generate Certificates

```bash
# Generate CA
openssl genrsa -out /etc/egide/ca.key 4096
openssl req -x509 -new -nodes -key /etc/egide/ca.key \
  -sha256 -days 3650 -out /etc/egide/ca.crt \
  -subj "/CN=Egide CA"

# Generate server certificate
openssl genrsa -out /etc/egide/tls.key 2048
openssl req -new -key /etc/egide/tls.key \
  -out /etc/egide/tls.csr \
  -subj "/CN=egide.example.com"

# Sign certificate
openssl x509 -req -in /etc/egide/tls.csr \
  -CA /etc/egide/ca.crt -CAkey /etc/egide/ca.key \
  -CAcreateserial -out /etc/egide/tls.crt \
  -days 365 -sha256

# Set permissions
sudo chown egide:egide /etc/egide/*.key
sudo chmod 600 /etc/egide/*.key
```

### Update Configuration

```toml
[server]
bind_address = "0.0.0.0:8200"
tls_enabled = true
tls_cert = "/etc/egide/tls.crt"
tls_key = "/etc/egide/tls.key"
```

## PostgreSQL Setup

### Install PostgreSQL

```bash
# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib

# RHEL/CentOS
sudo dnf install postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl start postgresql
```

### Create Database

```bash
sudo -u postgres psql << EOF
CREATE USER egide WITH PASSWORD 'secure-password';
CREATE DATABASE egide OWNER egide;
GRANT ALL PRIVILEGES ON DATABASE egide TO egide;
\c egide
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EOF
```

### Update Configuration

```toml
[storage]
type = "postgresql"

[storage.postgresql]
host = "localhost"
port = 5432
database = "egide"
username = "egide"
password_env = "EGIDE_DB_PASSWORD"
```

### Set Environment Variable

```bash
# Add to /etc/environment or systemd service
EGIDE_DB_PASSWORD=secure-password
```

## Firewall

### Allow Port

```bash
# UFW (Ubuntu)
sudo ufw allow 8200/tcp

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-port=8200/tcp
sudo firewall-cmd --reload
```

## Log Rotation

### /etc/logrotate.d/egide

```
/var/log/egide/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 egide egide
    postrotate
        systemctl reload egide > /dev/null 2>&1 || true
    endscript
}
```

## Backup

### SQLite Backup

```bash
# Stop service (recommended)
sudo systemctl stop egide

# Backup database
cp /var/lib/egide/egide.db /backup/egide-$(date +%Y%m%d).db

# Restart
sudo systemctl start egide
```

### PostgreSQL Backup

```bash
pg_dump -U egide egide > /backup/egide-$(date +%Y%m%d).sql
```

## Upgrade

```bash
# Download new version
curl -LO https://github.com/nubster-opensources/egide/releases/download/v0.2.0/egide-linux-amd64.tar.gz

# Stop service
sudo systemctl stop egide

# Backup current binaries
sudo mv /usr/local/bin/egide-server /usr/local/bin/egide-server.bak
sudo mv /usr/local/bin/egide /usr/local/bin/egide.bak

# Install new version
tar -xzf egide-linux-amd64.tar.gz
sudo mv egide-server egide /usr/local/bin/

# Start service
sudo systemctl start egide

# Unseal
egide operator unseal
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u egide -f

# Check permissions
ls -la /var/lib/egide
ls -la /etc/egide
```

### Permission Denied

```bash
sudo chown -R egide:egide /var/lib/egide
sudo chown -R egide:egide /etc/egide
sudo chmod 600 /etc/egide/*.key
```

### Port Already in Use

```bash
# Find process using port
sudo lsof -i :8200

# Kill or change port in config
```

## Next Steps

- [Production Checklist](./production-checklist.md)
- [Backup & Recovery](../guides/backup.md)
- [High Availability](../guides/high-availability.md)
