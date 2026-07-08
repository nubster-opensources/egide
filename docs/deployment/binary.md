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

Create the data directory:

```bash
sudo mkdir -p /var/lib/egide
```

## Configuration

Egide has no configuration file; it is configured through CLI flags or environment variables only (see [Configuration](../getting-started/configuration.md)).

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
Environment=EGIDE_DATA_DIR=/var/lib/egide
Environment=EGIDE_BIND_ADDRESS=0.0.0.0:8200
Environment=EGIDE_GRPC_BIND=0.0.0.0:8201
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/egide-server
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
ReadWritePaths=/var/lib/egide
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
# Unseal Keys (hex):
#   Key 1: xxxx
#   Key 2: xxxx
#   Key 3: xxxx
#   Key 4: xxxx
#   Key 5: xxxx
#
# Unseal Keys (base64):
#   Key 1: xxxx
#   ...
#
# Root Token: xxxxx
#
# IMPORTANT: Save these keys securely!
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

## TLS

> **Status: planned, not implemented yet.** `egide-server` does not terminate TLS itself; it binds to a plain HTTP address (`--bind` / `EGIDE_BIND_ADDRESS`). Terminate TLS with a reverse proxy (nginx, Caddy, Traefik) placed in front of it, using certificates from a trusted CA or your internal PKI:

```bash
# Generate CA and server certificate for the reverse proxy
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key \
  -sha256 -days 3650 -out ca.crt \
  -subj "/CN=Egide CA"

openssl genrsa -out tls.key 2048
openssl req -new -key tls.key \
  -out tls.csr \
  -subj "/CN=egide.example.com"

openssl x509 -req -in tls.csr \
  -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out tls.crt \
  -days 365 -sha256

sudo chmod 600 tls.key
```

## PostgreSQL Setup

> **Status: planned, not implemented yet.** `egide-server` always uses its bundled SQLite backend today; there is no flag or environment variable to point it at PostgreSQL, even though the `egide-storage-postgres` crate exists in the workspace. See [Configuration](../getting-started/configuration.md#storage-backend).

## Firewall

### Allow Port

```bash
# UFW (Ubuntu)
sudo ufw allow 8200/tcp

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-port=8200/tcp
sudo firewall-cmd --reload
```

## Log Management

Egide logs to stdout via `tracing`, filtered by `RUST_LOG` (default `info,egide=debug`). Under systemd, stdout is captured by journald automatically:

```bash
sudo journalctl -u egide -f
```

Configure journald's own retention (`SystemMaxUse=` in `/etc/systemd/journald.conf`) if you need to cap disk usage; Egide does not write its own log files.

## Backup

### SQLite Backup

The data directory holds one SQLite file per internal engine (for example `system.db`, `transit.db`, and one file per secrets tenant). Back up the whole directory:

```bash
# Stop service (recommended)
sudo systemctl stop egide

# Backup the data directory
cp -r /var/lib/egide /backup/egide-$(date +%Y%m%d)

# Restart
sudo systemctl start egide
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
```

### Permission Denied

```bash
sudo chown -R egide:egide /var/lib/egide
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
