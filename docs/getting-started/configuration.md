# Configuration

Egide is configured via a TOML file and environment variables.

## Configuration File

By default, Egide looks for configuration in:
1. Path specified by `--config` flag
2. `EGIDE_CONFIG` environment variable
3. `/etc/egide/egide.toml`
4. `./egide.toml`

### Example Configuration

```toml
# Server settings
[server]
bind = "0.0.0.0:8200"
tls_enabled = true
tls_cert_file = "/etc/egide/tls/server.crt"
tls_key_file = "/etc/egide/tls/server.key"

# Storage backend
[storage]
backend = "sqlite"

[storage.sqlite]
path = "/var/lib/egide/egide.db"

# Seal configuration
[seal]
type = "shamir"

[seal.shamir]
shares = 5
threshold = 3

# Logging
[logging]
level = "info"
format = "json"
output = "stdout"

# Telemetry
[telemetry]
metrics_enabled = true
metrics_path = "/metrics"

# Resource limits
[limits]
max_request_size = 1048576
request_timeout = 30
max_connections = 1000
```

## Configuration Reference

### Server

| Parameter | Description | Default |
|-----------|-------------|---------|
| `bind` | Address and port to bind | `0.0.0.0:8200` |
| `tls_enabled` | Enable TLS | `false` |
| `tls_cert_file` | Path to TLS certificate | - |
| `tls_key_file` | Path to TLS private key | - |
| `dev_mode` | Enable development mode | `false` |

### Storage

| Parameter | Description | Default |
|-----------|-------------|---------|
| `backend` | Storage backend (`sqlite`, `postgres`) | `sqlite` |

#### SQLite

| Parameter | Description | Default |
|-----------|-------------|---------|
| `path` | Database file path | `/var/lib/egide/egide.db` |

#### PostgreSQL

| Parameter | Description | Default |
|-----------|-------------|---------|
| `host` | Database host | `localhost` |
| `port` | Database port | `5432` |
| `database` | Database name | `egide` |
| `username` | Database user | - |
| `password` | Database password | - |
| `ssl_mode` | SSL mode (`disable`, `prefer`, `require`) | `prefer` |

### Seal

| Parameter | Description | Default |
|-----------|-------------|---------|
| `type` | Seal type (`shamir`) | `shamir` |

#### Shamir

| Parameter | Description | Default |
|-----------|-------------|---------|
| `shares` | Number of key shares | `5` |
| `threshold` | Shares required to unseal | `3` |

### Logging

| Parameter | Description | Default |
|-----------|-------------|---------|
| `level` | Log level (`trace`, `debug`, `info`, `warn`, `error`) | `info` |
| `format` | Log format (`json`, `pretty`) | `json` |
| `output` | Log output (`stdout`, `stderr`, or file path) | `stdout` |

### Telemetry

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics_enabled` | Enable Prometheus metrics | `true` |
| `metrics_path` | Metrics endpoint path | `/metrics` |

### Limits

| Parameter | Description | Default |
|-----------|-------------|---------|
| `max_request_size` | Maximum request body size (bytes) | `1048576` (1 MB) |
| `request_timeout` | Request timeout (seconds) | `30` |
| `max_connections` | Maximum concurrent connections | `1000` |

## Environment Variables

All configuration options can be set via environment variables:

| Variable | Description |
|----------|-------------|
| `EGIDE_CONFIG` | Path to configuration file |
| `EGIDE_DEV_MODE` | Enable development mode (`true`/`false`) |
| `EGIDE_BIND_ADDRESS` | Server bind address |
| `EGIDE_LOG_LEVEL` | Log level |
| `EGIDE_STORAGE_BACKEND` | Storage backend |

Environment variables take precedence over the configuration file.

## TLS Configuration

For production, always enable TLS:

```toml
[server]
tls_enabled = true
tls_cert_file = "/etc/egide/tls/server.crt"
tls_key_file = "/etc/egide/tls/server.key"
```

Generate a self-signed certificate for testing:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=egide.local"
```

For production, use certificates from your PKI or a trusted CA.

## Next Steps

- [Architecture](../concepts/architecture.md) — Understand how Egide works
- [Production Deployment](../guides/production.md) — Production best practices
