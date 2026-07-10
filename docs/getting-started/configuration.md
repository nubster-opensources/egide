# Configuration

Egide is configured through command-line flags and environment variables only.
There is no configuration file: no `--config` flag, no `EGIDE_CONFIG` variable,
and no TOML (or other format) file is parsed anywhere in the codebase.

## Server (`egide-server`)

| Flag | Environment variable | Default | Description |
|------|----------------------|---------|--------------|
| `--data-dir` | `EGIDE_DATA_DIR` | `./data` | Directory for persistent storage (SQLite database files) |
| `--dev` | `EGIDE_DEV_MODE` | disabled | Enable development mode (auto-unseal) |
| `--bind` | `EGIDE_BIND_ADDRESS` | `0.0.0.0:8200` | REST server bind address |
| `--grpc-bind` | `EGIDE_GRPC_BIND` | `0.0.0.0:8201` | gRPC server bind address |

An explicit `--flag` always overrides the corresponding environment variable.

> `--dev` / `EGIDE_DEV_MODE` also requires an explicit `EGIDE_UNSAFE_DEV_MODE=1` opt-in to actually activate, and release builds (including the published Docker image) refuse dev mode categorically regardless of either variable. It stores the master key in cleartext and must never be used outside local development. See [Installation](installation.md#development-mode) and the [production checklist](../deployment/production-checklist.md).

## CLI client (`egide`)

| Flag | Environment variable | Default | Description |
|------|----------------------|---------|--------------|
| `--addr` | `EGIDE_ADDR` | `http://localhost:8200` | Egide server address |
| `--token` | `EGIDE_TOKEN` | none | Authentication token sent with requests |

Example:

```bash
export EGIDE_ADDR="https://egide.internal:8200"
export EGIDE_TOKEN="<token>"
egide status
```

## Storage backend

Egide always uses the bundled SQLite backend today. The data directory
(`--data-dir` / `EGIDE_DATA_DIR`) holds one SQLite database file per internal
engine (for example the seal state and the Transit engine each get their own
file, and secrets are stored per tenant).

The workspace also ships an `egide-storage-postgres` crate (tested as a
library), but `egide-server` does not expose any flag or environment variable
to select it at startup. There is no `EGIDE_STORAGE_TYPE`, `DATABASE_URL`, or
equivalent switch today.

> **Status: planned, not implemented yet.** Wiring the PostgreSQL backend into
> `egide-server` startup, with an explicit storage-selection flag, is on the
> roadmap; no target version is committed. See the [roadmap](../explanation/roadmap.md).

## TLS

> **Status: planned, not implemented yet.** `egide-server` does not terminate
> TLS itself: it binds to a plain HTTP address (`--bind` / `EGIDE_BIND_ADDRESS`
> for REST, `--grpc-bind` / `EGIDE_GRPC_BIND` for gRPC). For production,
> terminate TLS at a reverse proxy or load balancer placed in front of Egide.
> See [Production Deployment](../guides/production.md).

## Next Steps

- [Architecture](../concepts/architecture.md): Understand how Egide works
- [Production Deployment](../guides/production.md): Production best practices
