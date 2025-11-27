# Installation

This guide covers the different ways to install Egide.

## Requirements

- **Operating System**: Linux (recommended), macOS, or Windows
- **Architecture**: x86_64 (AMD64)
- **Memory**: Minimum 128 MB, recommended 512 MB
- **Disk**: Minimum 100 MB for binaries

## Docker (Recommended)

The easiest way to run Egide is using Docker:

```bash
docker run -d \
  --name egide \
  -p 8200:8200 \
  -v egide-data:/var/lib/egide \
  nubster/egide:latest
```

For development with auto-unseal:

```bash
docker run -d \
  --name egide-dev \
  -p 8200:8200 \
  -e EGIDE_DEV_MODE=true \
  nubster/egide:latest
```

> **Warning**: Never use `EGIDE_DEV_MODE=true` in production. It disables security features.

## Docker Compose

Create a `docker-compose.yml`:

```yaml
services:
  egide:
    image: nubster/egide:latest
    ports:
      - "8200:8200"
    volumes:
      - egide-data:/var/lib/egide
      - ./config:/etc/egide:ro
    environment:
      - EGIDE_CONFIG=/etc/egide/egide.toml
    restart: unless-stopped

volumes:
  egide-data:
```

Then run:

```bash
docker compose up -d
```

## Binary Installation

### Download

Download the latest release from [GitHub Releases](https://github.com/nubster-opensources/egide/releases):

```bash
# Linux (AMD64)
curl -LO https://github.com/nubster-opensources/egide/releases/latest/download/egide-linux-amd64.tar.gz
tar xzf egide-linux-amd64.tar.gz
sudo mv egide egide-server /usr/local/bin/
```

### Verify Installation

```bash
egide --version
egide-server --version
```

## Build from Source

### Prerequisites

- Rust 1.79 or later
- Git

### Build

```bash
git clone https://github.com/nubster-opensources/egide.git
cd egide
cargo build --release
```

Binaries will be available in `target/release/`:
- `egide-server` — The server binary
- `egide` — The CLI tool

### Install

```bash
sudo cp target/release/egide-server /usr/local/bin/
sudo cp target/release/egide /usr/local/bin/
```

## Next Steps

- [Quick Start](quick-start.md) — Initialize and start using Egide
- [Configuration](configuration.md) — Configure Egide for your environment
