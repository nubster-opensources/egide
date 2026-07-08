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

The published image is a release build. It always starts sealed and refuses dev mode by design: initialize and unseal it with the CLI or the REST API (see the [Quick Start](quick-start.md)).

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
- `egide-server`: the server binary
- `egide`: the CLI tool

### Install

```bash
sudo cp target/release/egide-server /usr/local/bin/
sudo cp target/release/egide /usr/local/bin/
```

### Development Mode

For local development against a debug build (not the published Docker image, which is always a release build), dev mode auto-unseals with the master key stored in cleartext. It requires an explicit opt-in and is refused entirely in release builds:

```bash
EGIDE_UNSAFE_DEV_MODE=1 cargo run -p egide-server -- --dev
```

Never set `EGIDE_UNSAFE_DEV_MODE` outside local development.

## Next Steps

- [Quick Start](quick-start.md): Initialize and start using Egide
- [Configuration](configuration.md): Configure Egide for your environment
