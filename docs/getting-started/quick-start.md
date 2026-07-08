# Quick Start

Get Egide up and running in 5 minutes.

## 1. Start the Server

Start Egide with a persistent volume. The published image is a release build, so it always starts sealed: dev mode is refused by design and cannot be enabled on it.

```bash
docker run -d \
  --name egide \
  -p 8200:8200 \
  -v egide-data:/var/lib/egide \
  nubster/egide:latest
```

> Dev mode is a development convenience for contributors running a debug build locally, not something available on this image. It stores the master key in cleartext and needs an explicit `EGIDE_UNSAFE_DEV_MODE=1` opt-in even then: `EGIDE_UNSAFE_DEV_MODE=1 cargo run -p egide-server -- --dev`. See [Installation](installation.md#build-from-source) for building from source.

## 2. Initialize Egide

First time only, initialize Egide to generate unseal keys:

```bash
egide operator init
```

This outputs:

- **Unseal Keys**: keep these safe! You need them to unseal Egide after restart.
- **Root Token**: initial admin token. Revoke after creating other tokens.

Example output:

```text
Unseal Key 1: AAAA...
Unseal Key 2: BBBB...
Unseal Key 3: CCCC...
Unseal Key 4: DDDD...
Unseal Key 5: EEEE...

Initial Root Token: s.XXXX...

Egide initialized with 5 key shares and a threshold of 3.
```

## 3. Unseal Egide

Egide starts sealed. Unseal it with the threshold number of keys:

```bash
egide operator unseal AAAA...
egide operator unseal BBBB...
egide operator unseal CCCC...
```

After the third key, Egide is unsealed and ready.

## 4. Authenticate

Set your token:

```bash
export EGIDE_TOKEN="s.XXXX..."
```

Or pass it with each command:

```bash
egide --token "s.XXXX..." status
```

## 5. Store a Secret

```bash
egide secrets put myapp/database \
  username=admin \
  password=supersecret
```

## 6. Read a Secret

```bash
egide secrets get myapp/database
```

Output:

```json
{
  "data": {
    "username": "admin",
    "password": "supersecret"
  },
  "metadata": {
    "version": 1,
    "created_at": "2025-01-15T10:30:00Z"
  }
}
```

## 7. Use Transit Encryption

Create an encryption key:

```bash
egide kms create my-key --type aes256
```

Encrypt data:

```bash
echo "sensitive data" | egide transit encrypt my-key
```

Output:

```text
egide:v1:XXXXXXXXXXXXXXXXXXXXXXXX
```

Decrypt:

```bash
egide transit decrypt my-key "egide:v1:XXXXXXXXXXXXXXXXXXXXXXXX"
```

## Next Steps

- [Configuration](configuration.md): Customize Egide settings
- [Secrets Engine](../concepts/secrets-engine.md): Learn more about secrets management
- [Docker Deployment](../guides/docker.md): Production Docker setup
