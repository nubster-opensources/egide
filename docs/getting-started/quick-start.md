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

Example output (5 shares, threshold 3, keys abbreviated):

```text
Initializing Egide with 5 shares, threshold 3...

Egide initialized successfully!

Unseal Keys (hex):
  Key 1: 7a3f...
  Key 2: c91e...
  Key 3: 4b02...
  Key 4: f8d1...
  Key 5: 05a9...

Unseal Keys (base64):
  Key 1: ej8...
  Key 2: yR4...
  Key 3: SwI...
  Key 4: +NE...
  Key 5: Bak...

Root Token: 3e7c9a1f2b8d4560...

IMPORTANT: Save these keys securely! They are required to unseal Egide.
The root token is needed for administrative operations.
```

## 3. Unseal Egide

Egide starts sealed. Unseal it with the threshold number of keys (one key per invocation):

```bash
egide operator unseal 7a3f...
egide operator unseal c91e...
egide operator unseal 4b02...
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

The CLI covers operator and secrets commands only. The Transit engine (encryption as a service) is reached through the REST API. Create a key (root token required):

```bash
curl -s -X POST http://localhost:8200/v1/transit/keys \
  -H "Authorization: Bearer $EGIDE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-key", "type": "aes256-gcm"}'
```

Encrypt data (any authenticated token can use an existing key):

```bash
curl -s -X POST http://localhost:8200/v1/transit/encrypt/my-key \
  -H "Authorization: Bearer $EGIDE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "'"$(echo -n "sensitive data" | base64)"'"}'
```

Output:

```json
{"ciphertext": "egide:v1:XXXXXXXXXXXXXXXXXXXXXXXX"}
```

Decrypt:

```bash
curl -s -X POST http://localhost:8200/v1/transit/decrypt/my-key \
  -H "Authorization: Bearer $EGIDE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "egide:v1:XXXXXXXXXXXXXXXXXXXXXXXX"}'
```

The response carries the plaintext base64-encoded: `{"plaintext": "..."}`.

## Next Steps

- [Configuration](configuration.md): Customize Egide settings
- [Secrets Engine](../concepts/secrets-engine.md): Learn more about secrets management
- [Docker Deployment](../guides/docker.md): Production Docker setup
