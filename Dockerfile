# =============================================================================
# Stage 1: Build
# =============================================================================
FROM rust:1.79-bookworm AS builder

WORKDIR /app

# Install dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY src/core/egide-crypto/Cargo.toml src/core/egide-crypto/
COPY src/core/egide-secrets/Cargo.toml src/core/egide-secrets/
COPY src/core/egide-kms/Cargo.toml src/core/egide-kms/
COPY src/core/egide-pki/Cargo.toml src/core/egide-pki/
COPY src/core/egide-transit/Cargo.toml src/core/egide-transit/
COPY src/server/egide-server/Cargo.toml src/server/egide-server/
COPY src/server/egide-api/Cargo.toml src/server/egide-api/
COPY src/server/egide-auth/Cargo.toml src/server/egide-auth/
COPY src/storage/egide-storage/Cargo.toml src/storage/egide-storage/
COPY src/storage/egide-storage-postgres/Cargo.toml src/storage/egide-storage-postgres/
COPY src/storage/egide-storage-sqlite/Cargo.toml src/storage/egide-storage-sqlite/
COPY src/cli/egide-cli/Cargo.toml src/cli/egide-cli/

# Create dummy source files for dependency caching
RUN mkdir -p src/core/egide-crypto/src && echo "pub mod error; pub use error::CryptoError;" > src/core/egide-crypto/src/lib.rs && echo "use thiserror::Error; #[derive(Debug, Error)] pub enum CryptoError { #[error(\"error\")] Error }" > src/core/egide-crypto/src/error.rs
RUN mkdir -p src/core/egide-secrets/src && echo "" > src/core/egide-secrets/src/lib.rs
RUN mkdir -p src/core/egide-kms/src && echo "" > src/core/egide-kms/src/lib.rs
RUN mkdir -p src/core/egide-pki/src && echo "" > src/core/egide-pki/src/lib.rs
RUN mkdir -p src/core/egide-transit/src && echo "" > src/core/egide-transit/src/lib.rs
RUN mkdir -p src/server/egide-server/src && echo "fn main() {}" > src/server/egide-server/src/main.rs
RUN mkdir -p src/server/egide-api/src && echo "" > src/server/egide-api/src/lib.rs
RUN mkdir -p src/server/egide-auth/src && echo "" > src/server/egide-auth/src/lib.rs
RUN mkdir -p src/storage/egide-storage/src && echo "" > src/storage/egide-storage/src/lib.rs
RUN mkdir -p src/storage/egide-storage-postgres/src && echo "" > src/storage/egide-storage-postgres/src/lib.rs
RUN mkdir -p src/storage/egide-storage-sqlite/src && echo "" > src/storage/egide-storage-sqlite/src/lib.rs
RUN mkdir -p src/cli/egide-cli/src && echo "fn main() {}" > src/cli/egide-cli/src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release || true

# Copy actual source code
COPY src/ src/

# Touch source files to invalidate cache and rebuild
RUN find src -name "*.rs" -exec touch {} \;

# Build release binaries
RUN cargo build --release --locked

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash egide

# Create directories
RUN mkdir -p /etc/egide /var/lib/egide /var/log/egide \
    && chown -R egide:egide /etc/egide /var/lib/egide /var/log/egide

# Copy binaries from builder
COPY --from=builder /app/target/release/egide-server /usr/local/bin/
COPY --from=builder /app/target/release/egide /usr/local/bin/

# Make binaries executable
RUN chmod +x /usr/local/bin/egide-server /usr/local/bin/egide

# Switch to non-root user
USER egide
WORKDIR /home/egide

# Expose default port
EXPOSE 8200

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD egide status || exit 1

# Default command
ENTRYPOINT ["egide-server"]
CMD ["--bind", "0.0.0.0:8200"]
