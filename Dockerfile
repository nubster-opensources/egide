# =============================================================================
# Stage chef: shared base with cargo-chef installed
# =============================================================================
FROM rust:1.94-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# =============================================================================
# Stage planner: derive the dependency recipe from the whole workspace
# =============================================================================
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# =============================================================================
# Stage builder: cook cached dependencies, then build the real binaries
# =============================================================================
FROM chef AS builder

# Build-time system dependencies (protoc is required by tonic-prost-build)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Cook dependencies in a layer invalidated only when recipe.json changes
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build the release binaries from the actual sources
COPY . .
RUN cargo build --release --locked --bin egide-server --bin egide

# =============================================================================
# Stage runtime
# =============================================================================
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="egide"
LABEL org.opencontainers.image.description="Sovereign KMS and secrets manager"
LABEL org.opencontainers.image.version="0.1.0"

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
CMD ["--data-dir", "/var/lib/egide", "--bind", "0.0.0.0:8200"]
