.PHONY: all build check test lint fmt clean release docker help
.DEFAULT_GOAL := help

# ============================================================================
# Variables
# ============================================================================

CARGO := cargo
DOCKER := docker
DOCKER_COMPOSE := docker compose

# Build configuration
RELEASE_FLAGS := --release --locked
TARGET_DIR := target

# Docker configuration
DOCKER_IMAGE := nubster/egide
DOCKER_TAG := latest

# ============================================================================
# Development
# ============================================================================

## Build all crates in debug mode
build:
	$(CARGO) build

## Check code compiles without building
check:
	$(CARGO) check --all-targets

## Run all tests
test:
	$(CARGO) test --all-features

## Run tests with output
test-verbose:
	$(CARGO) test --all-features -- --nocapture

## Run clippy linter
lint:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

## Format code
fmt:
	$(CARGO) fmt --all

## Check formatting
fmt-check:
	$(CARGO) fmt --all -- --check

## Run all quality checks (format, lint, test)
ci: fmt-check lint test

# ============================================================================
# Release
# ============================================================================

## Build release binaries
release:
	$(CARGO) build $(RELEASE_FLAGS)

## Build server binary only
release-server:
	$(CARGO) build $(RELEASE_FLAGS) -p egide-server

## Build CLI binary only
release-cli:
	$(CARGO) build $(RELEASE_FLAGS) -p egide-cli

# ============================================================================
# Security
# ============================================================================

## Run security audit
audit:
	$(CARGO) audit

## Install audit tool
audit-install:
	$(CARGO) install cargo-audit --locked

# ============================================================================
# Documentation
# ============================================================================

## Generate documentation
doc:
	$(CARGO) doc --all-features --no-deps

## Generate and open documentation
doc-open:
	$(CARGO) doc --all-features --no-deps --open

# ============================================================================
# Docker
# ============================================================================

## Build Docker image
docker-build:
	$(DOCKER) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

## Run with Docker Compose (development)
docker-dev:
	$(DOCKER_COMPOSE) -f deploy/docker/docker-compose.dev.yml up --build

## Run with Docker Compose (production)
docker-prod:
	$(DOCKER_COMPOSE) -f deploy/docker/docker-compose.yml up -d

## Stop Docker Compose
docker-stop:
	$(DOCKER_COMPOSE) down

## Clean Docker resources
docker-clean:
	$(DOCKER_COMPOSE) down -v --rmi local

# ============================================================================
# Database
# ============================================================================

## Run database migrations
db-migrate:
	@echo "Database migrations not yet implemented"

## Reset database
db-reset:
	@echo "Database reset not yet implemented"

# ============================================================================
# Utilities
# ============================================================================

## Clean build artifacts
clean:
	$(CARGO) clean

## Update dependencies
update:
	$(CARGO) update

## Show dependency tree
deps:
	$(CARGO) tree

## Generate Cargo.lock
lock:
	$(CARGO) generate-lockfile

## Install development tools
tools:
	$(CARGO) install cargo-audit --locked
	$(CARGO) install cargo-watch --locked

## Watch and rebuild on changes
watch:
	$(CARGO) watch -x check

## Watch and run tests on changes
watch-test:
	$(CARGO) watch -x test

# ============================================================================
# Help
# ============================================================================

## Show this help message
help:
	@echo "Nubster Egide - Makefile Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  build          Build all crates in debug mode"
	@echo "  check          Check code compiles without building"
	@echo "  test           Run all tests"
	@echo "  test-verbose   Run tests with output"
	@echo "  lint           Run clippy linter"
	@echo "  fmt            Format code"
	@echo "  fmt-check      Check formatting"
	@echo "  ci             Run all quality checks (format, lint, test)"
	@echo ""
	@echo "Release:"
	@echo "  release        Build release binaries"
	@echo "  release-server Build server binary only"
	@echo "  release-cli    Build CLI binary only"
	@echo ""
	@echo "Security:"
	@echo "  audit          Run security audit"
	@echo "  audit-install  Install audit tool"
	@echo ""
	@echo "Documentation:"
	@echo "  doc            Generate documentation"
	@echo "  doc-open       Generate and open documentation"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build   Build Docker image"
	@echo "  docker-dev     Run with Docker Compose (development)"
	@echo "  docker-prod    Run with Docker Compose (production)"
	@echo "  docker-stop    Stop Docker Compose"
	@echo "  docker-clean   Clean Docker resources"
	@echo ""
	@echo "Utilities:"
	@echo "  clean          Clean build artifacts"
	@echo "  update         Update dependencies"
	@echo "  deps           Show dependency tree"
	@echo "  lock           Generate Cargo.lock"
	@echo "  tools          Install development tools"
	@echo "  watch          Watch and rebuild on changes"
	@echo "  watch-test     Watch and run tests on changes"
	@echo ""
