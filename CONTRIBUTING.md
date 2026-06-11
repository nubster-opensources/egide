# Contributing to Nubster Egide

Thank you for your interest in contributing to Egide! This document provides guidelines and information for contributors.

## Code of Conduct

Please be respectful and constructive in all interactions. We are committed to providing a welcoming and inclusive environment.

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or request features
- Search existing issues before creating a new one
- Provide clear reproduction steps for bugs
- Include relevant system information (OS, Rust version, etc.)

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Ensure all tests pass (`cargo test`)
5. Run linting (`cargo clippy`)
6. Format code (`cargo fmt`)
7. Commit with clear messages
8. Push and create a Pull Request

### Commit Messages

Follow conventional commits format:

```
type(scope): description

[optional body]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(secrets): add secret versioning support`
- `fix(kms): handle key rotation edge case`
- `docs: update API documentation`

## Development Setup

### Prerequisites

- Rust 1.79 or later
- PostgreSQL 16+ (for integration tests)
- Docker (optional, for containerized testing)

### Building

```bash
# Build all crates
cargo build

# Build in release mode
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p egide-crypto

# Run with logging
RUST_LOG=debug cargo test
```

### Linting

```bash
# Check for issues
cargo clippy --all-targets -- -D warnings

# Format code
cargo fmt --all
```

## Architecture Guidelines

### Code Style

- Follow Rust API guidelines
- Use `thiserror` for error types
- Document all public items with Rustdoc
- Avoid `unsafe` unless absolutely necessary
- Use `zeroize` for sensitive data

### Security Considerations

- Never log secrets or keys
- Zeroize sensitive data when done
- Use constant-time comparisons for secrets
- Validate all inputs
- Follow the principle of least privilege

## License

By contributing, you agree that your contributions will be licensed under the BSL 1.1 license.

## Questions?

Feel free to open an issue or reach out to the maintainers.
