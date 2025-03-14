# Prism Development Guidelines

## Build & Test Commands
- Build: `just build`
- Lint & Check: `just check` (runs cargo udeps and clippy)
- Unit tests: `just unit-test`
- Run single test: `cargo test --lib --release --features "mock_prover" -- test_name`
- Integration tests: `just integration-test`
- Generate coverage: `just coverage`
- Install dependencies: `just install-deps`

## Code Style Guidelines
- Follow [Rust Coding Standards](https://doc.rust-lang.org/nightly/style-guide/)
- Use rustfmt with project settings (merge_imports=true, imports_granularity="Crate", max_width=100)
- Create separate branches for features/bug fixes
- Write clear commit messages
- Include tests for new functionality
- Error handling: Use Result types with descriptive error messages
- Naming: follow Rust conventions (snake_case for functions/variables, CamelCase for types)
- Documentation: Add comments for public APIs and complex logic
- File organization: Group related functionality in modules