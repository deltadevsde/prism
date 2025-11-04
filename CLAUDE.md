# Prism Development Guide for AI Agents

This guide provides comprehensive instructions for AI agents working on the Prism codebase. It covers the architecture, development workflows, and critical guidelines for effective contributions.

## Project Overview

Prism is a high-performance key transparency solution written in Rust, creating SNARKs using a zkVM over a key directory tree. The codebase is organized into well-defined crates with clear boundaries and responsibilities.

## Github
- Repository name: prism
- Repository owner: deltadevsde
- Repository is https://github.com/deltadevsde/prism

## Important
- ALL instructions within this document MUST BE FOLLOWED, these are not optional unless explicitly stated.
- DO NOT edit more code than you have to.
- DO NOT WASTE TOKENS, be succinct and concise.

## Architecture Overview

### Core Components

1. **Common (`crates/common`)**: Defines Prism transactions and operations, among other shared types such as `Digest` and Prism `Account`s.
2. **Storage (`crates/storage`)**: Database trait and implementations, used by full nodes.
3. **Data Availability (`crates/da`)**: Defines the DA traits and implementations, the main one being Celestia. The transactions and SNARKs are both posted and read to/from the DA layer.
4. **Keys (`crates/keys`)**: Defines the public/private key types used in Prism, supporting multiple curves.
5. **Tree (`crates/tree`)**: Defines the Key Directory Tree, proof types, and the logic for executing transaction batches as well as verification that gets executed in the zkVM.
6. **zkVM (`crates/zk/sp1`)**: Defines the zkVM script that gets compiled to a provable ELF.
7. **Node Types (`crates/node_types`)**: Defines the node types used in Prism, including the prover and light nodes.
8. **CLI (`crates/cli`)**: Defines the command-line interface for interacting with Prism.
9. **HTTP Client (`crates/client`)**: HTTP client implementation for Prism.
10. **Serde (`crates/serde`)**: (De)Serialization traits and implementations that can be used in other crates.
11. **Cross Target (`crates/crosstarget`)**: Defines target agnostic components that can be used in wasm and native environments.

### Key Design Principles

- **Modularity**: Each crate can be used as a standalone library
- **Performance**: Extensive use of parallelism and optimized data structures
- **Extensibility**: Traits and generic types allow for different implementations
- **Type Safety**: Strong typing throughout with minimal use of dynamic dispatch

## Development Workflow

### Build & Test Commands
- Build: `just build`
- Lint & Check: `just check` (runs cargo udeps and clippy)
- Unit tests: `just unit-test`
- Run single test: `SP1_PROVER=mock cargo nextest --lib --release -- test_name`
- Generate coverage: `just coverage`
- Install dependencies: `just install-deps`

### Code Style Guidelines
- Follow [Rust Coding Standards](https://doc.rust-lang.org/nightly/style-guide/)
- Use rustfmt with project settings (merge_imports=true, imports_granularity="Crate", max_width=100)
- Create separate branches for features/bug fixes
- Include tests for new functionality
- Error handling: Use Result types with descriptive error messages and `?` operator
- Follow Rust naming conventions (snake_case for functions/variables, CamelCase for types)
- File organization: Group related functionality in modules

### Documentation
- Add comments mostly for public APIs that are exposed on crate level
- Only add comments for private APIs when they are complex or have non-obvious behavior
- Keep public method docstrings short and focused (e.g. very short summary, very short explanation of parameters & return value)
- If necessary, use longer examples only in module files (mod.rs or lib.rs)

### Testing
- Do not write tests for derived traits (Clone, Debug, PartialEq, Serialize, Deserialize, etc), unless there's a custom implementation for them

### Commits
- Always combine related changes in focused, granular commits
- Each commit should focus on a single logical change
- Break changes into multiple smaller commits that each represent a complete, working step
- Aim for commits that modify ~50 lines or less when possible (does not apply for non-code files)
- Use conventional commits
- Allowed types are feat, refactor, fix, build, ci, chore, docs, test, release
- Use canonical crate names as scopes for conventional commits (e.g. lightclient, prover, keys, da, etc..)
- Use "build" as scope for commits that update dependencies
- Do not mention AI in the description
- Always make a separate commit "chore: update zkVM ELF and keys" for keys.json and elf files as last commit, if they were updated

### CI Requirements

Before submitting changes, ensure:

1. **Format Check**: `just check`
2. **Tests Pass**: All unit tests and doc test
3. **Documentation**: Update relevant docs and add doc comments
