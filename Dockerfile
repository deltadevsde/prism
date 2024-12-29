# Stage 1: Base image with caching tools
FROM rust:1.83.0-slim-bookworm AS base
RUN apt-get update && apt-get install -y protobuf-compiler clang && rm -rf /var/lib/apt/lists/*
RUN cargo install sccache --version ^0.9
RUN cargo install cargo-chef --version ^0.1
ENV RUSTC_WRAPPER=sccache SCCACHE_DIR=/sccache

# Stage 2: Planner
FROM base AS planner
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder
FROM base AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo build --release

# Build SP1
RUN echo "Building SP1..." && \
    cd crates/zk/sp1 && cargo prove build

# Stage 4: Create the final image
FROM debian:12.8-slim

# Set the working directory
WORKDIR /usr/src/app

# Copy the built artifacts from the builder stage
COPY --from=builder /app/target/release/prism-cli /usr/local/bin/prism-cli
COPY --from=builder /app/crates/zk/sp1/target/release/sp1 /usr/local/bin/sp1

# Define the command to run the application
ENTRYPOINT ["prism-cli"]

CMD ["prover"]
