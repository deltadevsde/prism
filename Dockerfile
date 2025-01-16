FROM rust:1.83-slim-bookworm AS builder

WORKDIR /usr/src/myapp

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    cargo install just

COPY justfile .

RUN just install-deps

ENV PATH="/root/.sp1/bin:$PATH"

COPY . .

RUN just build

EXPOSE 8080

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        gnome-keyring \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/myapp/target/release/prism-cli /usr/local/bin/prism-cli

ENTRYPOINT ["prism-cli"]
