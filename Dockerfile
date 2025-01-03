FROM rust:latest AS builder

WORKDIR /usr/src/myapp

COPY . .

RUN cargo install just

RUN just install-deps

ENV PATH="/root/.sp1/bin:$PATH"

# RUN echo $PATH && exit 1

RUN just build

EXPOSE 8080

FROM debian:12-slim

RUN apt-get update && apt-get install -y libssl3

COPY --from=builder /usr/src/myapp/target/release/prism-cli /usr/local/bin/prism-cli

ENTRYPOINT ["prism-cli"]

