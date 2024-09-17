#!/bin/sh
set -e

curl -fSL -o mdbook.tar.gz https://github.com/rust-lang/mdBook/releases/download/v0.4.33/mdbook-v0.4.33-x86_64-unknown-linux-musl.tar.gz
tar -xzf mdbook.tar.gz

curl -fSL -o mdbook-katex.tar.gz https://github.com/lzanini/mdbook-katex/releases/download/v0.8.0/mdbook-katex-v0.8.0-x86_64-unknown-linux-musl.tar.gz
tar -xzf mdbook-katex.tar.gz

curl -fSL -o mdbook-mermaid.tar.gz https://github.com/badboy/mdbook-mermaid/releases/download/v0.14.0/mdbook-mermaid-v0.14.0-x86_64-unknown-linux-musl.tar.gz
tar -xzf mdbook-mermaid.tar.gz

chmod +x mdbook mdbook-katex mdbook-mermaid

export PATH=$(pwd):$PATH

export MDBOOK_PLUGIN_DIR=$(pwd)

./mdbook build