# Define the path to your docker-compose.yml file
DOCKER_COMPOSE_FILE := "ci/docker-compose.yml"

# Helper function to use correct docker compose command
docker_compose_cmd := if `uname -s` == "Linux" { "docker compose" } else { "docker-compose" }

# Check if running as root by examining the effective user ID
is_root := if `id -u` == "0" { "true" } else { "false" }

celestia-up:
  #!/usr/bin/env bash
  set -euo pipefail

  echo "Cleaning up any existing Docker resources..."
  {{docker_compose_cmd}} -f {{DOCKER_COMPOSE_FILE}} down -v --remove-orphans

  echo "Building Docker images..."
  {{docker_compose_cmd}} -f {{DOCKER_COMPOSE_FILE}} build

  echo "Spinning up a fresh Docker Compose stack..."
  {{docker_compose_cmd}} -f {{DOCKER_COMPOSE_FILE}} up -d --force-recreate --renew-anon-volumes

  echo "Waiting for services to be ready..."
  timeout=120
  start_time=$(date +%s)
  light_node_ready=false
  bridge_node_ready=false

  while true; do
    logs=$( {{docker_compose_cmd}} -f {{DOCKER_COMPOSE_FILE}} logs )

    if [[ $logs == *"Configuration finished. Running a light node"* ]]; then
      light_node_ready=true
      echo "Light node is ready!"
    fi

    if [[ $logs == *"Configuration finished. Running a bridge node"* ]]; then
      bridge_node_ready=true
      echo "Bridge node is ready!"
    fi

    if $light_node_ready && $bridge_node_ready; then
      echo "All services are ready!"
      break
    fi

    current_time=$(date +%s)
    elapsed=$((current_time - start_time))

    if [ $elapsed -ge $timeout ]; then
      echo "Timeout waiting for services to be ready. Check the logs for more information."
      {{docker_compose_cmd}} -f {{DOCKER_COMPOSE_FILE}} logs
      exit 1
    fi

    echo "Still waiting... (${elapsed}s elapsed)"
    sleep 5
  done

  echo "Celestia stack is up and running!"

celestia-down:
  {{docker_compose_cmd}} -f {{DOCKER_COMPOSE_FILE}} down -v --remove-orphans

celestia-logs:
  {{docker_compose_cmd}} -f {{DOCKER_COMPOSE_FILE}} logs -f

# Command to run integration tests with a fresh Docker setup
integration-test:
  #!/usr/bin/env bash
  set -euo pipefail

  for curve in ed25519 secp256k1 secp256r1; do
    just celestia-up

    export RUST_LOG="DEBUG,tracing=off,sp1_stark=info,jmt=off,p3_dft=off,p3_fri=off,sp1_core_executor=info,sp1_recursion_program=info,p3_merkle_tree=off,sp1_recursion_compiler=off,sp1_core_machine=off"

    SP1_PROVER=mock RUST_LOG=$RUST_LOG cargo test -p prism-tests --lib --release --features mock_prover

    just celestia-down
  done

check:
  @echo "Running cargo udeps..."
  cargo +nightly udeps --all-features --all-targets
  @echo "Running clippy..."
  cargo clippy --all --all-targets -- -D warnings

build:
  @echo "Building the project..."
  cargo build --release

  @echo "Building SP1 base binary..."
  cd crates/zk/sp1 && cargo prove build --bin base_prover --output-directory ../../../elf/ --elf-name base-riscv32im-succinct-zkvm-elf
  @echo "Base binary built successfully."

  @echo "Building SP1 recursive binary..."
  cd crates/zk/sp1 && cargo prove build --bin recursive_prover --output-directory ../../../elf/ --elf-name recursive-riscv32im-succinct-zkvm-elf
  @echo "Recursive binary built successfully."

  @echo "Creating verifying keys directory..."
  mkdir -p ./verification_keys

  @echo "Generating verification keys..."
  echo "{\"base_vk\": \"$(cd crates/zk/sp1 && cargo prove vkey --elf ../../../elf/base-riscv32im-succinct-zkvm-elf | grep '0x' | cut -d' ' -f2)\", \"recursive_vk\": \"$(cd crates/zk/sp1 && cargo prove vkey --elf ../../../elf/recursive-riscv32im-succinct-zkvm-elf | grep '0x' | cut -d' ' -f2)\"}" > ./verification_keys/keys.json

  @echo "Verification key hashes generated successfully"

unit-test:
  @echo "Running unit tests..."

  SP1_PROVER=mock cargo test --lib --release --features "mock_prover" -- --skip test_light_client_prover_talking

coverage:
  #!/usr/bin/env bash
  set -euo pipefail

  just celestia-up

  echo "Generating coverage report..."

  if ! SP1_PROVER=mock cargo llvm-cov nextest --html --output-dir coverage_report --lib --features "mock_prover" --release --workspace --exclude prism-cli --exclude-from-report prism-sp1 --ignore-filename-regex sp1; then
    echo "Coverage report generation failed."
  else
    echo "Coverage report generated in 'coverage_report' directory"
  fi

  just celestia-down

install-deps:
  #!/usr/bin/env bash
  set -euo pipefail

  echo "Installing project dependencies..."

  unameOut="$(uname -s)" && \
  case "${unameOut}" in \
    Linux*)     OS=Linux ;; \
    Darwin*)    OS=Mac ;; \
    *)          OS="UNKNOWN:${unameOut}" ;; \
  esac

  if [ "$OS" = "UNKNOWN:${unameOut}" ]; then \
    echo "Unsupported operating system. This script only supports Linux and macOS. Please install dependencies manually."; \
    exit 1; \
  fi

  # On Linux, ensure essential packages are installed
  if [ "$OS" = "Linux" ]; then \
    for package in build-essential pkg-config libssl-dev libclang-dev libfontconfig1-dev clang; do \
      if ! dpkg -s $package > /dev/null 2>&1; then \
        echo "Installing $package..."; \
        if {{is_root}}; then \
          apt update; \
          apt install $package -y; \
        else \
          sudo apt update; \
          sudo apt install $package -y; \
        fi; \
      else \
        echo "$package is already installed."; \
      fi; \
    done; \
  fi

  if ! cargo prove --version > /dev/null 2>&1; then \
    echo "Installing SP1..."
    curl -L https://sp1.succinct.xyz | bash; \
    source ~/.bashrc || source ~/.bash_profile || source ~/.zshrc; \

    echo "Running sp1up to install SP1 toolchain..."
    sp1up

    if cargo prove --version > /dev/null 2>&1; then \
      echo "SP1 installation successful!"; \
      cargo prove --version; \
    else \
      echo "SP1 installation may have failed. Please check and install manually if needed."; \
    fi
  else \
    echo "SP1 is already installed."; \
  fi

  for tool in cargo-udeps cargo-llvm-cov cargo-nextest; do \
    if ! command -v $tool > /dev/null; then \
      echo "Installing $tool..."; \
      cargo install $tool; \
    else \
      echo "$tool is already installed."; \
    fi; \
  done

  source ~/.bashrc || source ~/.bash_profile || source ~/.zshrc

  echo "All dependencies installed successfully!"
