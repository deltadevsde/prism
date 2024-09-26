# Define the path to your docker-compose.yml file
DOCKER_COMPOSE_FILE := "ci/docker-compose.yml"

celestia-up:
  #!/usr/bin/env bash
  set -euo pipefail

  echo "Cleaning up any existing Docker resources..."
  docker-compose -f {{DOCKER_COMPOSE_FILE}} down -v --remove-orphans

  echo "Spinning up a fresh Docker Compose stack..."
  docker-compose -f {{DOCKER_COMPOSE_FILE}} up -d --force-recreate --renew-anon-volumes

  echo "Waiting for services to be ready..."
  timeout=120
  start_time=$(date +%s)
  light_node_ready=false
  bridge_node_ready=false

  while true; do
    logs=$(docker-compose -f {{DOCKER_COMPOSE_FILE}} logs)

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
      docker-compose -f {{DOCKER_COMPOSE_FILE}} logs
      exit 1
    fi

    echo "Still waiting... (${elapsed}s elapsed)"
    sleep 5
  done


  echo "Celestia stack is up and running!"

celestia-down:
  docker-compose -f {{DOCKER_COMPOSE_FILE}} down -v --remove-orphans

celestia-logs:
  docker-compose -f {{DOCKER_COMPOSE_FILE}} logs -f

# Command to run integration tests with a fresh Docker setup
integration-test:
  #!/usr/bin/env bash
  set -euo pipefail

  just celestia-up

  echo "Running integration tests..."
  cargo test --release --test integration_tests

  just celestia-down

check:
  @echo "Running cargo udeps..."
  cargo +nightly udeps --all-features --all-targets
  @echo "Running clippy..."
  cargo clippy --all --all-targets -- -D warnings

build:
  @echo "Building the project..."
  cargo build --release
  @echo "Building SP1..."
  cd crates/sp1 && cargo prove build

unit-test:
  @echo "Running unit tests..."
  cargo test --lib --release --features mock_prover -- --skip test_light_client_sequencer_talking

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

  # Install Redis if not present
  if ! command -v redis-server > /dev/null; then \
    echo "Installing Redis..."; \
    if [ "$OS" = "Mac" ]; then \
      if ! command -v brew > /dev/null; then \
        echo "Homebrew is not installed. Please install Homebrew first."; \
        exit 1; \
      fi; \
      brew install redis; \
    elif [ "$OS" = "Linux" ]; then \
      sudo apt update; \
      sudo apt install redis-server -y; \
    fi; \
    echo "Redis installation complete!"; \
  else \
    echo "Redis is already installed."; \
  fi

  if ! command -v protoc > /dev/null; then \
    echo "Installing Protobuf..."; \
    if [ "$OS" = "Mac" ]; then \
      brew install protobuf; \
    elif [ "$OS" = "Linux" ]; then \
      sudo apt update; \
      sudo apt install protobuf-compiler -y; \
    fi; \
  else \
    echo "Protobuf is already installed."; \
  fi


  if ! command -v cargo prove > /dev/null; then \
    echo "Installing SP1..."
    curl -L https://sp1.succinct.xyz | bash; \
    source ~/.bashrc || source ~/.bash_profile || source ~/.zshrc; \


    echo "Running sp1up to install SP1 toolchain..."
    sp1up

    if command -v cargo prove > /dev/null; then \
      echo "SP1 installation successful!"; \
      cargo prove --version; \
    else \
      echo "SP1 installation may have failed. Please check and install manually if needed."; \
    fi
  else \
    echo "SP1 is already installed."; \
  fi

  echo "All dependencies installed successfully!"
