# Define the path to your docker-compose.yml file
DOCKER_COMPOSE_FILE := "ci/docker-compose.yml"

celestia-up:
  #!/usr/bin/env bash
  set -euo pipefail

  echo "Cleaning up any existing Docker resources..."
  if [ "$(uname -s)" = "Linux" ]; then \
    docker compose -f {{DOCKER_COMPOSE_FILE}} down -v --remove-orphans; \
  else \
    docker-compose -f {{DOCKER_COMPOSE_FILE}} down -v --remove-orphans; \
  fi

  echo "Building Docker images..."
  if [ "$(uname -s)" = "Linux" ]; then \
    docker compose -f {{DOCKER_COMPOSE_FILE}} build; \
  else \
    docker-compose -f {{DOCKER_COMPOSE_FILE}} build; \
  fi

  echo "Building Docker images..."
  docker-compose -f {{DOCKER_COMPOSE_FILE}} build

  echo "Spinning up a fresh Docker Compose stack..."
  if [ "$(uname -s)" = "Linux" ]; then \
    docker compose -f {{DOCKER_COMPOSE_FILE}} up -d --force-recreate --renew-anon-volumes; \
  else \
    docker-compose -f {{DOCKER_COMPOSE_FILE}} up -d --force-recreate --renew-anon-volumes; \
  fi

  echo "Waiting for services to be ready..."
  timeout=120
  start_time=$(date +%s)
  light_node_ready=false
  bridge_node_ready=false

  while true; do
    if [ "$(uname -s)" = "Linux" ]; then \
      logs=$(docker compose -f {{DOCKER_COMPOSE_FILE}} logs); \
    else \
      logs=$(docker-compose -f {{DOCKER_COMPOSE_FILE}} logs); \
    fi

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
      if [ "$(uname -s)" = "Linux" ]; then \
        docker compose -f {{DOCKER_COMPOSE_FILE}} logs; \
      else \
        docker-compose -f {{DOCKER_COMPOSE_FILE}} logs; \
      fi
      exit 1
    fi

    echo "Still waiting... (${elapsed}s elapsed)"
    sleep 5
  done

  echo "Celestia stack is up and running!"

celestia-down:
  if [ "$(uname -s)" = "Linux" ]; then \
    docker compose -f {{DOCKER_COMPOSE_FILE}} down -v --remove-orphans; \
  else \
    docker-compose -f {{DOCKER_COMPOSE_FILE}} down -v --remove-orphans; \
  fi

celestia-logs:
  if [ "$(uname -s)" = "Linux" ]; then \
    docker compose -f {{DOCKER_COMPOSE_FILE}} logs -f; \
  else \
    docker-compose -f {{DOCKER_COMPOSE_FILE}} logs -f; \
  fi

# Command to run integration tests with a fresh Docker setup
integration-test:
  #!/usr/bin/env bash
  set -euo pipefail

  just celestia-up

  echo "Running integration tests..."
  if ! cargo test -p prism-tests --lib --release --features mock_prover; then
    echo "Integration tests failed."
  fi

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
  cd crates/zk/sp1 && cargo prove build

unit-test:
  @echo "Running unit tests..."
  cargo test --lib --release --features "mock_prover" -- --skip test_light_client_prover_talking

coverage:
  #!/usr/bin/env bash
  set -euo pipefail

  just celestia-up

  echo "Generating coverage report..."
  if ! cargo llvm-cov nextest --html --output-dir coverage_report --lib --features "mock_prover" --release --workspace --exclude prism-cli --exclude-from-report prism-sp1 --ignore-filename-regex sp1; then
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
    for package in build-essential pkg-config libssl-dev libclang-dev clang; do \
      if ! dpkg -s $package > /dev/null 2>&1; then \
        echo "Installing $package..."; \
        sudo apt update; \
        sudo apt install $package -y; \
      else \
        echo "$package is already installed."; \
      fi; \
    done; \
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

  echo "All dependencies installed successfully!"
