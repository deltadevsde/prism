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
