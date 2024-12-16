#!/bin/bash
# Taken from eigerco/lumina

set -euo pipefail

# Name for this node or `light-0` if not provided
NODE_ID="${NODE_ID:-0}"
SKIP_AUTH="${SKIP_AUTH:-false}"
BRIDGE_COUNT="${BRIDGE_COUNT}"
NODE_NAME="light-$NODE_ID"
# a private local network
P2P_NETWORK="private"
# a light node configuration directory
CONFIG_DIR="$CELESTIA_HOME"
# directory and the files shared with the validator node
CREDENTIALS_DIR="/credentials"
# node credentials
NODE_KEY_FILE="$CREDENTIALS_DIR/$NODE_NAME.key"
NODE_JWT_FILE="$CREDENTIALS_DIR/$NODE_NAME.jwt"
# directory where validator will write the genesis hash and the bridge node their peers addresses
SHARED_DIR="/shared"
GENESIS_HASH_FILE="$SHARED_DIR/genesis_hash"
TRUSTED_PEERS_FILE="$SHARED_DIR/trusted_peers"

# Wait for the validator to set up and provision us via shared dir
wait_for_provision() {
  echo "Waiting for the validator node to start"
  while [[ ! ( -e "$GENESIS_HASH_FILE" && -e "$NODE_KEY_FILE" ) ]]; do
    sleep 0.1
  done
  echo "Validator is ready"

  echo "Waiting for $BRIDGE_COUNT bridge nodes to start"
  start_time=$(date +%s)
  timeout=30

  while true; do
    if [[ -e "$TRUSTED_PEERS_FILE" ]]; then

      echo "Trusted peers file exists"

      trusted_peers="$(cat "$TRUSTED_PEERS_FILE")"
      echo "Trusted peers: $trusted_peers"
      peer_count=$(echo "$trusted_peers" | tr ',' '\n' | wc -l)
      echo "Peer count: $peer_count"
      if [[ $peer_count -eq $BRIDGE_COUNT ]]; then
        echo "$BRIDGE_COUNT bridge nodes are ready"
        break
      else
        echo "Trusted peers file does not contain the expected number of commas. Retrying..."
      fi
    else
      echo "Trusted peers file does not exist yet. Retrying..."
    fi

    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    if [[ $elapsed -ge $timeout ]]; then
      echo "Timeout reached. Exiting."
      exit 1
    fi

    sleep 1
  done
}

# Import the test account key shared by the validator
import_shared_key() {
  echo "password" | cel-key import "$NODE_NAME" "$NODE_KEY_FILE" \
    --keyring-backend="test" \
    --p2p.network "$P2P_NETWORK" \
    --node.type light
}

add_trusted_genesis() {
  local genesis_hash

  # Read the hash of the genesis block
  genesis_hash="$(cat "$GENESIS_HASH_FILE")"
  trusted_peers="$(cat "$TRUSTED_PEERS_FILE")"
  # and make it trusted in the node's config
  echo "Trusting a genesis: $genesis_hash"
  sed -i'.bak' "s/TrustedHash = .*/TrustedHash = $genesis_hash/" "$CONFIG_DIR/config.toml"
}

add_trusted_peers() {
  local trusted_peers="$(cat "$TRUSTED_PEERS_FILE")"
  local formatted_peers=$(echo "$trusted_peers" | sed 's/\([^,]*\)/"\1"/g')
  echo "Trusting peers: $formatted_peers"
  sed -i'.bak' "s|TrustedPeers = .*|TrustedPeers = [$formatted_peers]|" "$CONFIG_DIR/config.toml"
}

write_jwt_token() {
  echo "Saving jwt token to $NODE_JWT_FILE"
  celestia light auth admin --p2p.network "$P2P_NETWORK" > "$NODE_JWT_FILE"
}

main() {
  # Initialize the light node
  celestia light init --p2p.network "$P2P_NETWORK"
  # Wait for a validator
  wait_for_provision
  # Import the key with the coins
  import_shared_key
  # Trust the private blockchain
  add_trusted_genesis
  # Trust the bridge nodes
  add_trusted_peers
  # Update the JWT token
  write_jwt_token
  # give validator some time to set up
  sleep 10
  # Start the light node
  echo "Configuration finished. Running a light node..."
  celestia light start \
    --rpc.skip-auth=$SKIP_AUTH \
    --rpc.addr 0.0.0.0 \
    --core.ip validator \
    --keyring.keyname "$NODE_NAME" \
    --p2p.network "$P2P_NETWORK"
}

main
