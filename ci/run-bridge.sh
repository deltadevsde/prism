#!/bin/bash
# Taken from eigerco/lumina

set -euo pipefail

# Name for this node or `bridge-0` if not provided
NODE_ID="${NODE_ID:-0}"
SKIP_AUTH="${SKIP_AUTH:-false}"
CONTAINER_NAME="${CONTAINER_NAME:-bridge-$NODE_ID}"
NODE_NAME="bridge-$NODE_ID"
# a private local network
P2P_NETWORK="private"
# a bridge node configuration directory
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
}

# Import the test account key shared by the validator
import_shared_key() {
  echo "password" | cel-key import "$NODE_NAME" "$NODE_KEY_FILE" \
    --keyring-backend="test" \
    --p2p.network "$P2P_NETWORK" \
    --node.type bridge
}

add_trusted_genesis() {
  local genesis_hash

  # Read the hash of the genesis block
  genesis_hash="$(cat "$GENESIS_HASH_FILE")"
  # and make it trusted in the node's config
  echo "Trusting a genesis: $genesis_hash"
  sed -i'.bak' "s/TrustedHash = .*/TrustedHash = $genesis_hash/" "$CONFIG_DIR/config.toml"
}

write_jwt_token() {
  echo "Saving jwt token to $NODE_JWT_FILE"
  celestia bridge auth admin --p2p.network "$P2P_NETWORK" > "$NODE_JWT_FILE"
}

append_trusted_peers() {
  peer_id=""
  start_time=$(date +%s)
  timeout=30

  while [[ -z "$peer_id" ]]; do
    peer_id=$(celestia p2p info | jq -r '.result.id' || echo "")
    if [[ -z "$peer_id" ]]; then
      echo "Node is not running yet. Retrying..."
      sleep 1
    fi

    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    if [[ $elapsed -ge $timeout ]]; then
      echo "Failed to retrieve Peer ID after $timeout seconds. Exiting."
      exit 1
    fi
  done

  #multiaddr: /dns/$CONTAINER_NAME/tcp/$RPC_PORT/p2p/$peer_id
  multiaddr="/dns/$CONTAINER_NAME/tcp/2121/p2p/$peer_id"
  echo "Appending trusted peer: $multiaddr"

  # Lock the file to prevent race conditions
  exec 9>"$TRUSTED_PEERS_FILE.lock"
  flock -x 9

  # Read existing peers into a variable
  existing_peers=""
  if [[ -s "$TRUSTED_PEERS_FILE" ]]; then
    existing_peers=$(cat "$TRUSTED_PEERS_FILE")
  fi

  # Append the new multiaddr to the existing peers
  if [[ -n "$existing_peers" ]]; then
    echo "$existing_peers,$multiaddr" > "$TRUSTED_PEERS_FILE"
  else
    echo "$multiaddr" > "$TRUSTED_PEERS_FILE"
  fi

  # Unlock the file
  flock -u 9
  exec 9>&-
}

main() {
  # Initialize the bridge node
  celestia bridge init --p2p.network "$P2P_NETWORK"
  # Wait for a validator
  wait_for_provision
  # Import the key with the coins
  import_shared_key
  # Trust the private blockchain
  add_trusted_genesis
  # Update the JWT token
  write_jwt_token
  # Append the peer multiaddr to the trusted peers (run in background, as the node needs to be running)
  append_trusted_peers &
  # give validator some time to set up
  sleep 4
  # Start the bridge node
  echo "Configuration finished. Running a bridge node..."
  celestia bridge start \
    --rpc.skip-auth=$SKIP_AUTH \
    --rpc.addr 0.0.0.0 \
    --core.ip validator \
    --keyring.keyname "$NODE_NAME" \
    --p2p.network "$P2P_NETWORK"
}

main
