mod cfg;
mod node_types;

use cfg::{
    Cli, Commands, initialize_da_layer, initialize_db, initialize_light_da_layer, load_config,
};
use clap::Parser;
use keystore_rs::{FileStore, KeyChain, KeyStore};
use prism_keys::{CryptoAlgorithm, SigningKey};
use prism_serde::base64::ToBase64;
use std::io::{Error, ErrorKind};

use node_types::NodeType;
use prism_lightclient::{LightClient, events::EventChannel};
use prism_prover::Prover;
use std::sync::Arc;

#[macro_use]
extern crate log;

pub const SIGNING_KEY_ID: &str = "prism";

/// The main function that initializes and runs a prism client.
#[tokio::main()]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let args = match cli.clone().command {
        Commands::LightClient(args) | Commands::Prover(args) | Commands::FullNode(args) => args,
    };

    let config = load_config(args.clone()).map_err(|e| Error::other(e.to_string()))?;

    let start_height = config.clone().network.celestia_config.unwrap_or_default().start_height;

    let node: Arc<dyn NodeType> = match cli.command {
        Commands::LightClient(_) => {
            let verifying_key = config.network.verifying_key.clone();

            let da = initialize_light_da_layer(&config).await.map_err(|e| {
                error!("error initializing light da layer: {}", e);
                Error::other(e.to_string())
            })?;

            let event_channel = EventChannel::new();

            Arc::new(LightClient::new(
                da,
                start_height,
                verifying_key,
                event_channel.publisher(),
            ))
        }
        Commands::Prover(_) => {
            let db = initialize_db(&config).map_err(|e| Error::other(e.to_string()))?;

            let da = initialize_da_layer(&config).await.map_err(|e| Error::other(e.to_string()))?;
            info!(
                "keystore type: {:?}",
                config.clone().keystore_type.unwrap_or_default()
            );

            info!("SP1_PROVER: {:?}", std::env::var("SP1_PROVER"));

            let signing_key = get_signing_key(config.keystore_type, config.keystore_path)?;
            let verifying_key = signing_key.verifying_key();

            info!(
                "prover's verifying key: {}",
                verifying_key.to_bytes().to_base64()
            );

            let prover_cfg = prism_prover::Config {
                prover: true,
                batcher: true,
                webserver: config.webserver.unwrap_or_default(),
                signing_key,
                verifying_key,
                start_height,
            };

            Arc::new(Prover::new(db, da, &prover_cfg).map_err(|e| {
                error!("error initializing prover: {}", e);
                Error::other(e.to_string())
            })?)
        }
        Commands::FullNode(_) => {
            let db = initialize_db(&config).map_err(|e| Error::other(e.to_string()))?;

            let da = initialize_da_layer(&config).await.map_err(|e| Error::other(e.to_string()))?;

            info!(
                "keystore type: {:?}",
                config.clone().keystore_type.unwrap_or_default()
            );

            info!("SP1_PROVER: {:?}", std::env::var("SP1_PROVER"));

            let signing_key = get_signing_key(config.keystore_type, config.keystore_path)?;

            let verifying_key = config
                .network
                .verifying_key
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "prover verifying key not found"))?;

            let prover_cfg = prism_prover::Config {
                prover: false,
                batcher: true,
                webserver: config.webserver.unwrap_or_default(),
                signing_key,
                verifying_key,
                start_height,
            };

            Arc::new(Prover::new(db, da, &prover_cfg).map_err(|e| {
                error!("error initializing prover: {}", e);
                Error::other(e.to_string())
            })?)
        }
    };

    node.start().await.map_err(|e| Error::other(e.to_string()))
}

fn get_signing_key(
    keystore_type: Option<String>,
    keystore_path: Option<String>,
) -> std::io::Result<SigningKey> {
    let keystore: Box<dyn KeyStore> = match keystore_type.unwrap_or_default().as_str() {
        "file" => {
            let file_store = FileStore::new(keystore_path.unwrap_or_default())
                .map_err(|e| Error::other(e.to_string()))?;
            Box::new(file_store)
        }
        "keychain" => Box::new(KeyChain),
        _ => {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid keystore type"));
        }
    };

    let raw_signing_key = keystore
        .get_or_create_signing_key(SIGNING_KEY_ID)
        .map_err(|e| Error::other(format!("Failed to get or create signing key: {}", e)))?;

    // Hardcoded ED25519 as keystore_rs only supports ED25519
    let signing_key =
        SigningKey::from_algorithm_and_bytes(CryptoAlgorithm::Ed25519, raw_signing_key.as_bytes())
            .map_err(|e| Error::other(format!("Failed to parse signing key: {}", e)))?;

    Ok(signing_key)
}
