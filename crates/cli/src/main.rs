mod cfg;
mod node_types;

use cfg::{initialize_da_layer, initialize_db, load_config, Cli, Commands};
use clap::Parser;
use keystore_rs::{KeyChain, KeyStore, KeyStoreType};
use prism_keys::{CryptoAlgorithm, SigningKey};
use prism_serde::base64::ToBase64;
use sp1_sdk::{HashableKey, Prover as _, ProverClient};
use std::io::{Error, ErrorKind};

use node_types::NodeType;
use prism_lightclient::{events::EventChannel, LightClient};
use prism_prover::Prover;
use std::sync::Arc;

#[macro_use]
extern crate log;

pub const PRISM_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The main function that initializes and runs a prism client.
#[tokio::main()]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let args = match cli.clone().command {
        Commands::LightClient(args) | Commands::Prover(args) | Commands::FullNode(args) => args,
    };

    let config =
        load_config(args.clone()).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    let da = initialize_da_layer(&config)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    let start_height = config.clone().network.celestia_config.unwrap_or_default().start_height;

    let node: Arc<dyn NodeType> = match cli.command {
        Commands::LightClient(_) => {
            let verifying_key = config.network.verifying_key;

            let client = ProverClient::builder().mock().build();
            let (_, vk) = client.setup(PRISM_ELF);
            let event_channel = EventChannel::new();

            Arc::new(LightClient::new(
                da,
                start_height,
                verifying_key,
                vk.bytes32(),
                event_channel.publisher(),
            ))
        }
        Commands::Prover(_) => {
            let db =
                initialize_db(&config).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let signing_key = get_signing_key()?;
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
                Error::new(ErrorKind::Other, e.to_string())
            })?)
        }
        Commands::FullNode(_) => {
            let db =
                initialize_db(&config).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let signing_key = get_signing_key()?;

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
                Error::new(ErrorKind::Other, e.to_string())
            })?)
        }
    };

    node.start().await.map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
}

fn get_signing_key() -> std::io::Result<SigningKey> {
    let signing_key_chain = KeyStoreType::KeyChain(KeyChain)
        .get_signing_key()
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    SigningKey::from_algorithm_and_bytes(CryptoAlgorithm::Ed25519, signing_key_chain.as_bytes())
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid signing key: {}", e),
            )
        })
}
