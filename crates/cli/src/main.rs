mod cfg;
mod node_types;

use cfg::{initialize_da_layer, load_config, Cli, Commands};
use clap::Parser;
use keystore_rs::{KeyChain, KeyStore, KeyStoreType};
use prism_keys::{SigningKey, VerifyingKey, KeyAlgorithm};

use node_types::NodeType;
use prism_lightclient::LightClient;
use prism_prover::Prover;
use prism_storage::RedisConnection;
use std::sync::Arc;
use std::str::FromStr;
#[macro_use]
extern crate log;

pub const PRISM_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The main function that initializes and runs a prism client.
#[tokio::main()]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let node: Arc<dyn NodeType> = match cli.command {
        Commands::LightClient(args) => {
            let config = load_config(args.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let da = initialize_da_layer(&config)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let celestia_config = config.celestia_config.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "celestia configuration not found",
                )
            })?;

            let verifying_key_algorithm = validate_algorithm(&config.verifying_key_algorithm)?;

            let prover_vk = VerifyingKey::from_algorithm_and_bytes(
                KeyAlgorithm::from_str(verifying_key_algorithm).expect("Failed to create verifying key"),
                config.verifying_key.unwrap().as_bytes(),
            ).map_err(|e| std::io::Error::new(
              std::io::ErrorKind::InvalidData, format!("invalid prover verifying key: {}", e),
            ))?;

            Arc::new(LightClient::new(da, celestia_config, Some(prover_vk)))
        }
        Commands::Prover(args) => {
            let config = load_config(args.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let da = initialize_da_layer(&config)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let redis_config = config.clone().redis_config.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "redis configuration not found",
                )
            })?;
            let redis_connections = RedisConnection::new(&redis_config)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let signing_key_chain = KeyStoreType::KeyChain(KeyChain)
                .get_signing_key()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let verifying_key_algorithm = validate_algorithm(&config.verifying_key_algorithm)?;

            let signing_key = SigningKey::from_algorithm_and_bytes(
              KeyAlgorithm::from_str(verifying_key_algorithm).expect("Failed to create verifying key"),
              signing_key_chain.as_bytes())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid signing key: {}", e)))?;
            let verifying_key = signing_key.verifying_key();

            let prover_cfg = prism_prover::Config {
                prover: true,
                batcher: true,
                webserver: config.webserver.unwrap_or_default(),
                signing_key: signing_key.clone(),
                verifying_key: verifying_key.clone(),
                start_height: config.celestia_config.unwrap_or_default().start_height,
            };

            info!(
                "prover verifying key: {}",
                prover_cfg.verifying_key.clone()
            );

            Arc::new(
                Prover::new(Arc::new(Box::new(redis_connections)), da, &prover_cfg).map_err(
                    |e| {
                        error!("error initializing prover: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    },
                )?,
            )
        }
        Commands::FullNode(args) => {
            let config = load_config(args.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let da = initialize_da_layer(&config)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let redis_config = config.clone().redis_config.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "redis configuration not found",
                )
            })?;
            let redis_connections = RedisConnection::new(&redis_config)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let signing_key_chain = KeyStoreType::KeyChain(KeyChain)
                .get_signing_key()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let verifying_key_algorithm = validate_algorithm(&config.verifying_key_algorithm)?;

            let signing_key = SigningKey::from_algorithm_and_bytes(
              KeyAlgorithm::from_str(verifying_key_algorithm).expect("Failed to create verifying key"),
              signing_key_chain.as_bytes())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid signing key: {}", e)))?;

            let prover_vk = config
                .verifying_key
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "prover verifying key not found",
                    )
                })
                .and_then(|vk| VerifyingKey::from_algorithm_and_bytes(
                  KeyAlgorithm::from_str(verifying_key_algorithm).expect("Failed to create verifying key"),
                  vk.as_bytes()).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid prover verifying key: {}", e),
                    )
                }))?;

            let prover_cfg = prism_prover::Config {
                prover: false,
                batcher: true,
                webserver: config.webserver.unwrap_or_default(),
                signing_key: signing_key.clone(),
                verifying_key: prover_vk,
                start_height: config.celestia_config.unwrap_or_default().start_height,
            };

            Arc::new(
                Prover::new(Arc::new(Box::new(redis_connections)), da, &prover_cfg).map_err(
                    |e| {
                        error!("error initializing prover: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    },
                )?,
            )
        }
    };

    node.start().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

fn validate_algorithm(algorithm: &str) -> Result<&str, std::io::Error> {
    if algorithm.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "verifying key algorithm is required"));
    }

    if !["ed25519", "secp256k1", "secp256r1"].contains(&algorithm) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid verifying key algorithm"));
    }

    Ok(algorithm)
}
