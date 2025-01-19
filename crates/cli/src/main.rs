mod cfg;
mod node_types;

use cfg::{initialize_da_layer, load_config, Cli, Commands};
use clap::Parser;
use keystore_rs::{FileStore, KeyChain, KeyStore};
use prism_keys::{CryptoAlgorithm, SigningKey, VerifyingKey};
use sp1_sdk::{HashableKey, ProverClient};
use std::io::{Error, ErrorKind};

use node_types::NodeType;
use prism_lightclient::LightClient;
use prism_prover::Prover;
use prism_storage::RedisConnection;
use std::{str::FromStr, sync::Arc};

#[macro_use]
extern crate log;

pub const PRISM_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

pub const SIGNING_KEY_ID: &str = "prism";

/// The main function that initializes and runs a prism client.
#[tokio::main()]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let node: Arc<dyn NodeType> = match cli.command {
        Commands::LightClient(args) => {
            let config = load_config(args.clone())
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let da = initialize_da_layer(&config)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let celestia_config = config.celestia_config.ok_or_else(|| {
                Error::new(ErrorKind::NotFound, "celestia configuration not found")
            })?;

            let verifying_key_algorithm =
                CryptoAlgorithm::from_str(&config.verifying_key_algorithm).map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "invalid verifying key algorithm format",
                    )
                })?;
            let prover_vk = VerifyingKey::from_algorithm_and_bytes(
                verifying_key_algorithm,
                config.verifying_key.unwrap().as_bytes(),
            )
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;

            let client = ProverClient::mock();
            let (_, vk) = client.setup(PRISM_ELF);

            Arc::new(LightClient::new(
                da,
                celestia_config,
                Some(prover_vk),
                vk.bytes32(),
            ))
        }
        Commands::Prover(args) => {
            let config = load_config(args.clone())
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let da = initialize_da_layer(&config)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let redis_config = config
                .clone()
                .redis_config
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "redis configuration not found"))?;
            let redis_connections = RedisConnection::new(&redis_config)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let keystore: Box<dyn KeyStore> =
                match config.keystore_type.unwrap_or_default().as_str() {
                    "file" => Box::new(
                        FileStore::new(config.keystore_path.unwrap_or_default()).map_err(|e| {
                            Error::new(
                                ErrorKind::Other,
                                format!("Failed to create FileStore: {}", e),
                            )
                        })?,
                    ),
                    "keychain" => Box::new(KeyChain),
                    _ => {
                        return Err(Error::new(ErrorKind::InvalidInput, "invalid keystore type"));
                    }
                };

            let raw_signing_key =
                keystore.get_or_create_signing_key(SIGNING_KEY_ID).map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Failed to get or create signing key: {}", e),
                    )
                })?;

            let verifying_key_algorithm =
                CryptoAlgorithm::from_str(&config.verifying_key_algorithm).map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "invalid verifying key algorithm format",
                    )
                })?;

            let signing_key = SigningKey::from_algorithm_and_bytes(
                verifying_key_algorithm,
                raw_signing_key.as_bytes(),
            )
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid signing key: {}", e),
                )
            })?;

            let verifying_key = signing_key.verifying_key();

            let prover_cfg = prism_prover::Config {
                prover: true,
                batcher: true,
                webserver: config.webserver.unwrap_or_default(),
                signing_key: signing_key.clone(),
                verifying_key: verifying_key.clone(),
                start_height: config.celestia_config.unwrap_or_default().start_height,
            };

            Arc::new(
                Prover::new(Arc::new(Box::new(redis_connections)), da, &prover_cfg).map_err(
                    |e| {
                        error!("error initializing prover: {}", e);
                        Error::new(ErrorKind::Other, e.to_string())
                    },
                )?,
            )
        }
        Commands::FullNode(args) => {
            let config = load_config(args.clone())
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let da = initialize_da_layer(&config)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let redis_config = config
                .clone()
                .redis_config
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "redis configuration not found"))?;
            let redis_connections = RedisConnection::new(&redis_config)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            let keystore: Box<dyn KeyStore> =
                match config.keystore_type.unwrap_or_default().as_str() {
                    "file" => Box::new(
                        FileStore::new(config.keystore_path.unwrap_or_default()).map_err(|e| {
                            Error::new(
                                ErrorKind::Other,
                                format!("Failed to create FileStore: {}", e),
                            )
                        })?,
                    ),
                    "keychain" => Box::new(KeyChain),
                    _ => {
                        return Err(Error::new(ErrorKind::InvalidInput, "invalid keystore type"));
                    }
                };

            let raw_signing_key =
                keystore.get_or_create_signing_key(SIGNING_KEY_ID).map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Failed to get or create signing key: {}", e),
                    )
                })?;

            let verifying_key_algorithm =
                CryptoAlgorithm::from_str(&config.verifying_key_algorithm).map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "invalid verifying key algorithm format",
                    )
                })?;

            let signing_key = SigningKey::from_algorithm_and_bytes(
                verifying_key_algorithm,
                raw_signing_key.as_bytes(),
            )
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid signing key: {}", e),
                )
            })?;

            let prover_vk = config
                .verifying_key
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "prover verifying key not found"))
                .and_then(|vk| {
                    VerifyingKey::from_algorithm_and_bytes(verifying_key_algorithm, vk.as_bytes())
                        .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))
                })?;

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
                        Error::new(ErrorKind::Other, e.to_string())
                    },
                )?,
            )
        }
    };

    node.start().await.map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
}
