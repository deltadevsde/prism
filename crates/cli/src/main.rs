mod cfg;
mod node_types;

use cfg::{initialize_da_layer, load_config, Cli, Commands};
use clap::Parser;
use keystore_rs::{KeyChain, KeyStore, KeyStoreType};
use prism_keys::{SigningKey, VerifyingKey};

use node_types::NodeType;
use prism_lightclient::LightClient;
use prism_prover::Prover;
use prism_storage::RedisConnection;
use std::sync::Arc;

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

            let prover_vk = VerifyingKey::from_algorithm_and_bytes(config.verifying_key_algorithm.as_str(), config.verifying_key.unwrap().as_bytes()).unwrap();

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

            let signing_key = SigningKey::from_algorithm_and_bytes(config.verifying_key_algorithm.as_str(), signing_key_chain.as_bytes()).unwrap();
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
                VerifyingKey::from(prover_cfg.verifying_key.clone())
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

            let signing_key = SigningKey::from_algorithm_and_bytes(config.verifying_key_algorithm.as_str(), signing_key_chain.as_bytes()).unwrap();

            let prover_vk = VerifyingKey::from_algorithm_and_bytes(config.verifying_key_algorithm.as_str(), config.verifying_key.unwrap().as_bytes()).unwrap();

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
