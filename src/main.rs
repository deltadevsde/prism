mod cfg;
pub mod circuits;
pub mod common;
pub mod consts;
pub mod da;
pub mod error;
mod node_types;
pub mod storage;
mod utils;
mod webserver;

use cfg::{initialize_da_layer, load_config};
use clap::Parser;
use keystore_rs::{KeyChain, KeyStore, KeyStoreType};

use crate::cfg::{CommandLineArgs, Commands};
use node_types::{lightclient::LightClient, sequencer::Sequencer, NodeType};
use std::sync::Arc;
use storage::RedisConnection;

#[macro_use]
extern crate log;

/// The main function that initializes and runs a prism client.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = CommandLineArgs::parse();
    let config = load_config(args.clone())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let da = initialize_da_layer(&config)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let node: Arc<dyn NodeType> = match args.command {
        Commands::LightClient {} => {
            let celestia_config = config.celestia_config.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "celestia configuration not found",
                )
            })?;
            Arc::new(LightClient::new(da, celestia_config, config.verifying_key))
        }
        Commands::Sequencer {} => {
            let redis_config = config.clone().redis_config.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "redis configuration not found",
                )
            })?;
            let redis_connections = RedisConnection::new(&redis_config)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let signing_key = KeyStoreType::KeyChain(KeyChain)
                .get_signing_key()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            Arc::new(
                Sequencer::new(Arc::new(redis_connections), da, config, signing_key).map_err(
                    |e| {
                        error!("error initializing sequencer: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    },
                )?,
            )
        }
    };

    node.start()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}
