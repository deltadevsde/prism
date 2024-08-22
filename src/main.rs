mod cfg;
pub mod common;
pub mod consts;
pub mod da;
pub mod error;
mod node_types;
mod nova;
pub mod storage;
mod tree;
mod utils;
mod webserver;

use cfg::{initialize_da_layer, load_config};
use clap::Parser;
use keystore_rs::{KeyChain, KeyStore, KeyStoreType};
use prism::nova::utils::create_pp;

use crate::cfg::{CommandLineArgs, Commands};
use anyhow::{Context, Result};
use arecibo::{provider::PallasEngine, supernova::PublicParams};
use node_types::{lightclient::LightClient, sequencer::Sequencer, NodeType};
use std::io;
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

    let pp = load_or_generate_public_params(&config.public_params_path)
        .expect("Failed to deserialize or generate public params.");

    if let Commands::GeneratePublicParams {} = args.command {
        bincode::serialize_into(io::stdout(), &pp).unwrap();
        return Ok(());
    }

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
                Sequencer::new(
                    Arc::new(Box::new(redis_connections)),
                    da,
                    config,
                    signing_key,
                )
                .map_err(|e| {
                    error!("error initializing sequencer: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                })?,
            )
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid node type",
            ));
        }
    };

    node.start()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

fn load_or_generate_public_params(path: &Option<String>) -> Result<PublicParams<PallasEngine>> {
    if let Some(path) = path {
        info!("Loading public params from file: {:?}", path);
        let bytes = std::fs::read(path).context("Failed to read public params file")?;
        bincode::deserialize(&bytes).context("Failed to deserialize public params")
    } else {
        warn!("No public params file provided, generating new ones. This may take a while.");
        Ok(create_pp())
    }
}
