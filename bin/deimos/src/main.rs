use cfg::{initialize_da_layer, load_config};
use clap::Parser;
use keystore::{KeyChain, KeyStore, KeyStoreType};

use crate::cfg::{CommandLineArgs, Commands};
use dotenvy::dotenv;
use node_types::{LightClient, NodeType, Sequencer};
use std::sync::Arc;
use storage::RedisConnections;

#[macro_use]
extern crate log;

/// The main function that initializes and runs a deimos client.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = CommandLineArgs::parse();
    let config = load_config(args.clone()).unwrap();

    std::env::set_var("RUST_LOG", &config.log_level);

    pretty_env_logger::init();
    dotenv().ok();

    let da = initialize_da_layer(&config).await;

    let node: Arc<dyn NodeType> = match args.command {
        Commands::LightClient {} => Arc::new(LightClient::new(da, config.public_key)),
        Commands::Sequencer {} => Arc::new(Sequencer::new(
            Arc::new(
                RedisConnections::new(&config.clone().redis_config.unwrap())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?,
            ),
            da,
            config,
            KeyStoreType::KeyChain(KeyChain).get_signing_key().unwrap(),
        )),
    };

    node.start()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}
