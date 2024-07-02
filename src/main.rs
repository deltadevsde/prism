mod cfg;
pub mod da;
pub mod error;
mod node_types;
pub mod storage;
mod utils;
mod webserver;
pub mod zk_snark;
extern crate keystore;

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

/// The main function that initializes and runs the Actix web server.
///
/// # Behavior
/// 1. Loads environment variables using `dotenv` and sets up the server configuration.
/// 2. Spawns a task that runs the `initialize_or_increment_epoch_state` function in a loop for epoch-based behavior of the application
/// 3. Sets up CORS (Cross-Origin Resource Sharing) rules to allow specific origins and headers.
/// 4. Registers routes for various services.
/// 5. Binds the server to the configured IP and port.
/// 6. Runs the server and awaits its completion.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = CommandLineArgs::parse();
    let config = load_config(args.clone()).unwrap();

    std::env::set_var("RUST_LOG", &config.log_level);

    pretty_env_logger::init();
    dotenv().ok();

    let da = initialize_da_layer(&config).await;

    let node: Arc<dyn NodeType> = match args.command {
        // LightClients need a DA layer, so we can unwrap here
        Commands::LightClient {} => Arc::new(LightClient::new(da.unwrap(), config.public_key)),
        Commands::Sequencer {} => Arc::new(Sequencer::new(
            // TODO: convert error to std::io::Error...is there a better solution?
            Arc::new(
                RedisConnections::new()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?,
            ),
            da,
            config,
            KeyStoreType::KeyChain(KeyChain).get_signing_key().unwrap(),
        )),
    };

    node.start().await
}
