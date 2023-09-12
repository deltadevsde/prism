pub mod da;
pub mod indexed_merkle_tree;
pub mod storage;
mod utils;
mod webserver;
pub mod zk_snark;

use actix_cors::Cors;
use actix_web::{
    get, post,
    rt::spawn,
    web::{self, Data},
    App as ActixApp, HttpResponse, HttpServer, Responder,
};
use bellman::groth16;
use bls12_381::Bls12;
use celestia_rpc::client::new_websocket;
use celestia_types::nmt::Namespace;
use clap::{Parser, Subcommand};
use config::{builder::DefaultState, ConfigBuilder, File, FileFormat};
use da::CelestiaConnection;
use indexed_merkle_tree::{sha256, ProofVariant};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{self, json, Value};
use storage::Sequencer;

use core::panic;
use dotenv::dotenv;
use num::{BigInt, Num};
use openssl::{
    conf,
    ssl::{SslAcceptor, SslFiletype, SslMethod},
};
use std::{
    env,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::sleep;

use crate::{
    storage::{ChainEntry, DerivedEntry, Entry, Operation, RedisConnections, UpdateEntryJson},
    utils::{is_not_revoked, validate_epoch, validate_epoch_from_proof_variants, validate_proof},
    zk_snark::{
        deserialize_custom_to_verifying_key, deserialize_proof, serialize_proof,
        HashChainEntryCircuit,
    },
};

#[macro_use]
extern crate log;

#[derive(Parser, Clone, Debug, Deserialize)]
#[command(author, version, about, long_about = None)]
struct CommandLineArgs {
    /// Log level
    #[arg(short, long)]
    log_level: Option<String>,

    /// Celestia Client websocket URL
    #[arg(short, long)]
    celestia_client: Option<String>,

    /// Celestia Namespace ID
    #[arg(short, long)]
    namespace_id: Option<String>,

    /// Duration between epochs in seconds
    #[arg(short, long)]
    epoch_time: Option<u64>,

    /// IP address
    #[arg(short, long)]
    ip: Option<String>,

    /// Port number
    #[arg(short, long)]
    port: Option<u16>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, Subcommand, Deserialize)]
enum Commands {
    LightClient,
    Sequencer,
}

#[derive(Debug, Deserialize)]
struct Config {
    ip: String,
    port: u16,
    log_level: String,
    celestia_connection_string: String,
    namespace_id: String,
    epoch_time: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ip: "127.0.0.1".to_string(),
            port: 8080,
            log_level: "DEBUG".to_string(),
            celestia_connection_string: "ws://localhost:26658".to_string(),
            namespace_id: "00000000000000de1008".to_string(),
            epoch_time: 60,
        }
    }
}

fn load_config(args: CommandLineArgs) -> Result<Config, config::ConfigError> {
    let settings = ConfigBuilder::<DefaultState>::default()
        .add_source(File::from_str(
            include_str!("config.toml"),
            FileFormat::Toml,
        ))
        .build()?;

    println!("{}", settings.get_string("log_level").unwrap_or_default());

    let default_config = Config::default();

    Ok(Config {
        ip: args.ip.unwrap_or(default_config.ip),
        port: args.port.unwrap_or(default_config.port),
        log_level: args.log_level.unwrap_or(default_config.log_level),
        celestia_connection_string: args
            .celestia_client
            .unwrap_or(default_config.celestia_connection_string),
        namespace_id: args.namespace_id.unwrap_or(default_config.namespace_id),
        epoch_time: args
            .epoch_time
            .map(|e| e as u64)
            .unwrap_or(default_config.epoch_time),
    })
}

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

    info!("Starting server at {}", &config.celestia_connection_string);

    let da = Arc::new(
        CelestiaConnection::new(
            &config.celestia_connection_string,
            None,
            &config.namespace_id,
        )
        .await,
    );

    let session = Arc::new(Sequencer {
        db: Arc::new(RedisConnections::new()),
        da,
    });
    let sequencer_session = Arc::clone(&session);

    spawn(async move {
        match args.command {
            Commands::LightClient {} => {
                lightclient_loop(&sequencer_session).await;
            }
            Commands::Sequencer {} => {
                sequencer_loop(&sequencer_session, config.epoch_time).await;
            }
        }
    });

    let ctx = Data::new(session);
}
