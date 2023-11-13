pub mod da;
pub mod indexed_merkle_tree;
pub mod error;
mod node_types;
pub mod storage;
mod utils;
mod webserver;
pub mod zk_snark;

use clap::{Parser, Subcommand};
use config::{builder::DefaultState, ConfigBuilder, File, FileFormat};
use da::{LocalDataAvailabilityLayer, DataAvailabilityLayer};
use serde::Deserialize;

use dotenv::dotenv;
use std::sync::Arc;

use crate::{
    node_types::{LightClient, NodeType, Sequencer},
    storage::{Operation, RedisConnections}, da::CelestiaConnection,
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
    #[arg(short = 'c', long)]
    celestia_client: Option<String>,

    /// Celestia Namespace ID
    #[arg(short = 'n', long)]
    celestia_namespace_id: Option<String>,

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

#[derive(Debug, Default, Clone, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "serde", derive(SerializeDisplay, DeserializeFromStr))]
enum DALayerOption {
    #[default]
    Celestia,
    #[cfg(test)]
    InMemory,
    None,
}

#[derive(Clone, Debug, Subcommand, Deserialize)]
enum Commands {
    LightClient,
    Sequencer,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    log_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    webserver: Option<WebServerConfig>,
    da_layer: DALayerOption,
    #[serde(skip_serializing_if = "Option::is_none")]
    celestia_config: Option<CelestiaConfig>,
    epoch_time: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebServerConfig {
    pub ip: String,
    pub port: u16,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        WebServerConfig {
            ip: "127.0.0.1".to_string(),
            port: 8080,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct CelestiaConfig {
    connection_string: String,
    namespace_id: String,
}

impl Default for CelestiaConfig {
    fn default() -> Self {
        CelestiaConfig {
            connection_string: "ws://localhost:26658".to_string(),
            namespace_id: "00000000000000de1008".to_string(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            webserver: Some(WebServerConfig::default()),
            log_level: "DEBUG".to_string(),
            da_layer: DALayerOption::default(),
            celestia_config: Some(CelestiaConfig::default()),
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
        log_level: args.log_level.unwrap_or(default_config.log_level),
        webserver: Some(WebServerConfig {
            ip: args
                .ip
                .unwrap_or(default_config.webserver.as_ref().unwrap().ip.clone()),
            port: args
                .port
                .unwrap_or(default_config.webserver.as_ref().unwrap().port),
        }),
        da_layer: DALayerOption::default(),
        celestia_config: Some(CelestiaConfig {
            connection_string: args.celestia_client.unwrap_or(
                default_config
                    .celestia_config
                    .as_ref()
                    .unwrap()
                    .connection_string
                    .clone(),
            ),
            namespace_id: args.celestia_namespace_id.unwrap_or(
                default_config
                    .celestia_config
                    .as_ref()
                    .unwrap()
                    .namespace_id
                    .clone(),
            ),
        }),
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

    #[cfg(test)]
    let da = Some(Arc::new(LocalDataAvailabilityLayer::new()) as Arc<dyn DataAvailabilityLayer + 'static>);

    #[cfg(not(test))]
    let da = match &config.da_layer {
        DALayerOption::Celestia => {
            let celestia_conf = config.clone().celestia_config.unwrap();
            Some(Arc::new(
                CelestiaConnection::new(
                    &celestia_conf.connection_string,
                    None,
                    &celestia_conf.namespace_id,
                )
                .await,
            ) as Arc<dyn DataAvailabilityLayer + 'static>)
        },
        DALayerOption::None => None,
    };


    let node: Arc<dyn NodeType> = match args.command {
        // LightClients need a DA layer, so we can unwrap here
        Commands::LightClient {} => Arc::new(LightClient::new(da.unwrap())),
        Commands::Sequencer {} => Arc::new(Sequencer::new(
            // TODO: convert error to std::io::Error...is there a better solution?
            Arc::new(RedisConnections::new().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?),
            da,
            config,
        )),
    };
    
    node.start().await
}
