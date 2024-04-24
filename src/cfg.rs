use clap::{Parser, Subcommand};
use config::{builder::DefaultState, ConfigBuilder, File, FileFormat};
use serde::Deserialize;
use std::sync::Arc;

use crate::da::{CelestiaConnection, DataAvailabilityLayer, LocalDataAvailabilityLayer};

#[derive(Clone, Debug, Subcommand, Deserialize)]
pub enum Commands {
    LightClient,
    Sequencer,
}

#[derive(Parser, Clone, Debug, Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct CommandLineArgs {
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

    #[arg(long)]
    public_key: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub log_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webserver: Option<WebServerConfig>,
    pub da_layer: DALayerOption,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub celestia_config: Option<CelestiaConfig>,
    pub epoch_time: u64,
    pub public_key: Option<String>,
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
            public_key: None,
        }
    }
}

pub fn load_config(args: CommandLineArgs) -> Result<Config, config::ConfigError> {
    let settings = ConfigBuilder::<DefaultState>::default()
        .add_source(File::from_str(
            include_str!("config.toml"),
            FileFormat::Toml,
        ))
        .build()?;

    info!("{}", settings.get_string("log_level").unwrap_or_default());

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
        public_key: args.public_key.or(default_config.public_key),
    })
}

#[cfg(not(test))]
pub async fn initialize_da_layer(
    config: &Config,
) -> Option<Arc<dyn DataAvailabilityLayer + 'static>> {
    match &config.da_layer {
        DALayerOption::Celestia => {
            let celestia_conf = config.clone().celestia_config.unwrap();
            match CelestiaConnection::new(
                &celestia_conf.connection_string,
                None,
                &celestia_conf.namespace_id,
            )
            .await
            {
                Ok(da) => Some(Arc::new(da) as Arc<dyn DataAvailabilityLayer + 'static>),
                Err(e) => {
                    error!("Failed to connect to Celestia: {}", e);
                    None
                }
            }
        }
        DALayerOption::None => None,
    }
}

#[cfg(test)]
pub async fn initialize_da_layer(
    _config: &Config,
) -> Option<Arc<dyn DataAvailabilityLayer + 'static>> {
    Some(Arc::new(LocalDataAvailabilityLayer::new()) as Arc<dyn DataAvailabilityLayer + 'static>)
}
