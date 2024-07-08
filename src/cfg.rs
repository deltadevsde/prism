use clap::{Parser, Subcommand};
use config::{builder::DefaultState, ConfigBuilder, File, FileFormat};
use serde::Deserialize;
use std::sync::Arc;

use crate::da::{
    CelestiaConnection,
    LocalDataAvailabilityLayer
};

use crate::da::DataAvailabilityLayer;

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

    #[arg(short = 'r', long)]
    redis_client: Option<String>,

    /// Celestia Namespace ID
    #[arg(short = 'n', long)]
    celestia_namespace_id: Option<String>,

    /// Duration between epochs in seconds
    #[arg(short, long)]
    epoch_time: Option<u64>,

    /// IP address for the webserver to listen on
    #[arg(short, long)]
    host: Option<String>,

    /// Port number for the webserver to listen on
    #[arg(short, long)]
    port: Option<u16>,

    #[arg(long)]
    public_key: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webserver: Option<WebServerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub celestia_config: Option<CelestiaConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]

    pub log_level: String,
    pub da_layer: DALayerOption,
    pub redis_config: Option<RedisConfig>,
    pub epoch_time: u64,
    pub public_key: Option<String>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "serde", derive(SerializeDisplay, DeserializeFromStr))]
pub enum DALayerOption {
    #[default]
    Celestia,
    InMemory,
    None,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        WebServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub connection_string: String
}

impl Default for RedisConfig {
    fn default() -> Self {
        RedisConfig{
            connection_string: "redis://127.0.0.1/".to_string()
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CelestiaConfig {
    pub connection_string: String,
    pub namespace_id: String,
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
            redis_config: Some(RedisConfig::default()),
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
            host: args
                .host
                .unwrap_or(default_config.webserver.as_ref().unwrap().host.clone()),
            port: args
                .port
                .unwrap_or(default_config.webserver.as_ref().unwrap().port),
        }),
        da_layer: DALayerOption::default(),
        redis_config: Some(RedisConfig {
            connection_string: args.redis_client.unwrap_or(
                default_config.redis_config.as_ref().unwrap().connection_string.clone()
            )
        }),
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

pub async fn initialize_da_layer(config: &Config) -> Arc<dyn DataAvailabilityLayer + 'static> {
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
                Ok(da) => Arc::new(da) as Arc<dyn DataAvailabilityLayer + 'static>,
                Err(e) => {
                    panic!("Failed to connect to Celestia: {}", e);
                }
            }
        }
        DALayerOption::InMemory => Arc::new(LocalDataAvailabilityLayer::new()) as Arc<dyn DataAvailabilityLayer + 'static>,
        DALayerOption::None => panic!("No DA Layer"),
    }
}