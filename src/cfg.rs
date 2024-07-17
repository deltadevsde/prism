use clap::{Parser, Subcommand};
use config::{builder::DefaultState, ConfigBuilder, File};
use dirs::home_dir;
use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, sync::Arc};

use crate::da::{
    celestia::CelestiaConnection, mock::LocalDataAvailabilityLayer, DataAvailabilityLayer,
};

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

    // Height to start searching the DA layer for SNARKs on
    #[arg(short = 's', long)]
    celestia_start_height: Option<u64>,

    /// Duration between epochs in seconds
    #[arg(short, long)]
    epoch_time: Option<u64>,

    /// IP address for the webserver to listen on
    #[arg(long)]
    host: Option<String>,

    /// Port number for the webserver to listen on
    #[arg(short, long)]
    port: Option<u16>,

    #[arg(long)]
    verifying_key: Option<String>,

    #[arg(long)]
    config_path: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webserver: Option<WebServerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub celestia_config: Option<CelestiaConfig>,
    pub da_layer: Option<DALayerOption>,
    pub redis_config: Option<RedisConfig>,
    pub epoch_time: Option<u64>,
    pub verifying_key: Option<String>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum DALayerOption {
    #[default]
    Celestia,
    InMemory,
    None,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RedisConfig {
    pub connection_string: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        RedisConfig {
            connection_string: "redis://127.0.0.1/".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CelestiaConfig {
    pub connection_string: String,
    pub start_height: u64,
    pub namespace_id: String,
}

impl Default for CelestiaConfig {
    fn default() -> Self {
        CelestiaConfig {
            connection_string: "ws://localhost:26658".to_string(),
            start_height: 0,
            namespace_id: "00000000000000de1008".to_string(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            webserver: Some(WebServerConfig::default()),
            da_layer: Some(DALayerOption::default()),
            celestia_config: Some(CelestiaConfig::default()),
            redis_config: Some(RedisConfig::default()),
            epoch_time: Some(60),
            verifying_key: None,
        }
    }
}

pub fn load_config(args: CommandLineArgs) -> Result<Config, config::ConfigError> {
    dotenv().ok();
    std::env::set_var(
        "RUST_LOG",
        args.log_level.or(Some("INFO".to_string())).unwrap(),
    );
    pretty_env_logger::init();

    let config_path = args.config_path.unwrap_or_else(|| {
        let home_dir = home_dir().expect("failed to get home directory");
        format!("{}/.deimos/config.toml", home_dir.to_string_lossy())
    });

    // if the config file doesn't exist, create it with the default values
    if !Path::new(&config_path).exists() {
        if let Some(parent) = Path::new(&config_path).parent() {
            fs::create_dir_all(parent).unwrap();
        }

        let default_config = Config::default();
        let config_toml = toml::to_string(&default_config).unwrap();
        fs::write(&config_path, config_toml).unwrap();
    }

    let config_source = ConfigBuilder::<DefaultState>::default()
        .add_source(File::with_name(&config_path))
        .build()?;

    let default_config = Config::default();
    let loaded_config: Config = config_source.try_deserialize().unwrap_or_else(|e| {
        error!("deserializing config file: {}", e);
        Config::default()
    });

    // if the config file is missing a field, use the default value
    let merged_config = Config {
        webserver: loaded_config.webserver.or(default_config.webserver),
        redis_config: loaded_config.redis_config.or(default_config.redis_config),
        celestia_config: loaded_config
            .celestia_config
            .or(default_config.celestia_config),
        da_layer: loaded_config.da_layer.or(default_config.da_layer),
        epoch_time: loaded_config.epoch_time.or(default_config.epoch_time),
        verifying_key: loaded_config.verifying_key.or(default_config.verifying_key),
    };

    if args.verifying_key.clone().is_none() && merged_config.verifying_key.clone().is_none() {
        warn!("sequencer's public key was not provided, this is not recommended and epoch signatures will not be verified.")
    }

    Ok(Config {
        webserver: Some(WebServerConfig {
            host: args
                .host
                .unwrap_or(merged_config.webserver.clone().unwrap().host),
            port: args.port.unwrap_or(merged_config.webserver.unwrap().port),
        }),
        redis_config: Some(RedisConfig {
            connection_string: args
                .redis_client
                .unwrap_or(merged_config.redis_config.unwrap().connection_string),
        }),
        celestia_config: Some(CelestiaConfig {
            connection_string: args.celestia_client.unwrap_or(
                merged_config
                    .celestia_config
                    .clone()
                    .unwrap()
                    .connection_string,
            ),
            start_height: args
                .celestia_start_height
                .unwrap_or(merged_config.celestia_config.clone().unwrap().start_height),
            namespace_id: args
                .celestia_namespace_id
                .unwrap_or(merged_config.celestia_config.unwrap().namespace_id),
        }),
        da_layer: merged_config.da_layer,
        epoch_time: Some(args.epoch_time.unwrap_or(merged_config.epoch_time.unwrap())),
        verifying_key: args.verifying_key.or(merged_config.verifying_key),
    })
}

pub async fn initialize_da_layer(config: &Config) -> Arc<dyn DataAvailabilityLayer + 'static> {
    match config.da_layer.as_ref().unwrap() {
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
                    panic!("connecting to celestia: {}", e);
                }
            }
        }
        DALayerOption::InMemory => {
            Arc::new(LocalDataAvailabilityLayer::new()) as Arc<dyn DataAvailabilityLayer + 'static>
        }
        DALayerOption::None => panic!("No DA Layer"),
    }
}
