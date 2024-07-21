use crate::consts::{DA_RETRY_COUNT, DA_RETRY_INTERVAL};
use crate::error::{DataAvailabilityError, PrismError, PrismResult, GeneralError};
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

pub fn load_config(args: CommandLineArgs) -> PrismResult<Config> {
    dotenv().ok();
    std::env::set_var(
        "RUST_LOG",
        args.clone().log_level.unwrap_or_else(|| "INFO".to_string()),
    );
    pretty_env_logger::init();

    let config_path = get_config_path(&args)?;
    ensure_config_file_exists(&config_path)?;

    let config_source = ConfigBuilder::<DefaultState>::default()
        .add_source(File::with_name(&config_path))
        .build()
        .map_err(|e| GeneralError::InitializationError(format!("building config: {}", e)))?;

    let default_config = Config::default();
    let loaded_config: Config = config_source.try_deserialize().unwrap_or_else(|e| {
        error!("deserializing config file: {}", e);
        Config::default()
    });

    let merged_config = merge_configs(loaded_config, default_config);
    let final_config = apply_command_line_args(merged_config, args);

    if final_config.verifying_key.is_none() {
        warn!("sequencer's public key was not provided. this is not recommended and epoch signatures will not be verified.");
    }

    Ok(final_config)
}

fn get_config_path(args: &CommandLineArgs) -> PrismResult<String> {
    args.config_path
        .clone()
        .or_else(|| {
            home_dir().map(|path| format!("{}/.prism/config.toml", path.to_string_lossy()))
        })
        .ok_or_else(|| {
            GeneralError::MissingArgumentError("could not determine config path".to_string()).into()
        })
}

fn ensure_config_file_exists(config_path: &str) -> PrismResult<()> {
    if !Path::new(config_path).exists() {
        if let Some(parent) = Path::new(config_path).parent() {
            fs::create_dir_all(parent).map_err(|e| {
                GeneralError::InitializationError(format!(
                    "failed to create config directory: {}",
                    e
                ))
            })?;
        }

        let default_config = Config::default();
        let config_toml = toml::to_string(&default_config).map_err(|e| {
            GeneralError::EncodingError(format!("failed to serialize default config: {}", e))
        })?;

        fs::write(config_path, config_toml).map_err(|e| {
            GeneralError::InitializationError(format!(
                "failed to write default config to disk: {}",
                e
            ))
        })?;
    }
    Ok(())
}

fn merge_configs(loaded: Config, default: Config) -> Config {
    Config {
        webserver: loaded.webserver.or(default.webserver),
        redis_config: loaded.redis_config.or(default.redis_config),
        celestia_config: loaded.celestia_config.or(default.celestia_config),
        da_layer: loaded.da_layer.or(default.da_layer),
        epoch_time: loaded.epoch_time.or(default.epoch_time),
        verifying_key: loaded.verifying_key.or(default.verifying_key),
    }
}

fn apply_command_line_args(config: Config, args: CommandLineArgs) -> Config {
    Config {
        webserver: Some(WebServerConfig {
            host: args.host.unwrap_or_else(|| {
                config
                    .webserver
                    .as_ref()
                    .map(|w| w.host.clone())
                    .unwrap_or_else(|| WebServerConfig::default().host)
            }),
            port: args.port.unwrap_or_else(|| {
                config
                    .webserver
                    .as_ref()
                    .map(|w| w.port)
                    .unwrap_or_else(|| WebServerConfig::default().port)
            }),
        }),
        redis_config: Some(RedisConfig {
            connection_string: args.redis_client.unwrap_or_else(|| {
                config
                    .redis_config
                    .as_ref()
                    .map(|r| r.connection_string.clone())
                    .unwrap_or_else(|| RedisConfig::default().connection_string)
            }),
        }),
        celestia_config: Some(CelestiaConfig {
            connection_string: args.celestia_client.unwrap_or_else(|| {
                config
                    .celestia_config
                    .as_ref()
                    .map(|c| c.connection_string.clone())
                    .unwrap_or_else(|| CelestiaConfig::default().connection_string)
            }),
            start_height: args.celestia_start_height.unwrap_or_else(|| {
                config
                    .celestia_config
                    .as_ref()
                    .map(|c| c.start_height)
                    .unwrap_or_else(|| CelestiaConfig::default().start_height)
            }),
            namespace_id: args.celestia_namespace_id.unwrap_or_else(|| {
                config
                    .celestia_config
                    .as_ref()
                    .map(|c| c.namespace_id.clone())
                    .unwrap_or_else(|| CelestiaConfig::default().namespace_id)
            }),
        }),
        da_layer: config.da_layer,
        epoch_time: Some(args.epoch_time.unwrap_or_else(|| {
            config
                .epoch_time
                .unwrap_or_else(|| Config::default().epoch_time.unwrap())
        })),
        verifying_key: args.verifying_key.or(config.verifying_key),
    }
}

pub async fn initialize_da_layer(
    config: &Config,
) -> PrismResult<Arc<dyn DataAvailabilityLayer + 'static>> {
    let da_layer = config.da_layer.as_ref().ok_or(PrismError::ConfigError(
        "DA Layer not specified".to_string(),
    ))?;

    match da_layer {
        DALayerOption::Celestia => {
            let celestia_conf = config
                .celestia_config
                .clone()
                .ok_or(PrismError::ConfigError(
                    "Celestia configuration not found".to_string(),
                ))?;

            for attempt in 1..=DA_RETRY_COUNT {
                match CelestiaConnection::new(
                    &celestia_conf.connection_string,
                    None,
                    &celestia_conf.namespace_id,
                )
                .await
                {
                    Ok(da) => return Ok(Arc::new(da) as Arc<dyn DataAvailabilityLayer + 'static>),
                    Err(e) => {
                        if attempt == DA_RETRY_COUNT {
                            return Err(DataAvailabilityError::ConnectionError(format!(
                                "failed to connect to celestia node after {} attempts: {}",
                                DA_RETRY_COUNT, e
                            ))
                            .into());
                        }
                        error!("Attempt {} to connect to celestia node failed: {}. Retrying in {} seconds...", attempt, e, DA_RETRY_INTERVAL.as_secs());
                        tokio::time::sleep(DA_RETRY_INTERVAL).await;
                    }
                }
            }
            unreachable!() // This line should never be reached due to the return in the last iteration
        }
        DALayerOption::InMemory => {
            Ok(Arc::new(LocalDataAvailabilityLayer::new())
                as Arc<dyn DataAvailabilityLayer + 'static>)
        }
        DALayerOption::None => Err(PrismError::ConfigError(
            "No DA Layer specified".to_string(),
        )),
    }
}
