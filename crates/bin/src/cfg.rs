use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use config::{builder::DefaultState, ConfigBuilder, File};
use dirs::home_dir;
use dotenvy::dotenv;
use log::{error, warn};
use prism_errors::{DataAvailabilityError, GeneralError, PrismError};
use prism_prover::webserver::WebServerConfig;
use prism_storage::redis::RedisConfig;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, sync::Arc};

use prism_da::{
    celestia::{CelestiaConfig, CelestiaConnection},
    consts::{DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    memory::InMemoryDataAvailabilityLayer,
    DataAvailabilityLayer,
};

#[derive(Clone, Debug, Subcommand, Deserialize)]
pub enum Commands {
    LightClient,
    Prover,
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

    /// Celestia Snark Namespace ID
    #[arg(long)]
    snark_namespace_id: Option<String>,

    /// Celestia Transaction Namespace ID
    #[arg(long)]
    transaction_namespace_id: Option<String>,

    // Height to start searching the DA layer for SNARKs on
    #[arg(short = 's', long)]
    celestia_start_height: Option<u64>,

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
    pub verifying_key: Option<String>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum DALayerOption {
    #[default]
    Celestia,
    InMemory,
    None,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            webserver: Some(WebServerConfig::default()),
            da_layer: Some(DALayerOption::default()),
            celestia_config: Some(CelestiaConfig::default()),
            redis_config: Some(RedisConfig::default()),
            verifying_key: None,
        }
    }
}

pub fn load_config(args: CommandLineArgs) -> Result<Config> {
    dotenv().ok();
    std::env::set_var(
        "RUST_LOG",
        args.clone().log_level.unwrap_or_else(|| "INFO".to_string()),
    );
    pretty_env_logger::init();

    let config_path = get_config_path(&args).context("Failed to determine config path")?;
    ensure_config_file_exists(&config_path).context("Failed to ensure config file exists")?;

    let config_source = ConfigBuilder::<DefaultState>::default()
        .add_source(File::with_name(&config_path))
        .build()
        .context("Failed to build config")?;

    let default_config = Config::default();
    let loaded_config: Config =
        config_source.try_deserialize().context("Failed to deserialize config file")?;

    let merged_config = merge_configs(loaded_config, default_config);
    let final_config = apply_command_line_args(merged_config, args);

    if final_config.verifying_key.is_none() {
        warn!("prover's public key was not provided. this is not recommended and epoch signatures will not be verified.");
    }

    Ok(final_config)
}

fn get_config_path(args: &CommandLineArgs) -> Result<String> {
    args.config_path
        .clone()
        .or_else(|| home_dir().map(|path| format!("{}/.prism/config.toml", path.to_string_lossy())))
        .ok_or_else(|| {
            GeneralError::MissingArgumentError("could not determine config path".to_string()).into()
        })
}

fn ensure_config_file_exists(config_path: &str) -> Result<()> {
    if !Path::new(config_path).exists() {
        if let Some(parent) = Path::new(config_path).parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        let default_config = Config::default();
        let config_toml =
            toml::to_string(&default_config).context("Failed to serialize default config")?;

        fs::write(config_path, config_toml).context("Failed to write default config to disk")?;
    }
    Ok(())
}

fn merge_configs(loaded: Config, default: Config) -> Config {
    Config {
        webserver: loaded.webserver.or(default.webserver),
        redis_config: loaded.redis_config.or(default.redis_config),
        celestia_config: loaded.celestia_config.or(default.celestia_config),
        da_layer: loaded.da_layer.or(default.da_layer),
        verifying_key: loaded.verifying_key.or(default.verifying_key),
    }
}

fn apply_command_line_args(config: Config, args: CommandLineArgs) -> Config {
    Config {
        webserver: Some(WebServerConfig {
            enabled: true,
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
            snark_namespace_id: args.snark_namespace_id.unwrap_or_else(|| {
                config
                    .celestia_config
                    .as_ref()
                    .map(|c| c.snark_namespace_id.clone())
                    .unwrap_or_else(|| CelestiaConfig::default().snark_namespace_id)
            }),
            transaction_namespace_id: Some(args.transaction_namespace_id.unwrap_or_else(|| {
                config
                    .celestia_config
                    .as_ref()
                    .map(|c| c.transaction_namespace_id.clone())
                    .unwrap_or_else(|| CelestiaConfig::default().transaction_namespace_id)
                    .unwrap()
            })),
        }),
        da_layer: config.da_layer,
        verifying_key: args.verifying_key.or(config.verifying_key),
    }
}

pub async fn initialize_da_layer(
    config: &Config,
) -> Result<Arc<dyn DataAvailabilityLayer + 'static>> {
    let da_layer = config.da_layer.as_ref().context("DA Layer not specified")?;

    match da_layer {
        DALayerOption::Celestia => {
            let celestia_conf =
                config.celestia_config.clone().context("Celestia configuration not found")?;

            for attempt in 1..=DA_RETRY_COUNT {
                match CelestiaConnection::new(&celestia_conf, Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJwdWJsaWMiLCJyZWFkIiwid3JpdGUiLCJhZG1pbiJdfQ.lyUUIegvG9MNObLElHw6DD3HM-xDoTktS7is6agjtC0")).await {
                    Ok(da) => return Ok(Arc::new(da) as Arc<dyn DataAvailabilityLayer + 'static>),
                    Err(e) => {
                        if attempt == DA_RETRY_COUNT {
                            return Err(DataAvailabilityError::NetworkError(format!(
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
            let (da_layer, _height_rx, _block_rx) = InMemoryDataAvailabilityLayer::new(30);
            Ok(Arc::new(da_layer) as Arc<dyn DataAvailabilityLayer + 'static>)
        }
        DALayerOption::None => Err(anyhow!(PrismError::ConfigError(
            "No DA Layer specified".into()
        ))),
    }
}
