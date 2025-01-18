use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use config::{builder::DefaultState, ConfigBuilder, File};
use dirs::home_dir;
use dotenvy::dotenv;
use log::{error, warn};
use prism_errors::{DataAvailabilityError, GeneralError};
use prism_prover::webserver::WebServerConfig;
use prism_storage::{
    database::StorageBackend,
    inmemory::InMemoryDatabase,
    redis::RedisConfig,
    rocksdb::{RocksDBConfig, RocksDBConnection},
    Database, RedisConnection,
};
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
    LightClient(CommandArgs),
    FullNode(CommandArgs),
    Prover(CommandArgs),
}

#[derive(Args, Deserialize, Clone, Debug)]
pub struct CommandArgs {
    /// Log level
    #[arg(short, long, default_value = "INFO")]
    log_level: String,

    #[arg(short = 'n', long, default_value = "local")]
    network_name: Option<String>,

    #[arg(long)]
    verifying_key: Option<String>,

    /// The algorithm used for the verifying key.
    ///
    /// Can be one of: `ed25519`, `secp256k1`, `secp256r1`.
    #[arg(long, default_value = "ed25519")]
    verifying_key_algorithm: Option<String>,

    #[arg(long)]
    home_path: Option<String>,

    #[command(flatten)]
    database: DatabaseArgs,

    #[command(flatten)]
    celestia: CelestiaArgs,

    #[command(flatten)]
    webserver: WebserverArgs,
}

#[derive(Parser, Clone, Debug, Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args, Deserialize, Clone, Debug)]
#[group(required = false, multiple = true)]
struct CelestiaArgs {
    /// Celestia Client websocket URL
    #[arg(short = 'c', long)]
    celestia_client: Option<String>,

    /// Celestia Snark Namespace ID
    #[arg(long)]
    snark_namespace_id: Option<String>,

    /// Celestia Transaction Namespace ID
    #[arg(long)]
    operation_namespace_id: Option<String>,

    /// Height to start searching the DA layer for SNARKs on
    #[arg(short = 's', long)]
    celestia_start_height: Option<u64>,
}

#[derive(Args, Deserialize, Clone, Debug)]
#[group(required = false, multiple = true)]
struct WebserverArgs {
    #[arg(long)]
    webserver_active: Option<bool>,

    /// IP address for the webserver to listen on
    #[arg(long, requires = "webserver_active", default_value = "127.0.0.1")]
    host: Option<String>,

    /// Port number for the webserver to listen on
    #[arg(short, long, requires = "webserver_active")]
    port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webserver: Option<WebServerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub celestia_config: Option<CelestiaConfig>,
    pub da_layer: DALayerOption,
    pub db: StorageBackend,
    pub verifying_key: Option<String>,
    pub verifying_key_algorithm: String,
}

impl Config {
    fn with_home(path: &str) -> Self {
        Config {
            webserver: Some(WebServerConfig::default()),
            celestia_config: Some(CelestiaConfig::default()),
            da_layer: DALayerOption::default(),
            db: StorageBackend::RocksDB(RocksDBConfig::new(&format!("{}/data", path))),
            verifying_key: None,
            verifying_key_algorithm: "ed25519".to_string(),
        }
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum DALayerOption {
    #[default]
    Celestia,
    InMemory,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
pub enum DBValues {
    #[default]
    RocksDB,
    InMemory,
    Redis,
}

#[derive(Args, Deserialize, Clone, Debug)]
pub struct DatabaseArgs {
    #[arg(long, value_enum, default_value_t = DBValues::RocksDB)]
    /// Storage backend to use. Default: `rocks-db`
    db_type: DBValues,

    /// Path to the RocksDB database, used when `db_type` is `rocks-db`
    #[arg(long)]
    rocksdb_path: Option<String>,

    /// Connection string to Redis, used when `db_type` is `redis`
    #[arg(long, required_if_eq("db_type", "redis"))]
    redis_url: Option<String>,
}

pub fn load_config(args: CommandArgs) -> Result<Config> {
    dotenv().ok();
    std::env::set_var("RUST_LOG", args.clone().log_level);
    pretty_env_logger::init();

    let home_path = get_prism_home(&args).context("Failed to determine prism home path")?;

    ensure_config_file_exists(&home_path).context("Failed to ensure config file exists")?;

    if let Some(rocksdb_path) = &args.database.rocksdb_path {
        fs::create_dir_all(rocksdb_path).context("Failed to create RocksDB directory")?;
    }

    let config_source = ConfigBuilder::<DefaultState>::default()
        .add_source(File::with_name(&format!("{}/config.toml", home_path)))
        .build()
        .context("Failed to build config")?;

    let loaded_config: Config =
        config_source.try_deserialize().context("Failed to deserialize config file")?;

    let final_config = apply_command_line_args(loaded_config, args);

    if final_config.verifying_key.is_none() {
        warn!("prover's public key was not provided. this is not recommended and epoch signatures will not be verified.");
    }

    Ok(final_config)
}

fn get_prism_home(args: &CommandArgs) -> Result<String> {
    let network_name = args.network_name.clone().unwrap_or_else(|| "custom".to_string());
    args.home_path
        .clone()
        .or_else(|| {
            home_dir().map(|path| format!("{}/.prism/{}/", path.to_string_lossy(), network_name))
        })
        .ok_or_else(|| {
            GeneralError::MissingArgumentError("could not determine config path".to_string()).into()
        })
}

fn ensure_config_file_exists(home_path: &str) -> Result<()> {
    let config_path = &format!("{}/config.toml", home_path);
    if !Path::new(config_path).exists() {
        if let Some(parent) = Path::new(config_path).parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        let default_config = Config::with_home(home_path);
        let config_toml =
            toml::to_string(&default_config).context("Failed to serialize default config")?;

        fs::write(config_path, config_toml).context("Failed to write default config to disk")?;
    }
    Ok(())
}

fn apply_command_line_args(config: Config, args: CommandArgs) -> Config {
    let webserver_config = &config.webserver.unwrap_or_default();
    let celestia_config = &config.celestia_config.unwrap_or_default();
    let prism_home = get_prism_home(&args.clone()).unwrap();

    Config {
        webserver: Some(WebServerConfig {
            enabled: args.webserver.webserver_active.unwrap_or(webserver_config.enabled),
            host: args.webserver.host.unwrap_or(webserver_config.host.clone()),
            port: args.webserver.port.unwrap_or(webserver_config.port),
        }),
        db: match args.database.db_type {
            DBValues::RocksDB => StorageBackend::RocksDB(RocksDBConfig {
                path: args.database.rocksdb_path.unwrap_or_else(|| format!("{}/data", prism_home)),
            }),
            DBValues::Redis => StorageBackend::Redis(RedisConfig {
                connection_string: args.database.redis_url.unwrap_or_default(),
            }),
            DBValues::InMemory => StorageBackend::InMemory,
        },
        celestia_config: Some(CelestiaConfig {
            connection_string: args
                .celestia
                .celestia_client
                .unwrap_or(celestia_config.connection_string.clone()),
            start_height: args
                .celestia
                .celestia_start_height
                .unwrap_or(celestia_config.start_height),
            snark_namespace_id: args
                .celestia
                .snark_namespace_id
                .unwrap_or(celestia_config.snark_namespace_id.clone()),
            operation_namespace_id: args
                .celestia
                .operation_namespace_id
                .unwrap_or(celestia_config.operation_namespace_id.clone()),
        }),
        da_layer: config.da_layer,
        verifying_key: args.verifying_key.or(config.verifying_key),
        verifying_key_algorithm: args
            .verifying_key_algorithm
            .unwrap_or(config.verifying_key_algorithm),
    }
}

pub fn initialize_db(cfg: &Config) -> Result<Arc<Box<dyn Database>>> {
    match &cfg.db {
        StorageBackend::RocksDB(cfg) => {
            let db = RocksDBConnection::new(cfg)
                .map_err(|e| GeneralError::InitializationError(e.to_string()))
                .context("Failed to initialize RocksDB")?;

            Ok(Arc::new(Box::new(db) as Box<dyn Database>))
        }
        StorageBackend::InMemory => Ok(Arc::new(
            Box::new(InMemoryDatabase::new()) as Box<dyn Database>
        )),
        StorageBackend::Redis(cfg) => {
            let db = RedisConnection::new(cfg)
                .map_err(|e| GeneralError::InitializationError(e.to_string()))
                .context("Failed to initialize Redis")?;
            Ok(Arc::new(Box::new(db) as Box<dyn Database>))
        }
    }
}

pub async fn initialize_da_layer(
    config: &Config,
) -> Result<Arc<dyn DataAvailabilityLayer + 'static>> {
    match config.da_layer {
        DALayerOption::Celestia => {
            let celestia_conf =
                config.celestia_config.clone().context("Celestia configuration not found")?;

            for attempt in 1..=DA_RETRY_COUNT {
                match CelestiaConnection::new(&celestia_conf, None).await {
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
    }
}
