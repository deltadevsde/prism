pub mod cli;
pub mod settings;
pub mod sources;
pub mod models;
pub mod validation;

#[cfg(test)]
pub mod tests;

pub use cli::{Cli, Commands, CommandArgs};
pub use models::{Settings, DALayerOption};

use anyhow::{Context, Result};
use std::sync::Arc;
use log::{error, info};
use tokio::time::Duration;

// Database imports
use prism_storage::database::Database;
use prism_storage::inmemory::InMemoryDatabase;
use prism_storage::rocksdb::RocksDBConnection;
use prism_storage::redis::RedisConnection;

// DA layer imports
use prism_da::{DataAvailabilityLayer, LightDataAvailabilityLayer};
use prism_da::memory::InMemoryDataAvailabilityLayer;
use prism_da::celestia::{
    full_node::CelestiaConnection,
    light_client::LightClientConnection,
    utils::CelestiaConfig
};

use crate::settings::validation::validate_config;

// Constants for DA layer connection retries
const DA_RETRY_COUNT: usize = 3;
const DA_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Load and validate settings from all available sources based on the command line arguments.
///
/// # Precedence Order
/// 1. CLI parameters override all other sources
/// 2. Environment variables override config file
/// 3. Config file provides base values
///
/// # Process
/// - Initialize logging based on CLI args
/// - Determine home directory and ensure config file exists
/// - Load and merge configurations from all sources
/// - Validate the final configuration
///
/// # Returns
/// - Result<Settings>: The validated configuration or an error
pub fn settings(args: CommandArgs) -> Result<Settings> {
    // Initialize logging early based on CLI args
    sources::init_logging(&args.log_level);

    // Get home directory and ensure config file exists
    let home_path = sources::get_prism_home(&args)
        .context("Failed to determine Prism home directory")?;

    sources::ensure_config_file_exists(&home_path, &args.network_name)
        .context("Failed to ensure config file exists")?;

    // Load and merge configurations in order of precedence
    let config = load_and_merge_configs(&home_path, args)?;

    // Validate the final configuration
    validate_config(&config)?;

    Ok(config)
}

/// Load and merge configurations from different sources with proper precedence
fn load_and_merge_configs(home_path: &str, args: CommandArgs) -> Result<Settings> {
    let config_path = format!("{}/config.toml", home_path);
    info!("Loading configuration from {}", config_path);

    // Load from file (lowest precedence)
    let config_file = sources::load_from_file(&config_path)
        .context("Failed to load config from file")?;

    // Load from environment (middle precedence)
    let env_config = sources::load_from_env()
        .context("Failed to load config from environment variables")?;

    // Merge configs with proper precedence
    let mut settings_builder = config_file;
    settings_builder.merge(env_config);

    // Convert SettingsBuilder to Settings
    let config = settings_builder.to_settings()
        .context("Failed to convert settings to config")?;

    // Apply command line arguments (highest precedence)
    sources::apply_command_line_args(config, args)
        .context("Failed to apply command line arguments")
}

/// Initialize the database based on the configuration.
///
/// # Arguments
/// * `cfg` - The application settings containing database configuration
///
/// # Returns
/// * `Result<Arc<Box<dyn Database>>>` - A thread-safe reference to the database
pub fn initialize_db(cfg: &Settings) -> Result<Arc<Box<dyn Database>>> {
    // Convert the new database config format to the StorageBackend enum
    match cfg.db.db_type.as_str() {
        "RocksDB" => {
            if let Some(rocksdb_config) = &cfg.db.rocksdb_config {
                // Get the home directory to resolve relative paths
                let home_path = std::env::var("PRISM_HOME_PATH").unwrap_or_else(|_| {
                    dirs::home_dir()
                        .map(|p| format!("{}/.prism/{}/", p.to_string_lossy(), cfg.network.network_name))
                        .unwrap_or_else(|| "./".to_string())
                });

                // Resolve the path - if it's absolute, use it as is; if relative, resolve against home
                let path = if std::path::Path::new(&rocksdb_config.directory_path).is_absolute() {
                    rocksdb_config.directory_path.clone()
                } else {
                    format!("{}/{}", home_path, rocksdb_config.directory_path)
                };

                info!("Initializing RocksDB database at {}", path);
                let db_config = prism_storage::rocksdb::RocksDBConfig::new(&path);
                RocksDBConnection::new(&db_config)
                    .map_err(|e| anyhow::anyhow!("Failed to initialize RocksDB: {}", e))
                    .map(|db| Arc::new(Box::new(db) as Box<dyn Database>))
            } else {
                // Default to in-memory if no config is provided
                info!("RocksDB config missing, falling back to in-memory database");
                Ok(Arc::new(Box::new(InMemoryDatabase::new()) as Box<dyn Database>))
            }
        }
        "Redis" => {
            if let Some(redis_config) = &cfg.db.redis_config {
                info!("Initializing Redis database with connection: {}", redis_config.url);
                let db_config = prism_storage::redis::RedisConfig {
                    connection_string: redis_config.url.clone()
                };
                RedisConnection::new(&db_config)
                    .map_err(|e| anyhow::anyhow!("Failed to initialize Redis: {}", e))
                    .map(|db| Arc::new(Box::new(db) as Box<dyn Database>))
            } else {
                // Default to in-memory if no config is provided
                info!("Redis config missing, falling back to in-memory database");
                Ok(Arc::new(Box::new(InMemoryDatabase::new()) as Box<dyn Database>))
            }
        }
        _ => {
            info!("Initializing in-memory database");
            Ok(Arc::new(Box::new(InMemoryDatabase::new()) as Box<dyn Database>))
        }
    }
}

/// Initialize the data availability layer based on the configuration.
///
/// # Arguments
/// * `config` - The application settings containing DA layer configuration
///
/// # Returns
/// * `Result<Arc<dyn DataAvailabilityLayer + 'static>>` - A thread-safe reference to the DA layer
pub async fn initialize_da_layer(
    config: &Settings,
) -> Result<Arc<dyn DataAvailabilityLayer + 'static>> {
    match config.da_layer {
        DALayerOption::Celestia => initialize_celestia_da_layer(config).await,
        DALayerOption::InMemory => initialize_memory_da_layer(),
    }
}

/// Initialize Celestia data availability layer
async fn initialize_celestia_da_layer(
    config: &Settings,
) -> Result<Arc<dyn DataAvailabilityLayer + 'static>> {
    // Create a CelestiaConfig from our new structure
    let mut celestia_conf = CelestiaConfig::default();
    celestia_conf.connection_string = config.network.celestia_config.connection_string.clone();
    celestia_conf.start_height = config.network.celestia_config.start_height;
    celestia_conf.snark_namespace_id = config.network.celestia_config.snark_namespace_id.clone();
    celestia_conf.operation_namespace_id = config.network.celestia_config.operation_namespace_id.clone();

    info!("Connecting to Celestia node at {}", celestia_conf.connection_string);
    try_connect_to_celestia(&celestia_conf, None).await
}

/// Initialize in-memory data availability layer
fn initialize_memory_da_layer() -> Result<Arc<dyn DataAvailabilityLayer + 'static>> {
    info!("Initializing in-memory data availability layer");
    let (da_layer, _height_rx, _block_rx) = InMemoryDataAvailabilityLayer::new(30);
    Ok(Arc::new(da_layer) as Arc<dyn DataAvailabilityLayer + 'static>)
}

/// Helper function to retry connecting to Celestia
///
/// # Arguments
/// * `celestia_conf` - The Celestia configuration
/// * `retries` - Optional number of retries (defaults to DA_RETRY_COUNT)
///
/// # Returns
/// * `Result<Arc<dyn DataAvailabilityLayer + 'static>>` - A thread-safe reference to the DA layer
async fn try_connect_to_celestia(
    celestia_conf: &CelestiaConfig,
    retries: Option<usize>,
) -> Result<Arc<dyn DataAvailabilityLayer + 'static>> {
    let retry_count = retries.unwrap_or(DA_RETRY_COUNT);

    for attempt in 1..=retry_count {
        match CelestiaConnection::new(celestia_conf, None).await {
            Ok(da) => {
                info!("Successfully connected to Celestia node");
                return Ok(Arc::new(da) as Arc<dyn DataAvailabilityLayer + 'static>);
            }
            Err(e) => {
                if attempt == retry_count {
                    return Err(anyhow::anyhow!(
                        "Failed to connect to Celestia node after {} attempts: {}",
                        retry_count, e
                    ));
                }
                error!(
                    "Attempt {} to connect to Celestia node failed: {}. Retrying in {} seconds...",
                    attempt, e, DA_RETRY_INTERVAL.as_secs()
                );
                tokio::time::sleep(DA_RETRY_INTERVAL).await;
            }
        }
    }

    // This should never be reached due to the return in the last iteration
    Err(anyhow::anyhow!("Failed to connect to Celestia node"))
}

/// Initialize a light data availability layer client based on the configuration.
///
/// # Arguments
/// * `config` - The application settings containing DA layer configuration
///
/// # Returns
/// * `Result<Arc<dyn LightDataAvailabilityLayer + Send + Sync + 'static>>` - A thread-safe reference to the light DA layer
pub async fn initialize_light_da_layer(
    config: &Settings,
) -> Result<Arc<dyn LightDataAvailabilityLayer + Send + Sync + 'static>> {
    match config.da_layer {
        DALayerOption::Celestia => initialize_light_celestia_client(config).await,
        DALayerOption::InMemory => initialize_light_memory_da_layer(),
    }
}

/// Initialize a Celestia light client connection
async fn initialize_light_celestia_client(
    config: &Settings,
) -> Result<Arc<dyn LightDataAvailabilityLayer + Send + Sync + 'static>> {
    info!("Initializing Celestia light client connection");
    let network_config = config.network.to_da_network_config();
    LightClientConnection::new(&network_config)
        .await
        .context("Failed to initialize light client connection")
        .map(|connection| {
            Arc::new(connection) as Arc<dyn LightDataAvailabilityLayer + Send + Sync + 'static>
        })
}

/// Initialize an in-memory light data availability layer
fn initialize_light_memory_da_layer() -> Result<Arc<dyn LightDataAvailabilityLayer + Send + Sync + 'static>> {
    info!("Initializing in-memory light data availability layer");
    let (da_layer, _height_rx, _block_rx) = InMemoryDataAvailabilityLayer::new(30);
    Ok(Arc::new(da_layer))
}
