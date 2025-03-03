use anyhow::{Context, Result};
use config::{Config as ConfigSource, File};
use prism_errors::GeneralError;
use crate::settings::{
    models::{
        Settings, DALayerOption, NetworkConfig,
        RocksDBConfig, RedisConfig
    },
    cli::{CommandArgs, DBValues},
    settings::SettingsBuilder
};
use std::{fs, path::Path};
use dirs::home_dir;
use dotenvy::dotenv;
use prism_keys::VerifyingKey;
use prism_da::celestia::utils::Network;
use log;

const PREFIX: &str = "PRISM_";

/// Initialize logging
pub fn init_logging(log_level: &str) {
    dotenv().ok();
    std::env::set_var("RUST_LOG", log_level);
    pretty_env_logger::init();
}

/// Get the Prism home directory
pub fn get_prism_home(args: &CommandArgs) -> Result<String> {
    let network_name = args.network_name.clone();
    args.home_path
        .clone()
        .or_else(|| {
            home_dir().map(|path| format!("{}/.prism/{}/", path.to_string_lossy(), network_name))
        })
        .ok_or_else(|| {
            GeneralError::MissingArgumentError("could not determine config path".to_string()).into()
        })
}

/// Ensure the config file exists, creating a default one if it doesn't
pub fn ensure_config_file_exists(home_path: &str, network_name: &str) -> Result<()> {
    let config_path = &format!("{}/config.toml", home_path);
    if !Path::new(config_path).exists() {
        if let Some(parent) = Path::new(config_path).parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        let default_config = Settings::initialize(home_path, network_name);
        let config_toml =
            toml::to_string(&default_config).context("Failed to serialize default config")?;

        fs::write(config_path, config_toml).context("Failed to write default config to disk")?;
    }
    Ok(())
}

/// Load configuration from a TOML file
pub fn load_from_file(config_path: &str) -> Result<SettingsBuilder> {
    let config_source = ConfigSource::builder()
        .add_source(File::with_name(config_path))
        .build()
        .context("Failed to build config")?;

    let config: Settings = config_source
        .try_deserialize()
        .context("Failed to deserialize config from file")?;

    Ok(SettingsBuilder::new(config))
}

/// Load configuration from environment variables
pub fn load_from_env() -> Result<SettingsBuilder> {
    let env_config = envy::prefixed(PREFIX)
        .from_env::<serde_json::Value>()
        .map_err(|e| anyhow::anyhow!("Failed to load config from environment: {}", e))?;

    Ok(SettingsBuilder::new(env_config))
}

/// Apply CLI arguments to the configuration
pub fn apply_command_line_args(config: Settings, args: CommandArgs) -> Result<Settings> {
    let _prism_home = get_prism_home(&args)?;

    // Apply celestia arguments
    let celestia_config = config.network.celestia_config.clone();
    let celestia_config_original = celestia_config.clone(); // Clone it to keep a reference for comparison later
    let mut updated_celestia_config = match config.da_layer {
        DALayerOption::Celestia => {
            let mut updated = celestia_config.clone(); // Clone here to avoid moving

            // Apply CLI arguments if provided
            if let Some(client) = args.celestia.celestia_client {
                updated.connection_string = client;
            }

            updated
        }
        _ => celestia_config,
    };

    // Apply custom network settings if using a custom network
    let mut custom_config = config.network.custom.clone();
    match &config.network.network {
        Network::Specter => {
            // For Specter network, CLI arguments for custom settings are ignored
            if args.celestia.celestia_start_height.is_some() ||
               args.celestia.snark_namespace_id.is_some() ||
               args.celestia.operation_namespace_id.is_some() ||
               args.verifying_key.is_some() {
                log::warn!("Ignoring custom network settings for predefined network '{}'", config.network.network_name);
            }

            // Use the Specter network configuration from utils.rs
            let specter_config = Network::Specter.config();

            // Update the celestia_config with the Specter network configuration
            if let Some(specter_celestia_config) = &specter_config.celestia_config {
                // Only update fields that are not overridden by CLI arguments
                if updated_celestia_config.connection_string == celestia_config_original.connection_string {
                    updated_celestia_config.connection_string = specter_celestia_config.connection_string.clone();
                }
                updated_celestia_config.start_height = specter_celestia_config.start_height;
                updated_celestia_config.snark_namespace_id = specter_celestia_config.snark_namespace_id.clone();
                updated_celestia_config.operation_namespace_id = specter_celestia_config.operation_namespace_id.clone();
            }
        },
        Network::Custom(_) => {
            // Apply CLI arguments to custom network settings
            if let Some(height) = args.celestia.celestia_start_height {
                custom_config.celestia_start_height = height;
            }

            if let Some(snark_id) = args.celestia.snark_namespace_id {
                custom_config.snark_namespace_id = snark_id;
            }

            if let Some(op_id) = args.celestia.operation_namespace_id {
                custom_config.operation_namespace_id = op_id;
            }

            if let Some(vk) = args.verifying_key.as_ref() {
                match VerifyingKey::try_from(vk.clone()) {
                    Ok(key) => custom_config.verifying_key = Some(key),
                    Err(e) => {
                        return Err(anyhow::anyhow!("Invalid verifying key format: {}", e));
                    }
                }
            }
        }
    }

    // Apply keystore arguments
    let mut keystore_config = config.keystore.clone();
    if let Some(keystore_type) = args.keystore_type {
        keystore_config.keystore_type = keystore_type;
    }

    if let Some(keystore_path) = args.keystore_path {
        keystore_config.file.file_path = keystore_path;
    }

    // Apply webserver arguments
    let mut webserver_config = config.webserver.clone();
    if let Some(active) = args.webserver.webserver_active {
        webserver_config.enabled = active;
    }

    if let Some(host) = args.webserver.host {
        webserver_config.host = host;
    }

    if let Some(port) = args.webserver.port {
        webserver_config.port = port;
    }

    // Apply database arguments
    let mut db_config = config.db.clone();
    match args.database.db_type {
        DBValues::RocksDB => {
            db_config.db_type = "RocksDB".to_string();
            if let Some(path) = args.database.rocksdb_path {
                if let Some(rocksdb_config) = db_config.rocksdb_config.as_mut() {
                    rocksdb_config.directory_path = path;
                } else {
                    db_config.rocksdb_config = Some(RocksDBConfig {
                        directory_path: path,
                    });
                }
            }
        }
        DBValues::InMemory => {
            db_config.db_type = "InMemory".to_string();
        }
        DBValues::Redis => {
            db_config.db_type = "Redis".to_string();
            if let Some(url) = args.database.redis_url {
                if let Some(redis_config) = db_config.redis_config.as_mut() {
                    redis_config.url = url;
                } else {
                    db_config.redis_config = Some(RedisConfig { url });
                }
            }
        }
    }

    // Create updated settings with the appropriate verifying key based on network type
    let verifying_key = match &config.network.network {
        Network::Specter => {
            // For Specter network, use the verifying key from the Specter network configuration
            Network::Specter.config().verifying_key
        },
        Network::Custom(_) => {
            // For custom networks, use None for backward compatibility
            None
        }
    };

    // Create updated settings
    Ok(Settings {
        da_layer: config.da_layer,
        keystore: keystore_config,
        webserver: webserver_config,
        network: NetworkConfig {
            network: config.network.network,
            network_name: config.network.network_name,
            verifying_key,
            celestia_config: updated_celestia_config,
            custom: custom_config,
        },
        db: db_config,
    })
}
