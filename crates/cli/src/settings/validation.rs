use anyhow::{Context, Result};
use url::Url;
use std::net::IpAddr;
use std::path::Path;
use log::warn;
use crate::settings::models::{Settings, DALayerOption, WebServerConfig};
use prism_da::celestia::utils::Network;

/// Validate the entire configuration
pub fn validate_config(config: &Settings) -> Result<()> {
    // Validate network configuration
    validate_network_config(config)?;

    // Validate database settings
    validate_database_config(config)?;

    // Validate web server configuration
    validate_webserver_config(&config.webserver)?;

    // Validate keystore configuration
    validate_keystore_config(config)?;

    Ok(())
}

/// Validate network configuration
fn validate_network_config(config: &Settings) -> Result<()> {
    // Check network-specific settings
    match &config.network.network {
        Network::Specter => {
            // Specter network has predefined settings, no additional validation needed
            // We can optionally verify that the settings match the expected values from utils.rs
            let specter_config = Network::Specter.config();

            // Verify that the verifying key is set correctly
            if config.network.verifying_key != specter_config.verifying_key {
                warn!("Specter network: Verifying key does not match the expected value. This may cause issues with epoch signature verification.");
            }
        },
        Network::Custom(_) => {
            // For custom networks, validate that required settings are provided
            if config.network.custom.verifying_key.is_none() {
                warn!("Custom network: Verifying key is not provided. This is not recommended as epoch signatures will not be verified.");
            }

            // Validate custom namespace IDs are non-empty
            if config.network.custom.snark_namespace_id.trim().is_empty() {
                return Err(anyhow::anyhow!("Custom network: SNARK namespace ID cannot be empty"));
            }

            if config.network.custom.operation_namespace_id.trim().is_empty() {
                return Err(anyhow::anyhow!("Custom network: Operation namespace ID cannot be empty"));
            }

            // Validate start height
            if config.network.custom.celestia_start_height == 0 {
                warn!("Custom network: Celestia start height is set to 0. This may cause scanning from the genesis block, which could be slow.");
            }
        }
    }

    // Validate celestia configuration when using celestia DA layer
    if let DALayerOption::Celestia = config.da_layer {
        let celestia_config = &config.network.celestia_config;

        // Validate connection string format (WebSocket URL)
        let connection_string = &celestia_config.connection_string;
        if !connection_string.starts_with("ws://") && !connection_string.starts_with("wss://") {
            return Err(anyhow::anyhow!("Celestia connection string must be a valid WebSocket URL starting with ws:// or wss://"));
        }

        // Try to parse as URL to validate format
        Url::parse(connection_string)
            .context("Invalid Celestia connection string format")?;

        // Validate namespace IDs are non-empty
        if celestia_config.snark_namespace_id.trim().is_empty() {
            return Err(anyhow::anyhow!("SNARK namespace ID cannot be empty"));
        }

        if celestia_config.operation_namespace_id.trim().is_empty() {
            return Err(anyhow::anyhow!("Operation namespace ID cannot be empty"));
        }

        // Validate start height
        if celestia_config.start_height == 0 {
            warn!("Celestia start height is set to 0. This may cause scanning from the genesis block, which could be slow.");
        }
    }

    Ok(())
}

/// Validate database configuration
fn validate_database_config(config: &Settings) -> Result<()> {
    match config.db.db_type.as_str() {
        "InMemory" => {
            // No validation needed for in-memory database
        }
        "RocksDB" => {
            if let Some(rocksdb_config) = &config.db.rocksdb_config {
                // Validate path exists or can be created
                let path = Path::new(&rocksdb_config.directory_path);
                if !path.exists() {
                    if let Some(parent) = path.parent() {
                        if !parent.exists() {
                            warn!("RocksDB directory path parent directory does not exist: {}. It will be created if possible.", parent.display());
                        }
                    }
                }
            } else {
                warn!("RocksDB configuration is missing, will use in-memory database instead");
            }
        }
        "Redis" => {
            if let Some(redis_config) = &config.db.redis_config {
                // Validate Redis connection string
                if redis_config.url.trim().is_empty() {
                    return Err(anyhow::anyhow!("Redis connection string cannot be empty"));
                }

                // Basic validation of Redis URL format
                if !redis_config.url.starts_with("redis://") {
                    return Err(anyhow::anyhow!("Redis connection string should start with 'redis://'"));
                }
            } else {
                warn!("Redis configuration is missing, will use in-memory database instead");
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Invalid database type: {}. Valid values are 'InMemory', 'RocksDB', or 'Redis'", config.db.db_type));
        }
    }

    Ok(())
}

/// Validate web server configuration
fn validate_webserver_config(webserver: &WebServerConfig) -> Result<()> {
    // Validate host is a valid IP address
    webserver.host.parse::<IpAddr>()
        .context("Web server host must be a valid IP address")?;

    // Port 0 is valid as it means "assign any available port"
    // Note: We don't need to check upper bound since u16 can't exceed 65535

    Ok(())
}

/// Validate keystore configuration
fn validate_keystore_config(config: &Settings) -> Result<()> {
    match config.keystore.keystore_type.as_str() {
        "keychain" => {
            // No additional validation needed for keychain
        }
        "file" => {
            // When keystore type is file, path must be provided
            if config.keystore.file.file_path.trim().is_empty() {
                return Err(anyhow::anyhow!("Keystore file path must be provided when keystore type is 'file'"));
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Invalid keystore type: {}. Valid values are 'keychain' or 'file'", config.keystore.keystore_type));
        }
    }

    Ok(())
}
