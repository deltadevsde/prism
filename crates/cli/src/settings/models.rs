use prism_da::celestia::utils::{CelestiaConfig, Network, NetworkConfig as DaNetworkConfig};
use prism_keys::VerifyingKey;
use serde::{Deserialize, Serialize};
use lumina_node::network::Network as LuminaNetwork;

/// Configuration for file-based keystore.
///
/// Contains settings specific to file-based keystores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreFileConfig {
    /// Path to the keystore file
    #[serde(alias = "path")]
    pub file_path: String,
}

impl Default for KeystoreFileConfig {
    fn default() -> Self {
        KeystoreFileConfig {
            file_path: "".to_string(),
        }
    }
}

/// Keystore configuration for the Prism application.
///
/// Contains settings related to the keystore including type and file-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreConfig {
    /// The type of keystore to use (keychain or file)
    #[serde(rename = "type")]
    pub keystore_type: String,

    /// File-specific configuration (used when keystore_type is "file")
    #[serde(default)]
    pub file: KeystoreFileConfig,
}

impl Default for KeystoreConfig {
    fn default() -> Self {
        KeystoreConfig {
            keystore_type: "keychain".to_string(),
            file: KeystoreFileConfig::default(),
        }
    }
}

// Default values for network configuration
mod defaults {
    pub fn network_name() -> String {
        "local".to_string()
    }

    pub fn connection_string() -> String {
        "ws://localhost:26658".to_string()
    }

    pub fn start_height() -> u64 {
        0
    }

    pub fn snark_namespace() -> String {
        "00000000000000de1008".to_string()
    }

    pub fn operation_namespace() -> String {
        "00000000000000de1009".to_string()
    }

    pub fn celestia_network() -> String {
        "private".to_string()
    }
}

/// Network configuration for the Prism application.
///
/// Contains all settings needed for connecting to Celestia and other network services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// The network type to connect to (Specter or Custom)
    #[serde(default = "default_network")]
    pub network: Network,

    /// The name of the network to connect to
    #[serde(default = "defaults::network_name")]
    pub network_name: String,

    /// The verifying key for the prover
    #[serde(default)]
    #[serde(serialize_with = "serialize_optional_verifying_key")]
    #[serde(deserialize_with = "deserialize_optional_verifying_key")]
    pub verifying_key: Option<VerifyingKey>,

    /// Celestia specific configuration
    #[serde(rename = "celestia")]
    pub celestia_config: CelestiaNetworkConfig,

    /// Custom network configuration (used when network is Custom)
    #[serde(default)]
    pub custom: CustomNetworkConfig,
}

/// Serialize Option<VerifyingKey> to a string, using empty string for None
fn serialize_optional_verifying_key<S>(
    key: &Option<VerifyingKey>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match key {
        Some(vk) => serializer.serialize_str(&vk.to_string()),
        None => serializer.serialize_str(""),
    }
}

/// Deserialize Option<VerifyingKey> from a string, treating empty string as None
fn deserialize_optional_verifying_key<'de, D>(
    deserializer: D,
) -> Result<Option<VerifyingKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        Ok(None)
    } else {
        VerifyingKey::try_from(s)
            .map(Some)
            .map_err(serde::de::Error::custom)
    }
}

/// Default function for Network field
pub fn default_network() -> Network {
    Network::Custom(defaults::network_name())
}

/// Helper function to convert LuminaNetwork to string
fn lumina_network_to_string(network: &LuminaNetwork) -> String {
    match network {
        LuminaNetwork::Mocha => "mocha".to_string(),
        LuminaNetwork::Arabica => "arabica".to_string(),
        _ => defaults::celestia_network(),
    }
}

/// Celestia network specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelestiaNetworkConfig {
    /// The celestia network to connect to (mocha, arabica, etc.)
    pub celestia_network: String,

    /// Connection string for Celestia node
    #[serde(default = "defaults::connection_string")]
    pub connection_string: String,

    /// Block height to start syncing from
    #[serde(default = "defaults::start_height")]
    pub start_height: u64,

    /// Namespace ID for SNARK data
    #[serde(default = "defaults::snark_namespace")]
    pub snark_namespace_id: String,

    /// Namespace ID for operation data
    #[serde(default = "defaults::operation_namespace")]
    pub operation_namespace_id: String,
}

impl Default for CelestiaNetworkConfig {
    fn default() -> Self {
        CelestiaNetworkConfig {
            celestia_network: defaults::celestia_network(),
            connection_string: defaults::connection_string(),
            start_height: defaults::start_height(),
            snark_namespace_id: defaults::snark_namespace(),
            operation_namespace_id: defaults::operation_namespace(),
        }
    }
}

/// Custom network configuration for user-defined networks
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomNetworkConfig {
    /// The verifying key for the prover in custom networks
    #[serde(default)]
    #[serde(serialize_with = "serialize_optional_verifying_key")]
    #[serde(deserialize_with = "deserialize_optional_verifying_key")]
    pub verifying_key: Option<VerifyingKey>,

    /// The celestia network to connect to (mocha, arabica, etc.)
    #[serde(default = "defaults::celestia_network")]
    pub celestia_network: String,

    /// Block height to start syncing from
    #[serde(default = "defaults::start_height")]
    pub celestia_start_height: u64,

    /// Namespace ID for SNARK data
    #[serde(default = "defaults::snark_namespace")]
    pub snark_namespace_id: String,

    /// Namespace ID for operation data
    #[serde(default = "defaults::operation_namespace")]
    pub operation_namespace_id: String,
}

impl NetworkConfig {
    /// Convert to the prism_da NetworkConfig type
    ///
    /// # Returns
    /// * `DaNetworkConfig` - Converted network configuration for the DA layer
    pub fn to_da_network_config(&self) -> DaNetworkConfig {
        let mut celestia_config = CelestiaConfig::default();
        celestia_config.connection_string = self.celestia_config.connection_string.clone();

        match &self.network {
            Network::Specter => {
                let specter_config = Network::Specter.config();

                // Apply Specter-specific configuration
                if let Some(specter_celestia_config) = specter_config.celestia_config {
                    celestia_config.start_height = specter_celestia_config.start_height;
                    celestia_config.snark_namespace_id = specter_celestia_config.snark_namespace_id;
                    celestia_config.operation_namespace_id = specter_celestia_config.operation_namespace_id;
                }

                DaNetworkConfig {
                    network: self.network.clone(),
                    network_name: self.network_name.clone(),
                    celestia_network: specter_config.celestia_network,
                    verifying_key: specter_config.verifying_key,
                    celestia_config: Some(celestia_config),
                }
            },
            Network::Custom(_) => {
                // For custom networks, use the custom configuration
                celestia_config.start_height = self.custom.celestia_start_height;
                celestia_config.snark_namespace_id = self.custom.snark_namespace_id.clone();
                celestia_config.operation_namespace_id = self.custom.operation_namespace_id.clone();

                // Convert string network type to LuminaNetwork
                let lumina_network = match self.custom.celestia_network.as_str() {
                    "mocha" => LuminaNetwork::Mocha,
                    "arabica" => LuminaNetwork::Arabica,
                    _ => LuminaNetwork::custom("custom").unwrap(),
                };

                DaNetworkConfig {
                    network: self.network.clone(),
                    network_name: self.network_name.clone(),
                    celestia_network: lumina_network,
                    verifying_key: self.custom.verifying_key.clone(),
                    celestia_config: Some(celestia_config),
                }
            }
        }
    }

    /// Parse the network name and return the corresponding Network enum
    ///
    /// # Arguments
    /// * `network_name` - The name of the network to parse
    ///
    /// # Returns
    /// * `Network` - The parsed network or Network::Custom if not recognized
    pub fn parse_network(network_name: &str) -> Network {
        match network_name.to_lowercase().as_str() {
            "specter" | "devnet" => Network::Specter,
            _ => Network::Custom(network_name.to_string()),
        }
    }
}

impl From<DaNetworkConfig> for NetworkConfig {
    fn from(config: DaNetworkConfig) -> Self {
        // Clone the celestia_config once to avoid moving it
        let celestia_config_ref = config.celestia_config.as_ref();

        match &config.network {
            Network::Specter => {
                let specter_config = Network::Specter.config();

                // Create CelestiaNetworkConfig from Specter configuration
                let celestia_config = if let Some(specter_celestia_config) = &specter_config.celestia_config {
                    CelestiaNetworkConfig {
                        celestia_network: lumina_network_to_string(&specter_config.celestia_network),
                        connection_string: celestia_config_ref
                            .map(|c| c.connection_string.clone())
                            .unwrap_or_else(|| specter_celestia_config.connection_string.clone()),
                        start_height: specter_celestia_config.start_height,
                        snark_namespace_id: specter_celestia_config.snark_namespace_id.clone(),
                        operation_namespace_id: specter_celestia_config.operation_namespace_id.clone(),
                    }
                } else {
                    CelestiaNetworkConfig::default()
                };

                NetworkConfig {
                    network: config.network,
                    network_name: config.network_name,
                    verifying_key: specter_config.verifying_key,
                    celestia_config,
                    custom: CustomNetworkConfig::default(),
                }
            },
            Network::Custom(_) => {
                // Create custom network config
                let custom_config = CustomNetworkConfig {
                    verifying_key: config.verifying_key.clone(),
                    celestia_network: lumina_network_to_string(&config.celestia_network),
                    celestia_start_height: celestia_config_ref
                        .map(|c| c.start_height)
                        .unwrap_or_else(defaults::start_height),
                    snark_namespace_id: celestia_config_ref
                        .map(|c| c.snark_namespace_id.clone())
                        .unwrap_or_else(defaults::snark_namespace),
                    operation_namespace_id: celestia_config_ref
                        .map(|c| c.operation_namespace_id.clone())
                        .unwrap_or_else(defaults::operation_namespace),
                };

                NetworkConfig {
                    network: config.network,
                    network_name: config.network_name,
                    verifying_key: None, // This field is now only used for backward compatibility
                    celestia_config: CelestiaNetworkConfig {
                        celestia_network: lumina_network_to_string(&config.celestia_network),
                        connection_string: celestia_config_ref
                            .map(|c| c.connection_string.clone())
                            .unwrap_or_else(defaults::connection_string),
                        start_height: defaults::start_height(),
                        snark_namespace_id: defaults::snark_namespace(),
                        operation_namespace_id: defaults::operation_namespace(),
                    },
                    custom: custom_config,
                }
            }
        }
    }
}

/// Main configuration for the Prism application.
///
/// Contains all settings needed for running the application, including
/// web server, network, storage, and data availability layer configurations.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    /// Data availability layer configuration
    #[serde(default)]
    pub da_layer: DALayerOption,

    /// Keystore configuration
    #[serde(default)]
    pub keystore: KeystoreConfig,

    /// Web server configuration
    #[serde(default)]
    pub webserver: WebServerConfig,

    /// Network configuration
    pub network: NetworkConfig,

    /// Database configuration
    #[serde(rename = "database")]
    pub db: DatabaseConfig,
}

/// Web server specific configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebServerConfig {
    /// Whether the web server is enabled
    pub enabled: bool,

    /// Host address for the web server
    pub host: String,

    /// Port for the web server
    pub port: u16,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        WebServerConfig {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 0,
        }
    }
}

/// Data availability layer options
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum DALayerOption {
    /// Celestia data availability layer (default)
    #[default]
    Celestia,

    /// In-memory data availability layer (for testing)
    InMemory,
}

/// Database configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Type of database to use (RocksDB, InMemory, Redis)
    #[serde(rename = "type")]
    pub db_type: String,

    /// RocksDB specific configuration
    #[serde(rename = "rocksdb")]
    pub rocksdb_config: Option<RocksDBConfig>,

    /// Redis specific configuration
    #[serde(rename = "redis")]
    pub redis_config: Option<RedisConfig>,
}

/// RocksDB specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RocksDBConfig {
    /// Path to the RocksDB database directory
    #[serde(alias = "path")]
    pub directory_path: String,
}

/// Redis specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// URL for Redis connection
    pub url: String,
}

impl Settings {
    /// Initialize a new default configuration
    ///
    /// # Arguments
    /// * `path` - Base path for data and keystore files
    /// * `network_name` - Name of the network to connect to
    ///
    /// # Returns
    /// * `Settings` - Default settings for the specified network
    pub fn initialize(_path: &str, network_name: &str) -> Self {
        let network = NetworkConfig::parse_network(network_name);

        let mut keystore_config = KeystoreConfig::default();
        keystore_config.file.file_path = "keystore.json".to_string();

        // Create network configuration based on network type
        let network_config = match &network {
            Network::Specter => {
                // For Specter network, use predefined configuration
                let specter_config = Network::Specter.config();

                // Convert to our NetworkConfig format
                NetworkConfig {
                    network,
                    network_name: network_name.to_string(),
                    verifying_key: specter_config.verifying_key,
                    celestia_config: CelestiaNetworkConfig {
                        celestia_network: lumina_network_to_string(&specter_config.celestia_network),
                        connection_string: specter_config.celestia_config
                            .as_ref()
                            .map(|c| c.connection_string.clone())
                            .unwrap_or_else(defaults::connection_string),
                        start_height: specter_config.celestia_config
                            .as_ref()
                            .map(|c| c.start_height)
                            .unwrap_or_else(defaults::start_height),
                        snark_namespace_id: specter_config.celestia_config
                            .as_ref()
                            .map(|c| c.snark_namespace_id.clone())
                            .unwrap_or_else(defaults::snark_namespace),
                        operation_namespace_id: specter_config.celestia_config
                            .as_ref()
                            .map(|c| c.operation_namespace_id.clone())
                            .unwrap_or_else(defaults::operation_namespace),
                    },
                    custom: CustomNetworkConfig::default(),
                }
            },
            Network::Custom(_) => {
                // For custom networks, use default settings
                let custom_config = CustomNetworkConfig::default();

                NetworkConfig {
                    network,
                    network_name: network_name.to_string(),
                    verifying_key: None,
                    celestia_config: CelestiaNetworkConfig::default(),
                    custom: custom_config,
                }
            },
        };

        Settings {
            da_layer: DALayerOption::default(),
            keystore: keystore_config,
            webserver: WebServerConfig::default(),
            network: network_config,
            db: DatabaseConfig {
                db_type: "RocksDB".to_string(),
                rocksdb_config: Some(RocksDBConfig {
                    directory_path: "data".to_string(),
                }),
                redis_config: Some(RedisConfig {
                    url: "redis://localhost:6379".to_string(),
                }),
            },
        }
    }
}
