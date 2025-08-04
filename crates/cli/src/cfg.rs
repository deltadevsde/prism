use anyhow::{Context, Result};
use config::{ConfigBuilder, File, builder::DefaultState};
use dirs::home_dir;
use dotenvy::dotenv;
use lumina_node::{self, network::Network as CelestiaNetwork};
use prism_da::{
    FullNodeDAConfig, LightClientDAConfig,
    celestia::{
        DEFAULT_FETCH_MAX_RETRIES, DEFAULT_FETCH_TIMEOUT, DEFAULT_PRUNING_DELAY,
        DEFAULT_SAMPLING_WINDOW,
        full_node::CelestiaFullNodeDAConfig,
        light_client::CelestiaLightClientDAConfig,
        utils::{CelestiaConfig, Network, NetworkConfig},
    },
};
use prism_errors::GeneralError;
use prism_keys::VerifyingKey;
use prism_prover::{
    factory::{FullNodeProverConfig, ProverProverConfig, WebServerConfig},
    prover::DEFAULT_MAX_EPOCHLESS_GAP,
};
use prism_serde::base64::FromBase64;
use prism_storage::{DatabaseConfig, rocksdb::RocksDBConfig};
use prism_telemetry::config::{TelemetryConfig, get_default_telemetry_config};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, str::FromStr};
use tracing::info;

use crate::cli_args::{CliCommandArgs, CliDaLayerType, CliDatabaseType};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webserver: Option<WebServerConfig>,
    pub network: NetworkConfig,
    pub keystore_type: Option<String>,
    pub keystore_path: Option<String>,
    pub da_layer: CliDaLayerType,
    pub db: DatabaseConfig,
    pub telemetry: Option<TelemetryConfig>,
    /// Maximum number of DA heights the prover will wait before posting a gapfiller proof
    pub max_epochless_gap: u64,
}

impl Config {
    fn initialize(path: &str, network_name: &str) -> Self {
        Config {
            webserver: Some(WebServerConfig {
                enabled: true,
                host: "127.0.0.1".to_string(),
                port: 41997,
            }),
            keystore_type: Some("keychain".to_string()),
            keystore_path: Some(format!("{}keystore.json", path)),
            network: Network::from_str(network_name).unwrap().config(),
            da_layer: CliDaLayerType::default(),
            db: DatabaseConfig::RocksDB(RocksDBConfig::new(&format!("{}data", path))),
            telemetry: Some(get_default_telemetry_config()),
            max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrismPreset {
    Specter,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum LightClientConfig {
    Preset(PrismPreset),
    Custom(LightClientCustomConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct LightClientCustomConfig {
    pub da: LightClientDAConfig,

    #[serde(flatten)]
    pub light_client: prism_lightclient::LightClientConfig,
}

impl LightClientConfig {
    pub fn custom_config(&self) -> LightClientCustomConfig {
        match self {
            LightClientConfig::Preset(PrismPreset::Specter) => LightClientCustomConfig {
                da: LightClientDAConfig::Celestia(CelestiaLightClientDAConfig {
                    celestia_network: CelestiaNetwork::Mocha,
                    snark_namespace_id: "000000000000000000000000000000000000707269736d5350457331"
                        .to_string(),
                    sampling_window: DEFAULT_SAMPLING_WINDOW,
                    pruning_delay: DEFAULT_PRUNING_DELAY,
                    fetch_timeout: DEFAULT_FETCH_TIMEOUT,
                    fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES,
                }),
                light_client: prism_lightclient::LightClientConfig {
                    verifying_key_str: "L2ilppK59Kq3aAMB/wpxdVGaI53DHPMdY6fcRodyFaA=".to_string(),
                },
            },
            LightClientConfig::Custom(config) => config.clone(),
        }
    }
}

impl Default for LightClientConfig {
    fn default() -> Self {
        LightClientConfig::Preset(PrismPreset::Specter)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum FullNodeConfig {
    Preset(PrismPreset),
    Custom(FullNodeCustomConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct FullNodeCustomConfig {
    pub db: DatabaseConfig,
    pub da: FullNodeDAConfig,

    #[serde(flatten)]
    pub full_node: FullNodeProverConfig,
}

impl FullNodeConfig {
    pub fn custom_config(&self) -> FullNodeCustomConfig {
        match self {
            FullNodeConfig::Preset(PrismPreset::Specter) => FullNodeCustomConfig {
                da: FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig {
                    url: "ws://localhost:26658".to_string(),
                    snark_namespace_id: "00000000000000de1008".to_string(),
                    operation_namespace_id: "00000000000000de1009".to_string(),
                    fetch_timeout: DEFAULT_FETCH_TIMEOUT,
                    fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES,
                }),
                db: DatabaseConfig::RocksDB(RocksDBConfig::new("./data")),
                full_node: FullNodeProverConfig::default(),
            },
            FullNodeConfig::Custom(config) => config.clone(),
        }
    }
}

impl Default for FullNodeConfig {
    fn default() -> Self {
        FullNodeConfig::Preset(PrismPreset::Specter)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ProverConfig {
    Preset(PrismPreset),
    Custom(ProverCustomConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProverCustomConfig {
    pub db: DatabaseConfig,
    pub da: FullNodeDAConfig,

    #[serde(flatten)]
    pub prover: ProverProverConfig,
}

impl ProverConfig {
    pub fn custom_config(&self) -> ProverCustomConfig {
        match self {
            ProverConfig::Preset(PrismPreset::Specter) => ProverCustomConfig {
                da: FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig {
                    url: "ws://localhost:26658".to_string(),
                    snark_namespace_id: "00000000000000de1008".to_string(),
                    operation_namespace_id: "00000000000000de1009".to_string(),
                    fetch_timeout: DEFAULT_FETCH_TIMEOUT,
                    fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES,
                }),
                db: DatabaseConfig::RocksDB(RocksDBConfig::new("./data")),
                prover: ProverProverConfig::default(),
            },
            ProverConfig::Custom(config) => config.clone(),
        }
    }
}

impl Default for ProverConfig {
    fn default() -> Self {
        ProverConfig::Preset(PrismPreset::Specter)
    }
}

pub fn load_config(args: CliCommandArgs) -> Result<Config> {
    dotenv().ok();

    let home_path = get_prism_home(&args).context("Failed to determine prism home path")?;

    ensure_config_file_exists(
        &home_path,
        &args.clone().network_name.unwrap_or("custom".to_string()),
    )
    .context("Failed to ensure config file exists")?;

    if let Some(rocksdb_path) = &args.database.rocksdb_path {
        fs::create_dir_all(rocksdb_path).context("Failed to create RocksDB directory")?;
    }

    let config_source = ConfigBuilder::<DefaultState>::default()
        .add_source(File::with_name(&format!("{}/config.toml", home_path)))
        .build()
        .context("Failed to build config")?;

    info!("Config file contents: {:?}", config_source);

    let loaded_config: Config =
        config_source.try_deserialize().context("Failed to deserialize config file")?;

    let final_config = apply_command_line_args(loaded_config, args);

    info!("Final config: {:?}", final_config);

    Ok(final_config)
}

fn get_prism_home(args: &CliCommandArgs) -> Result<String> {
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

fn ensure_config_file_exists(home_path: &str, network_name: &str) -> Result<()> {
    let config_path = &format!("{}/config.toml", home_path);
    if !Path::new(config_path).exists() {
        if let Some(parent) = Path::new(config_path).parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        let default_config = Config::initialize(home_path, network_name);
        let config_toml =
            toml::to_string(&default_config).context("Failed to serialize default config")?;

        fs::write(config_path, config_toml).context("Failed to write default config to disk")?;
    }
    Ok(())
}

fn apply_command_line_args(config: Config, args: CliCommandArgs) -> Config {
    let webserver_config = &config.webserver.unwrap_or(WebServerConfig {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 41997,
    });
    let network_config = &config.network.network.config();
    let prism_home = get_prism_home(&args.clone()).unwrap();

    let default_celestia_config = CelestiaConfig::default();
    let celestia_config = match config.da_layer {
        CliDaLayerType::Celestia => {
            let existing_config = config.network.celestia_config.clone().unwrap_or_default();

            Some(CelestiaConfig {
                connection_string: args
                    .celestia
                    .celestia_client
                    .or(Some(existing_config.connection_string))
                    .unwrap_or(default_celestia_config.connection_string),

                start_height: args
                    .celestia
                    .celestia_start_height
                    .or(Some(existing_config.start_height))
                    .unwrap_or(default_celestia_config.start_height),

                snark_namespace_id: args
                    .celestia
                    .snark_namespace_id
                    .or(Some(existing_config.snark_namespace_id))
                    .unwrap_or(default_celestia_config.snark_namespace_id),

                operation_namespace_id: args
                    .celestia
                    .operation_namespace_id
                    .or(Some(existing_config.operation_namespace_id))
                    .unwrap_or(default_celestia_config.operation_namespace_id),

                pruning_delay: existing_config.pruning_delay,
                sampling_window: existing_config.sampling_window,
                fetch_timeout: existing_config.fetch_timeout,
                fetch_max_retries: existing_config.fetch_max_retries,
            })
        }
        CliDaLayerType::InMemory => None,
    };

    Config {
        webserver: Some(WebServerConfig {
            enabled: args.webserver.webserver_active.unwrap_or(webserver_config.enabled),
            host: args.webserver.host.unwrap_or(webserver_config.host.clone()),
            port: args.webserver.port.unwrap_or(webserver_config.port),
        }),
        db: match args.database.db_type {
            CliDatabaseType::RocksDB => DatabaseConfig::RocksDB(RocksDBConfig {
                path: args.database.rocksdb_path.unwrap_or_else(|| format!("{}/data", prism_home)),
            }),
            CliDatabaseType::InMemory => DatabaseConfig::InMemory,
        },
        network: NetworkConfig {
            network: Network::from_str(&args.network_name.unwrap_or_default()).unwrap(),
            celestia_network: network_config.celestia_network.clone(),
            verifying_key: args
                .verifying_key
                .and_then(|x| VerifyingKey::from_base64(x).ok())
                .unwrap_or(network_config.verifying_key.clone()),
            celestia_config,
        },
        keystore_type: args.keystore_type.or(config.keystore_type),
        keystore_path: args.keystore_path.or(config.keystore_path),
        da_layer: config.da_layer,
        telemetry: config.telemetry,
        max_epochless_gap: config.max_epochless_gap,
    }
}
