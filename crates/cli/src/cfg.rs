use anyhow::{Context, Result, bail};
use config::{Config, Environment, File};
use dirs::home_dir;
use prism_da::{
    FullNodeDAConfig, LightClientDAConfig,
    celestia::{
        CelestiaNetwork, DEFAULT_FETCH_MAX_RETRIES, DEFAULT_FETCH_TIMEOUT, DEFAULT_PRUNING_DELAY,
        DEFAULT_SAMPLING_WINDOW, full_node::CelestiaFullNodeDAConfig,
        light_client::CelestiaLightClientDAConfig,
    },
};

use prism_lightclient::LightClientConfig;
use prism_prover::factory::{FullNodeProverConfig, ProverProverConfig};
use prism_storage::{DatabaseConfig, rocksdb::RocksDBConfig};
use prism_telemetry::config::TelemetryConfig;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, fs, path::Path};

use crate::cli_args::{
    CliDaLayerArgs, CliDaLayerType, CliDatabaseArgs, CliDatabaseType, FullNodeCliArgs,
    FullNodePreset, LightClientCliArgs, LightClientPreset, ProverCliArgs, ProverPreset,
};
/// Trait for configuration types that can be loaded from files and CLI arguments
pub(crate) trait LoadableConfig:
    Sized + Serialize + for<'de> Deserialize<'de> + Debug + Default
{
    type CliArgs: ConfigSource;

    /// Load configuration from file and CLI arguments
    fn load(cli_args: &Self::CliArgs) -> Result<Self> {
        let mut config: Self = load_config(cli_args.config_path())?;

        // Apply preset if specified in CLI args
        if let Some(preset) = cli_args.preset() {
            config.apply_preset(preset)?;
        }

        config.apply_cli_args(cli_args)?;

        println!("Final config: {}", serde_json::to_string_pretty(&config)?);

        Ok(config)
    }

    /// Apply preset configuration to self
    fn apply_preset(&mut self, preset: <Self::CliArgs as ConfigSource>::Preset) -> Result<()>;

    /// Apply CLI arguments to override config values
    fn apply_cli_args(&mut self, args: &Self::CliArgs) -> Result<()>;
}

/// Trait for CLI argument types that provide configuration sources
pub(crate) trait ConfigSource {
    type Preset;
    fn config_path(&self) -> &str;
    fn preset(&self) -> Option<Self::Preset>;
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct LightClientCmdConfig {
    pub da: LightClientDAConfig,
    pub telemetry: TelemetryConfig,

    #[serde(flatten)]
    pub light_client: LightClientConfig,
}

impl LoadableConfig for LightClientCmdConfig {
    type CliArgs = LightClientCliArgs;

    fn apply_preset(&mut self, preset: LightClientPreset) -> Result<()> {
        match preset {
            LightClientPreset::Specter => {
                self.da = LightClientDAConfig::Celestia(CelestiaLightClientDAConfig {
                    celestia_network: CelestiaNetwork::Mocha,
                    snark_namespace_id: "000000000000000000000000000000000000707269736d5350457331"
                        .to_string(),
                    sampling_window: DEFAULT_SAMPLING_WINDOW,
                    pruning_delay: DEFAULT_PRUNING_DELAY,
                    fetch_timeout: DEFAULT_FETCH_TIMEOUT,
                    fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES,
                });
                self.light_client = LightClientConfig {
                    verifying_key_str:
                        "MCowBQYDK2VwAyEAL2ilppK59Kq3aAMB/wpxdVGaI53DHPMdY6fcRodyFaA=".to_string(),
                };
            }
        }
        Ok(())
    }

    fn apply_cli_args(&mut self, args: &Self::CliArgs) -> Result<()> {
        match (&mut self.da, &args.da.da_type) {
            (_, None) => {
                // No cli arg specified, do not modify config
            }
            (LightClientDAConfig::Celestia(celestia_config), Some(CliDaLayerType::Celestia)) => {
                // TODO: Celestia network?

                // Update snark namespace ID if provided
                if let Some(namespace) = &args.da.celestia_snark_namespace_id {
                    celestia_config.snark_namespace_id = namespace.clone();
                }
            }
            (LightClientDAConfig::InMemory, Some(CliDaLayerType::InMemory)) => {
                // No changes needed for InMemory DA type
            }
            // If the DA type in the config doesn't match the CLI DA type, return an error
            _ => bail!("DA type mismatch"),
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct FullNodeCmdConfig {
    pub db: DatabaseConfig,
    pub da: FullNodeDAConfig,
    pub telemetry: TelemetryConfig,

    #[serde(flatten)]
    pub full_node: FullNodeProverConfig,
}

impl LoadableConfig for FullNodeCmdConfig {
    type CliArgs = FullNodeCliArgs;

    fn apply_preset(&mut self, preset: FullNodePreset) -> Result<()> {
        match preset {
            FullNodePreset::Specter => {
                self.da = FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig {
                    // TODO: Use correct specter values here, or derive url from celestia network in
                    // general. (Consider implementing an own Celestia Network that allows storing
                    // the url?)
                    // TODO: Ask Samuel whether we can define a url here for specter? (e.g. specific
                    // boot node) - or even better provide a mapping from celestia network to prism
                    // boot node url?
                    url: "ws://localhost:26658".to_string(),
                    celestia_network: CelestiaNetwork::Mocha,
                    snark_namespace_id: "00000000000000de1008".to_string(),
                    operation_namespace_id: "00000000000000de1009".to_string(),
                    fetch_timeout: DEFAULT_FETCH_TIMEOUT,
                    fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES,
                });
                self.full_node = FullNodeProverConfig {
                    verifying_key_str:
                        "MCowBQYDK2VwAyEAL2ilppK59Kq3aAMB/wpxdVGaI53DHPMdY6fcRodyFaA=".to_string(),
                    ..FullNodeProverConfig::default()
                };
            }
            // TODO: Introduce local preset here, that uses a local celestia node?
            FullNodePreset::Development => {
                self.da = FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig {
                    url: "ws://localhost:26658".to_string(),
                    celestia_network: CelestiaNetwork::Mocha,
                    snark_namespace_id: "00000000000000de1008".to_string(),
                    operation_namespace_id: "00000000000000de1009".to_string(),
                    fetch_timeout: DEFAULT_FETCH_TIMEOUT,
                    fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES,
                });
                self.db = DatabaseConfig::InMemory;
                self.telemetry = TelemetryConfig::default();
                self.full_node = FullNodeProverConfig::default();
            }
        }
        Ok(())
    }

    fn apply_cli_args(&mut self, args: &Self::CliArgs) -> Result<()> {
        // Update database configuration
        match (&mut self.db, &args.db.db_type) {
            (_, None) => {
                // No cli arg specified, do not modify config
            }
            (DatabaseConfig::RocksDB(rocksdb_config), Some(CliDatabaseType::RocksDB)) => {
                update_rocksdb_config(rocksdb_config, &args.db)?;
            }
            (DatabaseConfig::InMemory, Some(CliDatabaseType::InMemory)) => {
                // No changes needed for InMemory DB type
            }
            _ => bail!("DB type mismatch"),
        };

        // Update DA layer configuration
        match (&mut self.da, &args.da.da_type) {
            (_, None) => {
                // No cli arg specified, do not modify config
            }
            (FullNodeDAConfig::Celestia(celestia_config), Some(CliDaLayerType::Celestia)) => {
                update_celestia_full_node_da_config(celestia_config, &args.da)?;
            }
            (FullNodeDAConfig::InMemory, Some(CliDaLayerType::InMemory)) => {
                // No changes needed for InMemory DA type
            }
            // If the DA type in the config doesn't match the CLI DA type, return an error
            _ => bail!("DA type mismatch"),
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ProverCmdConfig {
    pub db: DatabaseConfig,
    pub da: FullNodeDAConfig,
    pub telemetry: TelemetryConfig,

    #[serde(flatten)]
    pub prover: ProverProverConfig,
}

impl LoadableConfig for ProverCmdConfig {
    type CliArgs = ProverCliArgs;

    fn apply_preset(&mut self, preset: ProverPreset) -> Result<()> {
        match preset {
            ProverPreset::Specter => {
                // TODO: Use correct specter values here, or derive url from celestia network in
                // general. (Consider implementing an own Celestia Network that allows storing
                // the url?)
                self.da = FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig {
                    url: "ws://localhost:26658".to_string(),
                    celestia_network: CelestiaNetwork::Mocha,
                    snark_namespace_id: "00000000000000de1008".to_string(),
                    operation_namespace_id: "00000000000000de1009".to_string(),
                    fetch_timeout: DEFAULT_FETCH_TIMEOUT,
                    fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES,
                });
                self.db = DatabaseConfig::RocksDB(RocksDBConfig::new("~/.prism/data/rocksdb"));
                self.telemetry = TelemetryConfig::default();
                self.prover = ProverProverConfig::default();
            }
            ProverPreset::Development => {
                self.da = FullNodeDAConfig::InMemory;
                self.db = DatabaseConfig::InMemory;
                self.telemetry = TelemetryConfig::default();
                self.prover = ProverProverConfig {
                    recursive_proofs: false,
                    ..Default::default()
                };
            }
        }
        Ok(())
    }

    fn apply_cli_args(&mut self, args: &Self::CliArgs) -> Result<()> {
        // Update database configuration
        match (&mut self.db, &args.db.db_type) {
            (_, None) => {
                // No cli arg specified, do not modify config
            }
            (DatabaseConfig::RocksDB(rocksdb_config), Some(CliDatabaseType::RocksDB)) => {
                update_rocksdb_config(rocksdb_config, &args.db)?;
            }
            (DatabaseConfig::InMemory, Some(CliDatabaseType::InMemory)) => {
                // No changes needed for InMemory DB type
            }
            _ => bail!("DB type mismatch"),
        };

        // Update DA layer configuration
        match (&mut self.da, args.da.da_type.as_ref()) {
            (_, None) => {
                // No cli arg specified, do not modify config
            }
            (FullNodeDAConfig::Celestia(celestia_config), Some(CliDaLayerType::Celestia)) => {
                update_celestia_full_node_da_config(celestia_config, &args.da)?;
            }
            (FullNodeDAConfig::InMemory, Some(CliDaLayerType::InMemory)) => {
                // No changes needed for InMemory DA type
            }
            // If the DA type in the config doesn't match the CLI DA type, return an error
            _ => bail!("DA type mismatch"),
        }

        Ok(())
    }
}

// Helper functions for updating configuration components

fn update_rocksdb_config(config: &mut RocksDBConfig, args: &CliDatabaseArgs) -> Result<()> {
    if let Some(path) = &args.rocksdb_path {
        config.path = path.clone();
    }
    Ok(())
}

fn update_celestia_full_node_da_config(
    config: &mut CelestiaFullNodeDAConfig,
    args: &CliDaLayerArgs,
) -> Result<()> {
    // Update URL if provided
    if let Some(url) = &args.celestia_url {
        config.url = url.clone();
    }
    // Update snark namespace ID if provided
    if let Some(namespace) = &args.celestia_snark_namespace_id {
        config.snark_namespace_id = namespace.clone();
    }
    // Update operation namespace ID if provided
    if let Some(namespace) = &args.celestia_operation_namespace_id {
        config.operation_namespace_id = namespace.clone();
    }
    Ok(())
}

fn update_light_client_da_config(
    config: &mut LightClientDAConfig,
    args: &CliDaLayerArgs,
) -> Result<()> {
    if let LightClientDAConfig::Celestia(celestia_config) = config {
        if let Some(namespace) = &args.celestia_snark_namespace_id {
            celestia_config.snark_namespace_id = namespace.clone();
        }
    }
    Ok(())
}

fn load_config<T: LoadableConfig>(config_path: &str) -> Result<T> {
    let expanded_path = expand_tilde(config_path);

    if let Err(e) = ensure_config_directory_exists(&expanded_path) {
        println!("Could not ensure config directory exists {}", e);
        return Ok(T::default());
    }

    let config_source = match Config::builder()
        .add_source(File::with_name(&expanded_path))
        .add_source(Environment::with_prefix("PRISM").separator("__"))
        .build()
    {
        Ok(config_source) => config_source,
        Err(e) => {
            println!("Failed to build config: {}. Using defaults.", e);
            return Ok(T::default());
        }
    };

    let config = match config_source.try_deserialize() {
        Ok(config) => config,
        Err(e) => {
            println!("Failed to deserialize config: {}. Using defaults.", e);
            return Ok(T::default());
        }
    };

    Ok(config)
}

fn ensure_config_directory_exists(config_path: impl AsRef<Path>) -> Result<()> {
    // If the path already exists, we're good
    if config_path.as_ref().exists() {
        return Ok(());
    }

    // Create parent directories if they don't exist
    if let Some(parent) = config_path.as_ref().parent() {
        return fs::create_dir_all(parent).context("Failed to create config directory");
    }

    bail!("Unable to create config directory");
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = home_dir() {
            return path.replacen("~", &home.to_string_lossy(), 1);
        }
    }
    path.to_string()
}
