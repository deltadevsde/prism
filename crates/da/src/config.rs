use prism_presets::{ApplyPreset, LightClientPreset, PresetError};
#[cfg(not(target_arch = "wasm32"))]
use prism_presets::{FullNodePreset, ProverPreset};
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use crate::celestia::CelestiaFullNodeDAConfig;
use crate::celestia::CelestiaLightClientDAConfig;

/// Configuration for the Data Availability layer used by light clients.
///
/// Determines which DA backend to use and its connection parameters.
/// Light client DA is used to read finalized epochs and proofs.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LightClientDAConfig {
    /// Celestia DA configuration with light client support.
    /// Provides efficient data retrieval through light client protocols
    /// with configurable pruning and retry policies.
    Celestia(CelestiaLightClientDAConfig),

    /// In-memory DA layer for testing and development.
    /// Data is stored locally and not persisted across restarts.
    /// Should not be used in production environments.
    #[default]
    InMemory,
}

impl LightClientDAConfig {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn use_storage_path(&mut self, path: Option<String>) -> Result<(), PresetError> {
        let Self::Celestia(celestia_config) = self else {
            return Err(PresetError::InvalidConfiguration(
                "No storage path outside of celestia".to_string(),
            ));
        };

        match path {
            Some(path) => {
                use crate::celestia::CelestiaLightClientDAStoreConfig;

                celestia_config.store = CelestiaLightClientDAStoreConfig::Disk { path };
            }
            None => {
                use crate::celestia::CelestiaLightClientDAStoreConfig;

                celestia_config.store = CelestiaLightClientDAStoreConfig::InMemory;
            }
        }
        Ok(())
    }
}

impl ApplyPreset<LightClientPreset> for LightClientDAConfig {
    fn apply_preset(&mut self, preset: &LightClientPreset) -> Result<(), PresetError> {
        match preset {
            LightClientPreset::Development => {
                // Nothing to change for DA in development preset
                Ok(())
            }
            LightClientPreset::Specter => {
                // When applying specter preset, we need to use celestia
                // If it is not set, apply preset on default celestia config
                if let Self::Celestia(celestia_config) = self {
                    celestia_config.apply_specter_preset()
                } else {
                    *self = Self::Celestia(CelestiaLightClientDAConfig::new_for_specter()?);
                    Ok(())
                }
            }
        }
    }
}

/// Configuration for the Data Availability layer used by full nodes.
///
/// Determines which DA backend to use and its connection parameters.
/// Full node DA is used to read and write finalized epochs and transactions.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FullNodeDAConfig {
    /// Celestia DA configuration with full node capabilities.
    /// Provides complete DA functionality including transaction publishing,
    /// block retrieval, and serving light clients.
    Celestia(CelestiaFullNodeDAConfig),

    /// In-memory DA layer for testing and development.
    /// Simulates DA operations locally without network connectivity.
    /// Should not be used in production environments.
    #[default]
    InMemory,
}

#[cfg(not(target_arch = "wasm32"))]
impl ApplyPreset<FullNodePreset> for FullNodeDAConfig {
    fn apply_preset(&mut self, preset: &FullNodePreset) -> Result<(), PresetError> {
        match preset {
            FullNodePreset::Specter => {
                // When applying specter preset, we need to use celestia
                // If it is not set, apply preset on default celestia config
                if let Self::Celestia(celestia_config) = self {
                    celestia_config.apply_specter_preset()
                } else {
                    *self = Self::Celestia(CelestiaFullNodeDAConfig::new_for_specter()?);
                    Ok(())
                }
            }
            FullNodePreset::Development => {
                *self = Self::InMemory;
                Ok(())
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl ApplyPreset<ProverPreset> for FullNodeDAConfig {
    fn apply_preset(&mut self, preset: &ProverPreset) -> Result<(), PresetError> {
        match preset {
            ProverPreset::Specter => {
                // When applying specter preset, we need to use celestia
                // If it is not set, apply preset on default celestia config
                if let Self::Celestia(celestia_config) = self {
                    celestia_config.apply_specter_preset()
                } else {
                    *self = Self::Celestia(CelestiaFullNodeDAConfig::new_for_specter()?);
                    Ok(())
                }
            }
            ProverPreset::Development => {
                *self = Self::InMemory;
                Ok(())
            }
        }
    }
}
