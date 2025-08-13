use std::{sync::Arc, time::Duration};

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    DataAvailabilityLayer,
    celestia::full_node::{CelestiaConnection, CelestiaFullNodeDAConfig},
};
use crate::{
    LightDataAvailabilityLayer,
    celestia::light_client::{
        CelestiaLightClientDAConfig, CelestiaLightClientDAStoreConfig, LightClientConnection,
    },
    consts::{DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    memory::InMemoryDataAvailabilityLayer,
};
use anyhow::Result;
use prism_errors::DataAvailabilityError;
#[cfg(not(target_arch = "wasm32"))]
use prism_presets::ProverPreset;
use prism_presets::{ApplyPreset, FullNodePreset, LightClientPreset, PresetError};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LightClientDAConfig {
    Celestia(CelestiaLightClientDAConfig),
    #[default]
    InMemory,
}

impl LightClientDAConfig {
    pub fn use_storage_path(&mut self, path: Option<String>) -> Result<(), PresetError> {
        let LightClientDAConfig::Celestia(celestia_config) = self else {
            return Err(PresetError::InvalidConfiguration(
                "No storage path outside of celestia".to_string(),
            ));
        };

        match path {
            Some(path) => {
                celestia_config.store = CelestiaLightClientDAStoreConfig::Disk { path };
            }
            None => {
                celestia_config.store = CelestiaLightClientDAStoreConfig::InMemory;
            }
        }
        Ok(())
    }
}

impl ApplyPreset<LightClientPreset> for LightClientDAConfig {
    fn apply_preset(&mut self, preset: &LightClientPreset) -> Result<(), PresetError> {
        match preset {
            LightClientPreset::Specter => {
                // When applying specter preset, we need to use celestia
                // If it is not set, apply preset on default celestia config
                if let LightClientDAConfig::Celestia(celestia_config) = self {
                    celestia_config.apply_preset(preset)
                } else {
                    *self = LightClientDAConfig::Celestia(
                        CelestiaLightClientDAConfig::default_with_preset(preset)?,
                    );
                    Ok(())
                }
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
type LightClientDALayerResult =
    Result<Arc<dyn LightDataAvailabilityLayer + Send + Sync>, DataAvailabilityError>;
#[cfg(target_arch = "wasm32")]
type LightClientDALayerResult = Result<Arc<dyn LightDataAvailabilityLayer>, DataAvailabilityError>;

pub async fn create_light_client_da_layer(
    config: &LightClientDAConfig,
) -> LightClientDALayerResult {
    info!("Initializing light client connection...");
    match config {
        LightClientDAConfig::Celestia(celestia_config) => {
            info!("Using celestia config: {:?}", celestia_config);
            let connection = LightClientConnection::new(celestia_config).await?;
            Ok(Arc::new(connection))
        }
        LightClientDAConfig::InMemory => {
            let (da_layer, _height_rx, _block_rx) =
                InMemoryDataAvailabilityLayer::new(Duration::from_secs(10));
            Ok(Arc::new(da_layer))
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FullNodeDAConfig {
    Celestia(CelestiaFullNodeDAConfig),
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
                if let FullNodeDAConfig::Celestia(celestia_config) = self {
                    celestia_config.apply_specter_preset()
                } else {
                    *self =
                        FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig::new_for_specter()?);
                    Ok(())
                }
            }
            FullNodePreset::Development => {
                *self = FullNodeDAConfig::InMemory;
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
                if let FullNodeDAConfig::Celestia(celestia_config) = self {
                    celestia_config.apply_specter_preset()
                } else {
                    *self =
                        FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig::new_for_specter()?);
                    Ok(())
                }
            }
            ProverPreset::Development => {
                *self = FullNodeDAConfig::InMemory;
                Ok(())
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn create_full_node_da_layer(
    config: &FullNodeDAConfig,
) -> Result<Arc<dyn DataAvailabilityLayer>, DataAvailabilityError> {
    info!("Initializing full node connection...");
    match config {
        FullNodeDAConfig::Celestia(celestia_conf) => {
            info!("Using celestia config: {:?}", celestia_conf);
            for attempt in 1..=DA_RETRY_COUNT {
                match CelestiaConnection::new(celestia_conf, None).await {
                    Ok(da) => return Ok(Arc::new(da)),
                    Err(e) => {
                        if attempt == DA_RETRY_COUNT {
                            return Err(DataAvailabilityError::NetworkError(format!(
                                "failed to connect to celestia node after {} attempts: {}",
                                DA_RETRY_COUNT, e
                            )));
                        }
                        error!(
                            "Attempt {} to connect to celestia node failed: {}. Retrying in {} seconds...",
                            attempt,
                            e,
                            DA_RETRY_INTERVAL.as_secs()
                        );
                        tokio::time::sleep(DA_RETRY_INTERVAL).await;
                    }
                }
            }
            unreachable!() // This line should never be reached due to the return in the last iteration
        }
        FullNodeDAConfig::InMemory => {
            let (da_layer, _height_rx, _block_rx) =
                InMemoryDataAvailabilityLayer::new(Duration::from_secs(10));
            Ok(Arc::new(da_layer))
        }
    }
}
