use std::{sync::Arc, time::Duration};

use crate::{
    DataAvailabilityLayer, LightDataAvailabilityLayer,
    celestia::{
        full_node::{CelestiaConnection, CelestiaFullNodeDAConfig},
        light_client::{CelestiaLightClientDAConfig, LightClientConnection},
    },
    consts::{DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    memory::InMemoryDataAvailabilityLayer,
};
use anyhow::Result;
use prism_errors::DataAvailabilityError;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LightClientDAConfig {
    Celestia(CelestiaLightClientDAConfig),
    #[default]
    InMemory,
}

// impl Default for LightClientDAConfig {
//     fn default() -> Self {
//         LightClientDAConfig::Celestia(CelestiaLightClientDAConfig {
//             celestia_network: CelestiaNetwork::Mocha,
//             snark_namespace_id: "000000000000000000000000000000000000707269736d5350457331"
//                 .to_string(),
//             sampling_window: DEFAULT_SAMPLING_WINDOW,
//             pruning_delay: DEFAULT_PRUNING_DELAY,
//             fetch_timeout: DEFAULT_FETCH_TIMEOUT,
//             fetch_max_retries: DEFAULT_FETCH_MAX_RETRIES,
//         })
//     }
// }

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FullNodeDAConfig {
    Celestia(CelestiaFullNodeDAConfig),
    #[default]
    InMemory,
}

pub async fn create_light_client_da_layer(
    config: &LightClientDAConfig,
) -> Result<Arc<dyn LightDataAvailabilityLayer + Send + Sync>, DataAvailabilityError> {
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
