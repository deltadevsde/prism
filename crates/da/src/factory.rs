use std::{sync::Arc, time::Duration};
use tracing::info;

#[cfg(not(target_arch = "wasm32"))]
use crate::{DataAvailabilityLayer, celestia::CelestiaConnection, config::FullNodeDAConfig};
use crate::{
    LightDataAvailabilityLayer, celestia::LightClientConnection, config::LightClientDAConfig,
    error::DataAvailabilityError, memory::InMemoryDataAvailabilityLayer,
};

#[cfg(not(target_arch = "wasm32"))]
type LightClientDALayerResult =
    Result<Arc<dyn LightDataAvailabilityLayer + Send + Sync>, DataAvailabilityError>;
#[cfg(target_arch = "wasm32")]
type LightClientDALayerResult = Result<Arc<dyn LightDataAvailabilityLayer>, DataAvailabilityError>;

/// Creates a light client data availability layer from the given configuration.
///
/// This function initializes the appropriate DA backend based on the configuration
/// and returns a trait object that implements [`LightDataAvailabilityLayer`].
///
/// See the crate-level documentation for usage examples and integration patterns.
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

/// Creates a full node data availability layer from the given configuration.
///
/// This function initializes the appropriate DA backend with retry logic for network
/// connections and returns a trait object that implements [`DataAvailabilityLayer`].
///
/// See the crate-level documentation for usage examples and integration patterns.
#[cfg(not(target_arch = "wasm32"))]
pub async fn create_full_node_da_layer(
    config: &FullNodeDAConfig,
) -> Result<Arc<dyn DataAvailabilityLayer>, DataAvailabilityError> {
    info!("Initializing full node connection...");
    match config {
        FullNodeDAConfig::Celestia(celestia_conf) => {
            let da = CelestiaConnection::new(celestia_conf, None).await.map_err(|e| {
                DataAvailabilityError::InitializationError(format!(
                    "Failed to create Celestia connection: {}",
                    e
                ))
            })?;
            Ok(Arc::new(da))
        }
        FullNodeDAConfig::InMemory => {
            let (da_layer, _height_rx, _block_rx) =
                InMemoryDataAvailabilityLayer::new(Duration::from_secs(10));
            Ok(Arc::new(da_layer))
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::celestia::{
        CelestiaFullNodeDAConfig, CelestiaLightClientDAConfig, CelestiaLightClientDAStoreConfig,
    };
    use prism_presets::{
        ApplyPreset, FullNodePreset, LightClientPreset, PresetError, ProverPreset,
    };

    #[test]
    fn test_light_client_da_config_default() {
        let config = LightClientDAConfig::default();
        assert!(matches!(config, LightClientDAConfig::InMemory));
    }

    #[test]
    fn test_light_client_da_config_apply_specter_preset() {
        let mut config = LightClientDAConfig::InMemory;
        let result = config.apply_preset(&LightClientPreset::Specter);

        assert!(result.is_ok());
        assert!(matches!(config, LightClientDAConfig::Celestia(_)));
    }

    #[test]
    fn test_light_client_da_config_apply_specter_preset_on_existing_celestia() {
        let mut config = LightClientDAConfig::Celestia(CelestiaLightClientDAConfig::default());
        let result = config.apply_preset(&LightClientPreset::Specter);

        assert!(result.is_ok());
        assert!(matches!(config, LightClientDAConfig::Celestia(_)));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_light_client_da_config_use_storage_path_with_celestia() {
        let mut config = LightClientDAConfig::Celestia(CelestiaLightClientDAConfig::default());
        let result = config.use_storage_path(Some("/test/path".to_string()));

        assert!(result.is_ok());
        if let LightClientDAConfig::Celestia(celestia_config) = config {
            assert!(matches!(
                celestia_config.store,
                CelestiaLightClientDAStoreConfig::Disk { .. }
            ));
        } else {
            panic!("Expected Celestia config");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_light_client_da_config_use_storage_path_with_inmemory_fails() {
        let mut config = LightClientDAConfig::InMemory;
        let result = config.use_storage_path(Some("/test/path".to_string()));

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PresetError::InvalidConfiguration(_)
        ));
    }

    #[tokio::test]
    async fn test_create_light_client_da_layer_inmemory() {
        let config = LightClientDAConfig::InMemory;
        let result = create_light_client_da_layer(&config).await;

        assert!(result.is_ok());
        // We can't easily test the exact type due to trait objects, but we can verify it was
        // created
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_da_config_default() {
        let config = FullNodeDAConfig::default();
        assert!(matches!(config, FullNodeDAConfig::InMemory));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_da_config_apply_specter_preset() {
        let mut config = FullNodeDAConfig::InMemory;
        let result = config.apply_preset(&FullNodePreset::Specter);

        assert!(result.is_ok());
        assert!(matches!(config, FullNodeDAConfig::Celestia(_)));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_da_config_apply_development_preset() {
        let mut config = FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig::default());
        let result = config.apply_preset(&FullNodePreset::Development);

        assert!(result.is_ok());
        assert!(matches!(config, FullNodeDAConfig::InMemory));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_da_config_apply_prover_specter_preset() {
        let mut config = FullNodeDAConfig::InMemory;
        let result = config.apply_preset(&ProverPreset::Specter);

        assert!(result.is_ok());
        assert!(matches!(config, FullNodeDAConfig::Celestia(_)));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_full_node_da_config_apply_prover_development_preset() {
        let mut config = FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig::default());
        let result = config.apply_preset(&ProverPreset::Development);

        assert!(result.is_ok());
        assert!(matches!(config, FullNodeDAConfig::InMemory));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_create_full_node_da_layer_inmemory() {
        let config = FullNodeDAConfig::InMemory;
        let result = create_full_node_da_layer(&config).await;

        assert!(result.is_ok());
        // We can't easily test the exact type due to trait objects, but we can verify it was
        // created
    }
}
