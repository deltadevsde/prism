use prism_errors::DataAvailabilityError;
use prism_presets::{ApplyPreset, LightClientPreset, PresetError};
#[cfg(not(target_arch = "wasm32"))]
use prism_presets::{FullNodePreset, ProverPreset};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
#[cfg(not(target_arch = "wasm32"))]
use tracing::error;
use tracing::info;

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    DataAvailabilityLayer,
    celestia::{CelestiaConnection, CelestiaFullNodeDAConfig, CelestiaLightClientDAStoreConfig},
    consts::{DA_RETRY_COUNT, DA_RETRY_INTERVAL},
};

#[cfg(all(feature = "aws", not(target_arch = "wasm32")))]
use crate::aws::{AwsFullNodeDAConfig, AwsFullNodeDataAvailabilityLayer};
use crate::{
    LightDataAvailabilityLayer,
    celestia::{CelestiaLightClientDAConfig, LightClientConnection},
    memory::InMemoryDataAvailabilityLayer,
};

#[cfg(feature = "aws")]
use crate::aws::{AwsLightClientDAConfig, AwsLightDataAvailabilityLayer};

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

    /// AWS S3 DA configuration with light client support.
    /// Provides WORM-compliant data retrieval from S3 Object Lock buckets
    /// with configurable regions and credentials.
    #[cfg(feature = "aws")]
    Aws(AwsLightClientDAConfig),

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
        #[cfg(feature = "aws")]
        LightClientDAConfig::Aws(aws_config) => {
            info!("Using AWS config: {:?}", aws_config);
            let connection = AwsLightDataAvailabilityLayer::new(aws_config).await?;
            Ok(Arc::new(connection))
        }
        LightClientDAConfig::InMemory => {
            let (da_layer, _height_rx, _block_rx) =
                InMemoryDataAvailabilityLayer::new(Duration::from_secs(10));
            Ok(Arc::new(da_layer))
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

    /// AWS S3 DA configuration with full node capabilities.
    /// Provides WORM-compliant data publishing and retrieval using S3 Object Lock
    /// with configurable retention periods and cross-region replication.
    #[cfg(feature = "aws")]
    Aws(AwsFullNodeDAConfig),

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
        #[cfg(feature = "aws")]
        FullNodeDAConfig::Aws(aws_config) => {
            info!("Using AWS config: {:?}", aws_config);
            for attempt in 1..=DA_RETRY_COUNT {
                match AwsFullNodeDataAvailabilityLayer::new(aws_config).await {
                    Ok(da) => return Ok(Arc::new(da)),
                    Err(e) => {
                        if attempt == DA_RETRY_COUNT {
                            return Err(DataAvailabilityError::NetworkError(format!(
                                "failed to connect to AWS S3 after {} attempts: {}",
                                DA_RETRY_COUNT, e
                            )));
                        }
                        error!(
                            "Attempt {} to connect to AWS S3 failed: {}. Retrying in {} seconds...",
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

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use prism_presets::{FullNodePreset, LightClientPreset, ProverPreset};

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

    #[cfg(all(feature = "aws", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_create_aws_light_client_da_layer() {
        use crate::aws::{AwsCredentialsConfig, AwsLightClientDAConfig};

        let config = LightClientDAConfig::Aws(AwsLightClientDAConfig {
            region: "us-east-1".to_string(),
            endpoint: Some("http://localhost:4566".to_string()), // LocalStack for testing
            epochs_bucket: "test-epochs-bucket".to_string(),
            metadata_bucket: "test-metadata-bucket".to_string(),
            max_timeout: Duration::from_secs(10),
            max_retries: 1,
            credentials: AwsCredentialsConfig::development("test".to_string(), "test".to_string()),
            key_prefix: String::new(),
            block_time: Duration::from_millis(100),
        });

        let result = create_light_client_da_layer(&config).await;

        // This will typically fail in CI without AWS/LocalStack setup, which is expected
        match result {
            Ok(_da_layer) => {
                // Success case - would happen with proper AWS setup
                println!("AWS light client DA layer created successfully");
            }
            Err(e) => {
                // Expected failure case in test environment
                assert!(
                    e.to_string().contains("InitializationError")
                        || e.to_string().contains("NetworkError")
                        || e.to_string().contains("Connection")
                        || e.to_string().contains("credentials")
                );
            }
        }
    }

    #[cfg(all(feature = "aws", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_create_aws_full_node_da_layer() {
        use crate::aws::{AwsCredentialsConfig, AwsFullNodeDAConfig, AwsLightClientDAConfig};

        let config = FullNodeDAConfig::Aws(AwsFullNodeDAConfig {
            light_client: AwsLightClientDAConfig {
                region: "us-east-1".to_string(),
                endpoint: Some("http://localhost:4566".to_string()), // LocalStack for testing
                epochs_bucket: "test-epochs-bucket".to_string(),
                metadata_bucket: "test-metadata-bucket".to_string(),
                max_timeout: Duration::from_secs(10),
                max_retries: 1,
                credentials: AwsCredentialsConfig::development(
                    "test".to_string(),
                    "test".to_string(),
                ),
                key_prefix: String::new(),
                block_time: Duration::from_millis(100),
            },
            transactions_bucket: "test-transactions-bucket".to_string(),
            retention_days: 1,
            enable_legal_holds: false,
            enable_cross_region_replication: false,
            replication_region: None,
            max_concurrent_uploads: 2,
        });

        let result = create_full_node_da_layer(&config).await;

        // This will typically fail in CI without AWS/LocalStack setup, which is expected
        match result {
            Ok(_da_layer) => {
                // Success case - would happen with proper AWS setup
                println!("AWS full node DA layer created successfully");
            }
            Err(e) => {
                // Expected failure case in test environment
                assert!(
                    e.to_string().contains("failed to connect to AWS S3")
                        || e.to_string().contains("InitializationError")
                        || e.to_string().contains("NetworkError")
                );
            }
        }
    }

    #[cfg(all(feature = "aws", not(target_arch = "wasm32")))]
    #[test]
    fn test_aws_preset_compatibility() {
        use crate::aws::{AwsFullNodeDAConfig, AwsLightClientDAConfig};

        // Test that AWS configs work with presets
        let mut aws_full_config = FullNodeDAConfig::Aws(AwsFullNodeDAConfig {
            light_client: AwsLightClientDAConfig::default(),
            transactions_bucket: "test-bucket".to_string(),
            retention_days: 30,
            enable_legal_holds: false,
            enable_cross_region_replication: false,
            replication_region: None,
            max_concurrent_uploads: 5,
        });

        // Apply development preset - should switch to InMemory
        let result = aws_full_config.apply_preset(&FullNodePreset::Development);
        assert!(result.is_ok());
        assert!(matches!(aws_full_config, FullNodeDAConfig::InMemory));

        // Test with Specter preset - should switch to Celestia
        let mut aws_config = FullNodeDAConfig::Aws(AwsFullNodeDAConfig::default());
        let result = aws_config.apply_preset(&FullNodePreset::Specter);
        assert!(result.is_ok());
        assert!(matches!(aws_config, FullNodeDAConfig::Celestia(_)));
    }
}
