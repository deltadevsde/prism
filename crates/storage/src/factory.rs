use std::sync::Arc;

use anyhow::Result;
use prism_errors::DatabaseError;
use prism_presets::{ApplyPreset, FullNodePreset, PresetError, ProverPreset};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    Database,
    inmemory::InMemoryDatabase,
    rocksdb::{RocksDBConfig, RocksDBConnection},
};

/// Configuration for the storage layer used by Prism nodes.
///
/// Determines which database implementation to use and its configuration.
/// Different backends provide trade-offs between performance, durability, and resource usage.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DatabaseConfig {
    /// In-memory storage backend for development and testing.
    /// Stores all data in RAM without persistence across restarts.
    #[default]
    InMemory,

    /// RocksDB storage backend for production deployments.
    /// Provides persistent, crash-resistant storage with LSM-tree architecture.
    RocksDB(RocksDBConfig),
}

impl ApplyPreset<FullNodePreset> for DatabaseConfig {
    fn apply_preset(&mut self, preset: &FullNodePreset) -> Result<(), PresetError> {
        match preset {
            FullNodePreset::Development => {
                *self = Self::InMemory;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl ApplyPreset<ProverPreset> for DatabaseConfig {
    fn apply_preset(&mut self, preset: &ProverPreset) -> Result<(), PresetError> {
        match preset {
            ProverPreset::Development => {
                *self = Self::InMemory;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Creates a database instance from the given configuration.
///
/// This function initializes the appropriate storage backend and returns
/// a trait object that implements the [`Database`] interface.
///
/// See the crate-level documentation for usage examples and integration patterns.
pub async fn create_storage(
    config: &DatabaseConfig,
) -> Result<Arc<Box<dyn Database>>, DatabaseError> {
    info!("Initializing storage layer...");
    match config {
        DatabaseConfig::InMemory => Ok(Arc::new(Box::new(InMemoryDatabase::new()))),
        DatabaseConfig::RocksDB(config) => {
            let db = RocksDBConnection::new(config)?;
            Ok(Arc::new(Box::new(db)))
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use prism_presets::{FullNodePreset, ProverPreset};

    #[test]
    fn test_database_config_default() {
        let config = DatabaseConfig::default();
        assert!(matches!(config, DatabaseConfig::InMemory));
    }

    #[test]
    fn test_database_config_apply_full_node_development_preset() {
        let mut config = DatabaseConfig::RocksDB(RocksDBConfig::new("/test/data"));
        let result = config.apply_preset(&FullNodePreset::Development);

        assert!(result.is_ok());
        assert!(matches!(config, DatabaseConfig::InMemory));
    }

    #[test]
    fn test_database_config_apply_full_node_specter_preset() {
        let mut config = DatabaseConfig::InMemory;
        let result = config.apply_preset(&FullNodePreset::Specter);

        assert!(result.is_ok());
        // Specter preset doesn't change the database config, so it should remain InMemory
        assert!(matches!(config, DatabaseConfig::InMemory));
    }

    #[test]
    fn test_database_config_apply_prover_development_preset() {
        let mut config = DatabaseConfig::RocksDB(RocksDBConfig::new("/test/data"));
        let result = config.apply_preset(&ProverPreset::Development);

        assert!(result.is_ok());
        assert!(matches!(config, DatabaseConfig::InMemory));
    }

    #[test]
    fn test_database_config_apply_prover_specter_preset() {
        let mut config = DatabaseConfig::InMemory;
        let result = config.apply_preset(&ProverPreset::Specter);

        assert!(result.is_ok());
        // Specter preset doesn't change the database config, so it should remain InMemory
        assert!(matches!(config, DatabaseConfig::InMemory));
    }

    #[tokio::test]
    async fn test_create_storage_inmemory() {
        let config = DatabaseConfig::InMemory;
        let result = create_storage(&config).await;

        assert!(result.is_ok());
        // Verify that the factory creates storage successfully
    }

    #[tokio::test]
    async fn test_create_storage_rocksdb() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config = DatabaseConfig::RocksDB(RocksDBConfig::new(temp_dir.path().to_str().unwrap()));
        let result = create_storage(&config).await;

        assert!(result.is_ok());
        // Verify that the factory creates storage successfully
    }
}
