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
                *self = DatabaseConfig::InMemory;
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
                *self = DatabaseConfig::InMemory;
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
