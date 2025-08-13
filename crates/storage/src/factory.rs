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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DatabaseConfig {
    #[default]
    InMemory,
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
