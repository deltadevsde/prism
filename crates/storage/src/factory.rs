use std::sync::Arc;

use anyhow::Result;
use prism_errors::DatabaseError;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    Database,
    inmemory::InMemoryDatabase,
    rocksdb::{RocksDBConfig, RocksDBConnection},
};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub enum DatabaseConfig {
    #[default]
    InMemory,
    RocksDB(RocksDBConfig),
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
