use anyhow::Result;
use auto_impl::auto_impl;
use jmt::storage::{TreeReader, TreeWriter};
use prism_common::digest::Digest;
use prism_da::FinalizedEpoch;
use prism_errors::{DatabaseError, PrismError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum StorageBackend {
    RocksDB(crate::rocksdb::RocksDBConfig),
    InMemory,
    Redis(crate::redis::RedisConfig),
}

#[auto_impl(&, Box, Arc)]
pub trait Database: Send + Sync + TreeReader + TreeWriter {
    fn get_commitment(&self, epoch: &u64) -> Result<Digest>;
    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> Result<()>;

    fn get_epoch(&self, height: &u64) -> Result<FinalizedEpoch>;
    fn add_epoch(&self, epoch: &FinalizedEpoch) -> Result<()>;

    fn get_latest_epoch_height(&self) -> Result<u64>;
    fn get_latest_epoch(&self) -> Result<FinalizedEpoch>;

    fn get_last_synced_height(&self) -> Result<u64>;
    fn set_last_synced_height(&self, height: &u64) -> Result<()>;

    fn flush_database(&self) -> Result<()>;
}

pub fn convert_to_connection_error(e: redis::RedisError) -> PrismError {
    PrismError::Database(DatabaseError::ConnectionError(e.to_string()))
}
