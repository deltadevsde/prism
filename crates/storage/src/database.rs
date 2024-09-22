use anyhow::Result;
use auto_impl::auto_impl;
use jmt::storage::{TreeReader, TreeWriter};
use prism_common::tree::Digest;
use prism_errors::{DatabaseError, PrismError};

#[auto_impl(&, Box, Arc)]
pub trait Database: Send + Sync + TreeReader + TreeWriter {
    fn get_commitment(&self, epoch: &u64) -> Result<String>;
    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> Result<()>;

    fn get_epoch(&self) -> Result<u64>;
    fn set_epoch(&self, epoch: &u64) -> Result<()>;

    #[cfg(test)]
    fn flush_database(&self) -> Result<()>;
}

pub fn convert_to_connection_error(e: redis::RedisError) -> PrismError {
    PrismError::Database(DatabaseError::ConnectionError(e.to_string()))
}
