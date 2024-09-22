use crate::Database;
use anyhow::{anyhow, Result};
use jmt::{
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
    KeyHash, OwnedValue, Version,
};
use prism_errors::DatabaseError;
use rocksdb::{DBWithThreadMode, Error, MultiThreaded, DB};

type RocksDB = DBWithThreadMode<MultiThreaded>;

pub struct RocksDBConnection {
    connection: RocksDB,
}

impl RocksDBConnection {
    pub fn new(path: &str) -> Result<RocksDBConnection, Error> {
        let db = DB::open_default(path)?;

        Ok(Self { connection: db })
    }
}

impl Database for RocksDBConnection {
    fn get_commitment(&self, epoch: &u64) -> anyhow::Result<String> {
        let key = format!("commitments:epoch_{}", epoch);
        let value = self.connection.get(key.as_bytes())?.ok_or_else(|| {
            DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch))
        })?;

        Ok(String::from_utf8(value)?)
    }

    fn set_commitment(
        &self,
        epoch: &u64,
        commitment: &prism_common::tree::Digest,
    ) -> anyhow::Result<()> {
        Ok(self.connection.put(
            format!("commitments:epoch_{}", epoch).as_bytes(),
            commitment.to_bytes(),
        )?)
    }

    fn get_epoch(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(b"app_state:epoch")?
            .ok_or_else(|| DatabaseError::NotFoundError("current epoch".to_string()))?;

        Ok(u64::from_be_bytes(
            res.try_into()
                .map_err(|e| DatabaseError::ReadError(e.to_string()))?,
        ))
    }

    fn set_epoch(&self, epoch: &u64) -> anyhow::Result<()> {
        Ok(self
            .connection
            .put(b"app_state:epoch", epoch.to_be_bytes())?)
    }
}

impl TreeWriter for RocksDBConnection {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        todo!()
    }
}

impl TreeReader for RocksDBConnection {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        todo!()
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        todo!()
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        todo!()
    }
}
