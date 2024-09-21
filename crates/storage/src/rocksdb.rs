use crate::Database;
use anyhow::{anyhow, Result};
use jmt::{
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
    KeyHash, OwnedValue, Version,
};
use prism_common::hashchain::{HashchainEntry, Hashchain};
use prism_errors::{DatabaseError, GeneralError};
use rocksdb::{DBWithThreadMode, Error, MultiThreaded, DB};

type RocksDB = DBWithThreadMode<MultiThreaded>;

pub struct RocksDBConnection {
    connection: RocksDB,
}

impl RocksDBConnection {
    pub fn new() -> Result<RocksDBConnection, Error> {
        let path = "";
        let db = DB::open_default(path)?;

        Ok(Self { connection: db })
    }
}

impl Database for RocksDBConnection {
    fn get_hashchain(&self, key: &str) -> anyhow::Result<prism_common::hashchain::Hashchain> {
        let value = match self.connection.get(key.as_bytes().to_vec()) {
            Ok(Some(value)) => Ok(String::from_utf8(value)?),
            Ok(None) => Err(DatabaseError::NotFoundError(format!("hashchain key: {}", key))),
            Err(e) => Err(DatabaseError::ReadError(e.to_string()))
        };

        let res: Vec<HashchainEntry> = serde_json::from_str(&value?)
            .map_err(|e| {
                anyhow!(GeneralError::ParsingError(format!("hashchain: {}", e)))
            })?;

        Ok(Hashchain {
            id: key.to_string(),
            entries: res
        })
    }

    fn set_hashchain(
        &self,
        incoming_operation: &prism_common::operation::Operation,
        value: &[prism_common::hashchain::HashchainEntry],
    ) -> anyhow::Result<()> {
        todo!()
    }

    fn get_commitment(&self, epoch: &u64) -> anyhow::Result<String> {
        todo!()
    }

    fn set_commitment(
        &self,
        epoch: &u64,
        commitment: &prism_common::tree::Digest,
    ) -> anyhow::Result<()> {
        todo!()
    }

    fn get_epoch(&self) -> anyhow::Result<u64> {
        todo!()
    }

    fn set_epoch(&self, epoch: &u64) -> anyhow::Result<()> {
        todo!()
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
