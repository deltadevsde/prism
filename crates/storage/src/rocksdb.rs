use crate::Database;
use anyhow::Result;
use jmt::{
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
    KeyHash, OwnedValue, Version,
};
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
