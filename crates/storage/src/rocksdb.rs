use crate::Database;
use anyhow::Result;
use jmt::{
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
    KeyHash, OwnedValue, Version,
};
use rocksdb::{Options, DB};

struct RocksDBConnection {
    pub connection: String,
}

impl RocksDBConnection {
    fn new() -> Result<RocksDBConnection> {
        Ok(Self { connection: () })
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

impl Database for RocksDBConnection {
    fn get_hashchain(&self, key: &str) -> anyhow::Result<prism_common::hashchain::Hashchain> {
        todo!()
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

    fn flush_database(&self) -> anyhow::Result<()> {
        todo!()
    }
}
