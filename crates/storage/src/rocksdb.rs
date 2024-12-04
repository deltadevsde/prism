use std::sync::Arc;

use crate::Database;
use anyhow::Result;
use bincode;
use jmt::{
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
    KeyHash, OwnedValue, Version,
};
use prism_common::digest::Digest;
use prism_errors::DatabaseError;
use rocksdb::{DBWithThreadMode, MultiThreaded, Options, DB};

type RocksDB = DBWithThreadMode<MultiThreaded>;

#[derive(Clone)]
pub struct RocksDBConnection {
    connection: Arc<RocksDB>,
    path: String,
}

impl RocksDBConnection {
    pub fn new(path: &str) -> Result<RocksDBConnection> {
        let db = DB::open_default(path)?;

        Ok(Self {
            connection: Arc::new(db),
            path: path.to_string(),
        })
    }
}

impl Database for RocksDBConnection {
    fn get_commitment(&self, epoch: &u64) -> anyhow::Result<Digest> {
        let key = format!("commitments:epoch_{}", epoch);
        let raw_bytes = self.connection.get(key.as_bytes())?.ok_or_else(|| {
            DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch))
        })?;

        let value: [u8; 32] =
            raw_bytes.try_into().expect("commitment digest should always be 32 bytes");

        Ok(Digest(value))
    }

    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> anyhow::Result<()> {
        Ok(self.connection.put::<&[u8], [u8; 32]>(
            format!("commitments:epoch_{}", epoch).as_bytes(),
            commitment.0,
        )?)
    }

    fn get_last_synced_height(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(b"app_state:sync_height")?
            .ok_or_else(|| DatabaseError::NotFoundError("current sync height".to_string()))?;

        Ok(u64::from_be_bytes(res.try_into().unwrap()))
    }

    fn set_last_synced_height(&self, height: &u64) -> anyhow::Result<()> {
        Ok(self.connection.put(b"app_state:sync_height", height.to_be_bytes())?)
    }

    fn get_epoch(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(b"app_state:epoch")?
            .ok_or_else(|| DatabaseError::NotFoundError("current epoch".to_string()))?;

        Ok(u64::from_be_bytes(res.try_into().unwrap()))
    }

    fn set_epoch(&self, epoch: &u64) -> anyhow::Result<()> {
        Ok(self.connection.put(b"app_state:epoch", epoch.to_be_bytes())?)
    }

    fn flush_database(&self) -> Result<()> {
        Ok(DB::destroy(&Options::default(), &self.path)?)
    }
}

impl TreeReader for RocksDBConnection {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let key = format!("node:{}", hex::encode(bincode::serialize(node_key)?));
        let value = self.connection.get(key.as_bytes())?;

        match value {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let value_key = format!("value_history:{}", hex::encode(key_hash.0));
        let iter = self.connection.prefix_iterator(value_key.as_bytes());

        let mut latest_value = None;
        let mut latest_version = 0;

        for item in iter {
            let (key, value) = item?;
            let version: Version =
                bincode::deserialize(&hex::decode(&key[value_key.len() + 1..])?)?;

            if version <= max_version && version > latest_version {
                latest_version = version;
                latest_value = Some(value);
            }
        }

        Ok(latest_value.map(|v| bincode::deserialize(&v).unwrap()))
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let mut iter = self.connection.iterator(rocksdb::IteratorMode::End);

        while let Some(Ok((key, value))) = iter.next() {
            if key.starts_with(b"node:") {
                let node: Node = bincode::deserialize(&value)?;
                if let Node::Leaf(leaf) = node {
                    let node_key: NodeKey = bincode::deserialize(&hex::decode(&key[5..])?)?;
                    return Ok(Some((node_key, leaf)));
                }
            }
        }

        Ok(None)
    }
}

impl TreeWriter for RocksDBConnection {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();

        for (node_key, node) in node_batch.nodes() {
            let key = format!("node:{}", hex::encode(bincode::serialize(node_key)?));
            let value = bincode::serialize(node)?;
            batch.put(key.as_bytes(), &value);
        }

        for ((version, key_hash), value) in node_batch.values() {
            let value_key = format!("value_history:{}", hex::encode(key_hash.0));
            let version_key = format!(
                "{}:{}",
                value_key,
                hex::encode(bincode::serialize(version)?)
            );

            if let Some(v) = value {
                let serialized_value = bincode::serialize(v)?;
                batch.put(version_key.as_bytes(), &serialized_value);
            } else {
                batch.delete(version_key.as_bytes());
            }
        }

        self.connection.write(batch)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmt::{KeyHash, OwnedValue, Version};
    use tempfile::TempDir;

    fn setup_db() -> (TempDir, RocksDBConnection) {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDBConnection::new(temp_dir.path().to_str().unwrap()).unwrap();
        (temp_dir, db)
    }

    #[test]
    fn test_write_and_read_value() {
        let (_temp_dir, db) = setup_db();

        let key_hash = KeyHash([1; 32]);
        let value: OwnedValue = vec![4, 5, 6];
        let version: Version = 1;

        let mut batch = NodeBatch::default();
        batch.insert_value(version, key_hash, value.clone());

        db.write_node_batch(&batch).unwrap();

        let read_value = db.get_value_option(version, key_hash).unwrap();
        assert_eq!(read_value, Some(value));
    }

    #[test]
    fn test_get_value_option_with_multiple_versions() {
        let (_temp_dir, db) = setup_db();

        let key_hash = KeyHash([2; 32]);
        let value1: OwnedValue = vec![1, 1, 1];
        let value2: OwnedValue = vec![2, 2, 2];

        let mut batch = NodeBatch::default();
        batch.insert_value(1, key_hash, value1.clone());
        batch.insert_value(2, key_hash, value2.clone());

        db.write_node_batch(&batch).unwrap();

        assert_eq!(db.get_value_option(1, key_hash).unwrap(), Some(value1));
        assert_eq!(
            db.get_value_option(2, key_hash).unwrap(),
            Some(value2.clone())
        );
        assert_eq!(db.get_value_option(3, key_hash).unwrap(), Some(value2));
    }
}
