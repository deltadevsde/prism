use std::sync::Arc;

use crate::Database;
use anyhow::{Result, anyhow};
use jmt::{
    KeyHash, OwnedValue, Version,
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
};
use prism_common::digest::Digest;
use prism_errors::DatabaseError;
use prism_serde::binary::{FromBinary, ToBinary};
use rocksdb::{DB, DBWithThreadMode, MultiThreaded, Options};
use serde::{Deserialize, Serialize};

type RocksDB = DBWithThreadMode<MultiThreaded>;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RocksDBConfig {
    pub path: String,
}

impl RocksDBConfig {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }
}

#[derive(Clone)]
pub struct RocksDBConnection {
    connection: Arc<RocksDB>,
    path: String,
}

impl RocksDBConnection {
    pub fn new(cfg: &RocksDBConfig) -> Result<RocksDBConnection> {
        let path = &cfg.path;
        let db = DB::open_default(path)?;

        Ok(Self {
            connection: Arc::new(db),
            path: path.to_string(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum Key {
    Commitment,
    Node,
    ValueHistory,
    Epoch,
}

fn create_final_key(prefix: Vec<u8>, suffix: impl AsRef<[u8]>) -> Vec<u8> {
    let mut key = prefix.clone();
    key.push(b':');
    key.extend_from_slice(suffix.as_ref());
    key
}

impl Key {
    fn with<T: AsRef<[u8]>>(self, suffix: T) -> Vec<u8> {
        let id = self.as_byte();
        let key = suffix.as_ref();
        let mut fullkey = Vec::<u8>::with_capacity(key.len() + 1);
        fullkey.push(id);
        fullkey.extend_from_slice(key);
        fullkey
    }

    fn as_byte(&self) -> u8 {
        match self {
            Key::Commitment => 0,
            Key::Node => 1,
            Key::ValueHistory => 2,
            Key::Epoch => 3,
        }
    }
}

impl Database for RocksDBConnection {
    fn get_commitment(&self, epoch: &u64) -> anyhow::Result<Digest> {
        let key = Key::Commitment.with(epoch.encode_to_bytes()?);
        let raw_bytes = self.connection.get(key)?.ok_or_else(|| {
            DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch))
        })?;

        let value: [u8; 32] =
            raw_bytes.try_into().expect("commitment digest should always be 32 bytes");

        Ok(Digest(value))
    }

    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> anyhow::Result<()> {
        Ok(self.connection.put::<&[u8], [u8; 32]>(
            Key::Commitment.with(epoch.encode_to_bytes()?).as_ref(),
            commitment.0,
        )?)
    }

    fn get_last_synced_height(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(b"app_state:sync_height")?
            .ok_or_else(|| DatabaseError::NotFoundError("current sync height".to_string()))?;

        Ok(u64::from_be_bytes(res.try_into().map_err(|e| {
            anyhow!("failed byte conversion from BigEndian to u64: {:?}", e)
        })?))
    }

    fn set_last_synced_height(&self, height: &u64) -> anyhow::Result<()> {
        Ok(self.connection.put(b"app_state:sync_height", height.to_be_bytes())?)
    }

    fn get_epoch(&self, height: &u64) -> anyhow::Result<prism_da::FinalizedEpoch> {
        let key = Key::Epoch.with(height.encode_to_bytes()?);
        let epoch_data = self
            .connection
            .get(key)?
            .ok_or_else(|| DatabaseError::NotFoundError(format!("epoch at height {}", height)))?;

        prism_da::FinalizedEpoch::decode_from_bytes(&epoch_data).map_err(|e| {
            anyhow!(DatabaseError::ParsingError(format!(
                "Failed to decode epoch at height {}: {}",
                height, e
            )))
        })
    }

    fn add_epoch(&self, epoch: &prism_da::FinalizedEpoch) -> anyhow::Result<()> {
        // Get the latest height to check for sequential ordering
        let latest_height = self.get_latest_epoch_height().ok();

        if let Some(latest) = latest_height {
            if latest as usize + 1 != epoch.height as usize {
                return Err(anyhow!(DatabaseError::WriteError(format!(
                    "epoch height mismatch: expected {}, got {}",
                    latest + 1,
                    epoch.height
                ))));
            }
        } else if epoch.height != 0 {
            // If there's no latest height, we expect the first epoch to have height 0
            return Err(anyhow!(DatabaseError::WriteError(format!(
                "first epoch must have height 0, got {}",
                epoch.height
            ))));
        }

        // Encode the epoch to bytes
        let epoch_data = epoch.encode_to_bytes().map_err(|e| {
            anyhow!(DatabaseError::ParsingError(format!(
                "Failed to encode epoch at height {}: {}",
                epoch.height, e
            )))
        })?;

        // Use a write batch to atomically store the epoch and update the latest height
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(
            Key::Epoch.with(epoch.height.encode_to_bytes()?),
            &epoch_data,
        );
        batch.put(b"app_state:latest_epoch_height", epoch.height.to_be_bytes());

        self.connection.write(batch)?;
        Ok(())
    }

    fn get_latest_epoch_height(&self) -> anyhow::Result<u64> {
        let res = self
            .connection
            .get(b"app_state:latest_epoch_height")?
            .ok_or_else(|| DatabaseError::NotFoundError("latest epoch height".to_string()))?;

        Ok(u64::from_be_bytes(res.try_into().map_err(|e| {
            anyhow!("failed byte conversion from BigEndian to u64: {:?}", e)
        })?))
    }

    fn get_latest_epoch(&self) -> anyhow::Result<prism_da::FinalizedEpoch> {
        let height = self.get_latest_epoch_height()?;
        self.get_epoch(&height)
    }

    fn flush_database(&self) -> Result<()> {
        Ok(DB::destroy(&Options::default(), &self.path)?)
    }
}

impl TreeReader for RocksDBConnection {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let key = Key::Node.with(node_key.encode_to_bytes()?);
        let value = self.connection.get(key)?;

        // Check if node has valid data
        match value {
            Some(data) => Ok(Some(Node::decode_from_bytes(&data)?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let value_key = Key::ValueHistory.with(key_hash.0);
        let max_version_bytes = max_version.to_be_bytes();
        let max_key = create_final_key(value_key.clone(), max_version_bytes);

        // Search db backwards starting at max_key
        let mut iter = self.connection.iterator(rocksdb::IteratorMode::From(
            &max_key,
            rocksdb::Direction::Reverse,
        ));

        // Search for value
        if let Some(Ok((key, value))) = iter.next() {
            // Ensure the key is the same
            if key.starts_with(&value_key) {
                return Ok(Some(OwnedValue::decode_from_bytes(&value)?));
            }
        }

        Ok(None)
    }

    // This method only gets called on JMT restoration
    // TODO: Add test cases in KeyDirectoryTree to test this functionality
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        unimplemented!("JMT restoration from snapshot is unimplemented.")
    }
}

impl TreeWriter for RocksDBConnection {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();

        // Put each node in the batch (for tree structure)
        for (node_key, node) in node_batch.nodes() {
            let key = Key::Node.with(node_key.encode_to_bytes()?);
            let value = node.encode_to_bytes()?;
            batch.put(key, &value);
        }

        // Put each value in the batch (for versioning)
        for ((version, key_hash), value) in node_batch.values() {
            // Create base key
            let value_key = Key::ValueHistory.with(key_hash.0);
            let encoded_value =
                value.as_ref().map(|v| v.encode_to_bytes()).transpose()?.unwrap_or_default();
            let version_bytes = version.to_be_bytes();

            // Create final key
            let final_key = create_final_key(value_key, version_bytes);

            batch.put(final_key, &encoded_value);
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
        let cfg = RocksDBConfig::new(temp_dir.path().to_str().unwrap());
        let db = RocksDBConnection::new(&cfg).unwrap();
        (temp_dir, db)
    }

    #[test]
    fn test_rw_commitment() {
        let (_temp_dir, db) = setup_db();

        let epoch = 1;
        let commitment = Digest([1; 32]);

        db.set_commitment(&epoch, &commitment).unwrap();
        let read_commitment = db.get_commitment(&epoch).unwrap();

        assert_eq!(read_commitment, commitment);
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
