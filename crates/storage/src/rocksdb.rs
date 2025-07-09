use std::sync::Arc;

use crate::Database;
use anyhow::{Result, anyhow};
use jmt::{
    KeyHash, OwnedValue, Version,
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
};
use prism_common::digest::Digest;
use prism_errors::DatabaseError;
use prism_serde::{
    binary::{FromBinary, ToBinary},
    hex::FromHex,
};
use rocksdb::{DB, DBWithThreadMode, MultiThreaded, Options};
use serde::{Deserialize, Serialize};

const KEY_PREFIX_COMMITMENTS: &str = "commitments:epoch_";
const KEY_PREFIX_NODE: &str = "node:";
const KEY_PREFIX_VALUE_HISTORY: &str = "value_history:";
const KEY_PREFIX_EPOCHS: &str = "epochs:height_";

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

impl Database for RocksDBConnection {
    fn get_commitment(&self, epoch: &u64) -> anyhow::Result<Digest> {
        let key = format!("{KEY_PREFIX_COMMITMENTS}{}", epoch);
        let raw_bytes = self.connection.get(key.as_bytes())?.ok_or_else(|| {
            DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch))
        })?;

        let value: [u8; 32] =
            raw_bytes.try_into().expect("commitment digest should always be 32 bytes");

        Ok(Digest(value))
    }

    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> anyhow::Result<()> {
        Ok(self.connection.put::<&[u8], [u8; 32]>(
            format!("{KEY_PREFIX_COMMITMENTS}{}", epoch).as_bytes(),
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
        let key = format!("{}{}", KEY_PREFIX_EPOCHS, height);
        let epoch_data = self
            .connection
            .get(key.as_bytes())?
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
            format!("{}{}", KEY_PREFIX_EPOCHS, epoch.height).as_bytes(),
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

fn create_key(prefix: &str, node_key: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let mut key = Vec::with_capacity(prefix.len() + node_key.as_ref().len());
    key.extend_from_slice(prefix.as_bytes());
    key.extend_from_slice(node_key.as_ref());
    Ok(key)
}

fn key_concat(prefix: Vec<u8>, suffix: impl AsRef<[u8]>) -> Result<Vec<u8>> {
<<<<<<< HEAD
    let mut key = prefix;
=======
    let mut key = prefix.clone();
>>>>>>> bed1af7c (Refactored more key stuff in rocksdb)
    key.push(b':');
    key.extend_from_slice(suffix.as_ref());
    Ok(key)
}

impl TreeReader for RocksDBConnection {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let key = create_key(KEY_PREFIX_NODE, node_key.encode_to_bytes()?)?;
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
        let value_key = create_key(KEY_PREFIX_VALUE_HISTORY, key_hash.0)?;
        let max_version_bytes = max_version.to_be_bytes();
        let max_key = key_concat(value_key.clone(), max_version_bytes)?;

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

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let mut iter = self.connection.iterator(rocksdb::IteratorMode::End);

        while let Some(Ok((key, value))) = iter.next() {
            if key.starts_with(KEY_PREFIX_NODE.as_bytes()) {
                let node: Node = Node::decode_from_bytes(&value)?;
                if let Node::Leaf(leaf) = node {
                    let node_key = NodeKey::decode_from_bytes(&Vec::<u8>::from_hex(
                        &key[KEY_PREFIX_NODE.len()..],
                    )?)?;
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

        // Put each node in the batch (for tree structure)
        for (node_key, node) in node_batch.nodes() {
            let key = create_key(KEY_PREFIX_NODE, node_key.encode_to_bytes()?)?;
            let value = node.encode_to_bytes()?;
            batch.put(key, &value);
        }

        // Put each value in the batch (for versioning)
        for ((version, key_hash), value) in node_batch.values() {
            // Create base key
            let value_key = create_key(KEY_PREFIX_VALUE_HISTORY, key_hash.0)?;
            let encoded_value =
                value.as_ref().map(|v| v.encode_to_bytes()).transpose()?.unwrap_or_default();
            let version_bytes = version.to_be_bytes();

            // Create final key
            let final_key = key_concat(value_key.clone(), version_bytes)?;

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
