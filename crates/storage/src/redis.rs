use anyhow::{Result, anyhow};
use jmt::{
    KeyHash, OwnedValue, Version,
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
};
use prism_common::digest::Digest;
use prism_da::FinalizedEpoch;
use prism_serde::{
    binary::{FromBinary, ToBinary},
    hex::{FromHex, ToHex},
};
use redis::{Client, Commands, Connection};
use serde::{Deserialize, Serialize};
use std::{
    self,
    process::Command,
    sync::{Mutex, MutexGuard},
    thread::sleep,
    time::Duration,
};

use prism_errors::DatabaseError;

use crate::database::{Database, convert_to_connection_error};
use tracing::debug;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RedisConfig {
    pub connection_string: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        RedisConfig {
            connection_string: "redis://127.0.0.1/".to_string(),
        }
    }
}

// there are different key prefixes for the different tables in the database
// app_state:key => app state (just epoch counter for now)
// commitments:key => epoch commitments
pub struct RedisConnection {
    connection: Mutex<Connection>,
}

impl RedisConnection {
    pub fn new(cfg: &RedisConfig) -> Result<RedisConnection> {
        let connection_string = cfg.connection_string.clone();
        let try_client =
            Client::open(connection_string.clone()).map_err(convert_to_connection_error)?;
        let try_connection = try_client.get_connection();

        if try_connection.is_err() {
            debug!("starting redis-server...");

            let _child = Command::new("redis-server")
                .spawn()
                .map_err(|e| DatabaseError::InitializationError(e.to_string()))?;

            // TODO: fix this hack
            sleep(Duration::from_secs(5));
            debug!("redis-server started");
        }

        let client = Client::open(connection_string).map_err(convert_to_connection_error)?;
        let connection = client.get_connection().map_err(convert_to_connection_error)?;

        Ok(RedisConnection {
            connection: Mutex::new(connection),
        })
    }
    // looks like we need lifetime annotations here, because we are returning a MutexGuard:
    // 'a is a generic lifetime and &'a Mutex<T> should make sure, that the MutexGuard is not
    // dropped before the Mutex itself... because rust can not make sure that's the case, we
    // need to use the 'static lifetime here (but i dont really know why the issue pops up now
    // and not before, i think we were using the same/similar pattern in the other functions)
    fn lock_connection(&self) -> Result<MutexGuard<Connection>> {
        self.connection.lock().map_err(|_| anyhow!(DatabaseError::LockError))
    }
}

impl TreeReader for RedisConnection {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let mut con = self.lock_connection()?;
        let serialized_key = node_key.encode_to_bytes()?.to_hex();
        let node_data: Option<Vec<u8>> = con.get(format!("node:{}", serialized_key))?;
        Ok(node_data.map(|data| Node::decode_from_bytes(&data).unwrap()))
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let mut con = self.lock_connection()?;
        let keys: Vec<String> = con.keys("node:*")?;
        let mut rightmost: Option<(NodeKey, LeafNode)> = None;

        for key in keys {
            let node_data: Vec<u8> = con.get(&key)?;
            let node = Node::decode_from_bytes(&node_data)?;
            if let Node::Leaf(leaf_node) = node {
                let node_key_bytes = Vec::<u8>::from_hex(key.strip_prefix("node:").unwrap())?;
                let node_key = NodeKey::decode_from_bytes(&node_key_bytes)?;
                if rightmost.is_none()
                    || leaf_node.key_hash() > rightmost.as_ref().unwrap().1.key_hash()
                {
                    rightmost = Some((node_key, leaf_node));
                }
            }
        }

        Ok(rightmost)
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let mut con = self.lock_connection()?;
        let value_key = format!("value_history:{}", key_hash.0.to_hex());
        let values: Vec<(String, f64)> =
            con.zrevrangebyscore_withscores(&value_key, max_version as f64, 0f64)?;

        if let Some((encoded_value, _)) = values.first() {
            if encoded_value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(OwnedValue::from_hex(encoded_value)?))
            }
        } else {
            Ok(None)
        }
    }
}

impl TreeWriter for RedisConnection {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let mut con = self.lock_connection()?;
        let mut pipe = redis::pipe();

        for (node_key, node) in node_batch.nodes() {
            let serialized_key = node_key.encode_to_bytes()?.to_hex();
            let node_data = node.encode_to_bytes()?;
            pipe.set(format!("node:{}", serialized_key), node_data);
        }

        for ((version, key_hash), value) in node_batch.values() {
            let value_key = format!("value_history:{}", key_hash.0.to_hex());
            let encoded_value = value.as_ref().map(ToHex::to_hex).unwrap_or_default();
            pipe.zadd(&value_key, encoded_value, *version as f64);
        }

        pipe.execute(&mut con);
        Ok(())
    }
}

impl Database for RedisConnection {
    fn get_commitment(&self, epoch: &u64) -> Result<Digest> {
        let mut con = self.lock_connection()?;
        let redis_value =
            con.get::<&str, String>(&format!("commitments:epoch_{}", epoch)).map_err(|_| {
                DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch))
            })?;

        // storing hashes into
        let value = redis_value.trim_matches('"').as_bytes();
        Ok(Digest(value.try_into().unwrap()))
    }

    fn get_last_synced_height(&self) -> Result<u64> {
        let mut con = self.lock_connection()?;
        con.get("app_state:sync_height").map_err(|_| {
            anyhow!(DatabaseError::NotFoundError(
                "current sync height".to_string()
            ))
        })
    }

    fn set_last_synced_height(&self, height: &u64) -> Result<()> {
        let mut con = self.lock_connection()?;
        con.set::<&str, &u64, ()>("app_state:sync_height", height).map_err(|_| {
            anyhow!(DatabaseError::WriteError(format!(
                "sync_height: {}",
                height
            )))
        })
    }

    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> Result<()> {
        let mut con = self.lock_connection()?;
        con.set::<&String, &[u8; 32], ()>(&format!("commitments:epoch_{}", epoch), &commitment.0)
            .map_err(|_| {
                anyhow!(DatabaseError::WriteError(format!(
                    "commitment for epoch: {}",
                    epoch
                )))
            })
    }

    fn get_epoch(&self, height: &u64) -> Result<FinalizedEpoch> {
        let mut con = self.lock_connection()?;
        let epoch_data: Vec<u8> = con
            .get(format!("epochs:height_{}", height))
            .map_err(|_| DatabaseError::NotFoundError(format!("epoch at height {}", height)))?;

        FinalizedEpoch::decode_from_bytes(&epoch_data).map_err(|e| {
            anyhow!(DatabaseError::ParsingError(format!(
                "Failed to decode epoch at height {}: {}",
                height, e
            )))
        })
    }

    fn add_epoch(&self, epoch: &FinalizedEpoch) -> Result<()> {
        let mut con = self.lock_connection()?;

        // Get the latest height to check for sequential ordering
        let latest_height: Option<u64> = con.get("app_state:latest_epoch_height").ok();

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

        // Store the epoch and update the latest height
        let mut pipe = redis::pipe();
        pipe.set(format!("epochs:height_{}", epoch.height), epoch_data)
            .set("app_state:latest_epoch_height", epoch.height);

        pipe.execute(&mut con);
        Ok(())
    }

    fn get_latest_epoch_height(&self) -> Result<u64> {
        let mut con = self.lock_connection()?;
        con.get("app_state:latest_epoch_height")
            .map_err(|_| DatabaseError::NotFoundError("latest epoch height".to_string()).into())
    }

    fn get_latest_epoch(&self) -> Result<FinalizedEpoch> {
        let height = self.get_latest_epoch_height()?;
        self.get_epoch(&height)
    }

    fn flush_database(&self) -> Result<()> {
        let mut conn = self.lock_connection()?;
        redis::cmd("FLUSHALL")
            .query::<()>(&mut conn)
            .map_err(|_| anyhow!(DatabaseError::DeleteError("all transactions".to_string())))
    }
}
