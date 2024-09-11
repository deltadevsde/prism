use anyhow::{anyhow, Result};
use auto_impl::auto_impl;
use jmt::{
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
    KeyHash, OwnedValue, Version,
};
use mockall::predicate::*;
use redis::{Client, Commands, Connection};
use std::{
    self,
    process::Command,
    sync::{Mutex, MutexGuard},
    thread::sleep,
    time::Duration,
};

use crate::{
    cfg::RedisConfig,
    error::{DatabaseError, GeneralError, PrismError},
};
use prism_common::{
    hashchain::{Hashchain, HashchainEntry},
    operation::Operation,
    tree::Digest,
};

// there are different key prefixes for the different tables in the database
// app_state:key => app state (just epoch counter for now)
// commitments:key => epoch commitments
pub struct RedisConnection {
    connection: Mutex<Connection>,
}

#[auto_impl(&, Box, Arc)]
pub trait Database: Send + Sync + TreeReader + TreeWriter {
    fn get_hashchain(&self, key: &str) -> Result<Hashchain>;
    fn update_hashchain(
        &self,
        incoming_operation: &Operation,
        value: &[HashchainEntry],
    ) -> Result<()>;

    fn get_commitment(&self, epoch: &u64) -> Result<String>;
    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> Result<()>;

    fn get_epoch(&self) -> Result<u64>;
    fn set_epoch(&self, epoch: &u64) -> Result<()>;

    #[cfg(test)]
    fn flush_database(&self) -> Result<()>;
}

fn convert_to_connection_error(e: redis::RedisError) -> PrismError {
    PrismError::Database(DatabaseError::ConnectionError(e.to_string()))
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
        let connection = client
            .get_connection()
            .map_err(convert_to_connection_error)?;

        Ok(RedisConnection {
            connection: Mutex::new(connection),
        })
    }
    // looks like we need lifetime annotations here, because we are returning a MutexGuard:
    // 'a is a generic lifetime and &'a Mutex<T> should make sure, that the MutexGuard is not dropped before the Mutex itself...
    // because rust can not make sure that that's the case, we need to use the 'static lifetime here
    // (but i dont really know why the issue pops up now and not before, i think we were using the same/similar pattern in the other functions)
    fn lock_connection(&self) -> Result<MutexGuard<Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow!(DatabaseError::LockError))
    }
}

impl TreeReader for RedisConnection {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let mut con = self.lock_connection()?;
        let serialized_key = hex::encode(borsh::to_vec(node_key).unwrap());
        let node_data: Option<Vec<u8>> = con.get(format!("node:{}", serialized_key))?;
        match node_data {
            None => return Ok(None),
            Some(data) => {
                let node: Node = borsh::from_slice::<Node>(&data).unwrap();
                Ok(Some(node))
            }
        }
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let mut con = self.lock_connection()?;
        let keys: Vec<String> = con.keys("node:*")?;
        let mut rightmost: Option<(NodeKey, LeafNode)> = None;

        for key in keys {
            let node_data: Vec<u8> = con.get(&key)?;
            let node: Node = borsh::from_slice::<Node>(&node_data)?;
            if let Node::Leaf(leaf) = node {
                // let node_key = NodeKey::from_str(key.strip_prefix("node:").unwrap())?;
                let node_key_bytes = hex::decode(key.strip_prefix("node:").unwrap()).unwrap();
                let node_key = borsh::from_slice::<NodeKey>(node_key_bytes.as_ref()).unwrap();
                if rightmost.is_none() || leaf.key_hash() > rightmost.as_ref().unwrap().1.key_hash()
                {
                    rightmost.replace((node_key, leaf));
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
        let versions: Vec<(Version, OwnedValue)> = con.zrangebyscore_withscores(
            format!("value_history:{:?}", key_hash),
            0,
            max_version as f64,
        )?;
        Ok(versions.last().map(|(_, value)| value.clone()))
    }
}

impl TreeWriter for RedisConnection {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let mut con = self.lock_connection()?;
        let mut pipe = redis::pipe();

        for (node_key, node) in node_batch.nodes() {
            let node_data = borsh::to_vec(node)?;
            pipe.set(format!("node:{:?}", node_key), node_data);
        }

        for ((version, key_hash), value) in node_batch.values() {
            if let Some(v) = value {
                pipe.zadd(format!("value_history:{:?}", key_hash), v, *version as f64);
            } else {
                pipe.zadd(
                    format!("value_history:{:?}", key_hash),
                    Vec::<u8>::new(),
                    *version as f64,
                );
            }
        }

        pipe.execute(&mut con);
        Ok(())
    }
}

impl Database for RedisConnection {
    fn get_hashchain(&self, key: &str) -> Result<Hashchain> {
        let mut con = self.lock_connection()?;
        let value: String = con
            .get(format!("main:{}", key))
            .map_err(|_| DatabaseError::NotFoundError(format!("hashchain key {}", key)))?;

        serde_json::from_str(&value)
            .map_err(|e| anyhow!(GeneralError::ParsingError(format!("hashchain: {}", e))))
    }

    fn get_commitment(&self, epoch: &u64) -> Result<String> {
        let mut con = self.lock_connection()?;
        let value = con
            .get::<&str, String>(&format!("commitments:epoch_{}", epoch))
            .map_err(|_| {
                DatabaseError::NotFoundError(format!("commitment from epoch_{}", epoch))
            })?;
        Ok(value.trim_matches('"').to_string())
    }

    fn get_epoch(&self) -> Result<u64> {
        let mut con = self.lock_connection()?;
        con.get("app_state:epoch")
            .map_err(|_| anyhow!(DatabaseError::NotFoundError("current epoch".to_string())))
    }

    fn set_epoch(&self, epoch: &u64) -> Result<()> {
        let mut con = self.lock_connection()?;
        con.set::<&str, &u64, ()>("app_state:epoch", epoch)
            .map_err(|_| anyhow!(DatabaseError::WriteError(format!("epoch: {}", epoch))))
    }

    fn update_hashchain(
        &self,
        incoming_operation: &Operation,
        value: &[HashchainEntry],
    ) -> Result<()> {
        let mut con = self.lock_connection()?;
        let value = serde_json::to_string(&value).map_err(|_| {
            PrismError::General(GeneralError::ParsingError(
                "hashchain to string".to_string(),
            ))
        })?;
        let id = incoming_operation.id();
        con.set::<&str, String, ()>(&format!("main:{}", id), value)
            .map_err(|_| {
                anyhow!(DatabaseError::WriteError(format!(
                    "hashchain update for key: {}",
                    id
                )))
            })
    }

    fn set_commitment(&self, epoch: &u64, commitment: &Digest) -> Result<()> {
        let mut con = self.lock_connection()?;
        con.set::<&String, &String, ()>(
            &format!("commitments:epoch_{}", epoch),
            &commitment.to_string(),
        )
        .map_err(|_| {
            anyhow!(DatabaseError::WriteError(format!(
                "commitment for epoch: {}",
                epoch
            )))
        })
    }

    #[cfg(test)]
    fn flush_database(&self) -> Result<()> {
        let mut conn = self.lock_connection()?;
        redis::cmd("FLUSHALL")
            .query::<()>(&mut conn)
            .map_err(|_| anyhow!(DatabaseError::DeleteError("all entries".to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Database;
    use prism_common::{operation::Operation, tree::hash};
    use serde::{Deserialize, Serialize};
    use serial_test::serial;

    // Helper functions

    // set up redis connection and flush database before each test
    fn setup() -> RedisConnection {
        let redis_connection = RedisConnection::new(&RedisConfig::default()).unwrap();
        redis_connection.flush_database().unwrap();
        redis_connection
    }

    // flush database after each test
    fn teardown(redis_connections: &RedisConnection) {
        redis_connections.flush_database().unwrap();
    }

    fn create_mock_chain_entry() -> HashchainEntry {
        HashchainEntry {
            hash: hash(b"test_hash"),
            previous_hash: hash(b"test_previous_hash"),
            operation: Operation::Add {
                id: "test_id".to_string(),
                value: "test_value".to_string(),
            },
        }
    }

    fn create_add_operation_with_test_value(id: &str) -> Operation {
        Operation::Add {
            id: id.to_string(),
            value: "test_value".to_string(),
        }
    }

    #[test]
    #[serial]
    fn test_get_hashchain() {
        let redis_connections = setup();

        let incoming_operation = create_add_operation_with_test_value("main:test_key");
        let chain_entry = create_mock_chain_entry();

        redis_connections
            .update_hashchain(&incoming_operation, &[chain_entry.clone()])
            .unwrap();

        let hashchain = redis_connections
            .get_hashchain(&incoming_operation.id())
            .unwrap();

        let first = hashchain.get(0);

        assert_eq!(first.hash, chain_entry.hash);
        assert_eq!(first.previous_hash, chain_entry.previous_hash);
        assert_eq!(first.operation, chain_entry.operation);

        teardown(&redis_connections);
    }

    #[test]
    #[serial]
    fn test_try_getting_hashchain_for_missing_key() {
        let redis_connections = setup();

        let incoming_operation = create_add_operation_with_test_value("main:test_key");
        let chain_entry = create_mock_chain_entry();

        redis_connections
            .update_hashchain(&incoming_operation, &[chain_entry.clone()])
            .unwrap();

        let hashchain = redis_connections.get_hashchain("main:missing_test_key");
        println!("{:?}", hashchain);
        assert!(hashchain.is_err());

        teardown(&redis_connections);
    }

    #[test]
    #[serial]
    fn test_try_getting_wrong_formatted_hashchain_value() {
        let redis_connection = setup();

        let mut con = redis_connection.lock_connection().unwrap();

        #[derive(Serialize, Deserialize, Clone)]
        struct InvalidChainEntry {
            pub hash_val: String, // instead of just "hash"
            pub previous_hash: String,
            pub operation: Operation,
        }

        let wrong_chain_entry = InvalidChainEntry {
            hash_val: "wrong".to_string(),
            previous_hash: "formatted".to_string(),
            operation: Operation::Add {
                id: "test".to_string(),
                value: "entry".to_string(),
            },
        };

        let value = serde_json::to_string(&vec![wrong_chain_entry.clone()]).unwrap();

        con.set::<&String, String, String>(
            &"main:key_to_wrong_formatted_chain_entry".to_string(),
            value,
        )
        .unwrap();

        drop(con); // drop the lock on the connection bc get_hashchain also needs a lock on the connection

        let hashchain = redis_connection.get_hashchain("main:key_to_wrong_formatted_chain_entry");

        assert!(hashchain.is_err());

        teardown(&redis_connection);
    }

    #[test]
    #[serial]
    /*
        TODO: In the test writing, it is noticeable that things may either not have been named correctly here, or need to be reconsidered. The update_hashchain function receives an IncomingEntry and a Vec<ChainEntry> as parameters.
        The Vec<ChainEntry> is the current state of the hashchain, the IncomingEntry is the new entry to be added. is to be added. Now, in hindsight, I would have expected that within the function the new hashchain would be created,
        or else just a value to a key-value pair is created. But neither is the case, instead there are two more update() functions outside of RedisConnections, which then creates the new hashchain is created. This needs to be discussed again with @distractedm1nd :)
        What should happen at the database level? Should the new hashchain be created? Or should only a new value be added to a key-value pair?
    */
    fn test_update_hashchain() {
        let redis_connections = setup();

        let incoming_operation = Operation::Add {
            id: "test_key".to_string(),
            value: "test_value".to_string(),
        };

        let chain_entries: Vec<HashchainEntry> = vec![create_mock_chain_entry()];

        match redis_connections.update_hashchain(&incoming_operation, &chain_entries) {
            Ok(_) => (),
            Err(e) => panic!("Failed to update hashchain: {}", e),
        }

        let hashchain = redis_connections
            .get_hashchain(&incoming_operation.id())
            .unwrap();
        assert_eq!(hashchain.get(0).hash, hash(b"test_hash"));
        assert_eq!(hashchain.len(), 1);

        teardown(&redis_connections);
    }
}
