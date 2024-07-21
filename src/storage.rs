use indexed_merkle_tree::{node::Node, sha256_mod, tree::Proof, Hash};
use mockall::{predicate::*, *};
use redis::{Client, Commands, Connection};
use serde::{Deserialize, Serialize};
use std::{
    self,
    fmt::Display,
    process::Command,
    sync::{Mutex, MutexGuard},
    thread::sleep,
    time::Duration,
};

use crate::{
    cfg::RedisConfig,
    error::{DatabaseError, PrismError, PrismResult, GeneralError},
    utils::parse_json_to_proof,
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Operation {
    Add,
    Revoke,
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Operation::Add => write!(f, "Add"),
            Operation::Revoke => write!(f, "Revoke"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ChainEntry {
    pub hash: Hash,
    pub previous_hash: Hash,
    pub operation: Operation,
    pub value: Hash,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Entry {
    pub id: String,
    pub value: Vec<ChainEntry>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DerivedEntry {
    pub id: String,
    pub value: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IncomingEntry {
    pub id: String,
    pub operation: Operation,
    pub value: String,
}

// there are different key prefixes for the different tables in the database
// main:key => clear text key with hashchain
// derived:key => hashed key with last hashchain entry hash
// input_order => input order of the hashchain keys
// app_state:key => app state (just epoch counter for now)
// merkle_proofs:key => merkle proofs (in the form: epoch_{epochnumber}_{commitment})
// commitments:key => epoch commitments
pub struct RedisConnection {
    connection: Mutex<Connection>,
}

#[automock]
pub trait Database: Send + Sync {
    fn get_keys(&self) -> PrismResult<Vec<String>>;
    fn get_derived_keys(&self) -> PrismResult<Vec<String>>;
    fn get_hashchain(&self, key: &str) -> PrismResult<Vec<ChainEntry>>;
    fn get_derived_value(&self, key: &str) -> PrismResult<String>;
    fn get_derived_keys_in_order(&self) -> PrismResult<Vec<String>>;
    fn get_commitment(&self, epoch: &u64) -> PrismResult<String>;
    fn get_proof(&self, id: &str) -> PrismResult<String>;
    fn get_proofs_in_epoch(&self, epoch: &u64) -> PrismResult<Vec<Proof>>;
    fn get_epoch(&self) -> PrismResult<u64>;
    fn set_epoch(&self, epoch: &u64) -> PrismResult<()>;
    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &[ChainEntry],
    ) -> PrismResult<()>;
    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> PrismResult<()>;
    fn get_epochs(&self) -> PrismResult<Vec<u64>>;
    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &Hash,
        proofs: &str,
    ) -> PrismResult<()>;
    fn add_commitment(&self, epoch: &u64, commitment: &Hash) -> PrismResult<()>;
    fn initialize_derived_dict(&self) -> PrismResult<()>;
    fn flush_database(&self) -> PrismResult<()>;
}

fn convert_to_connection_error(e: redis::RedisError) -> PrismError {
    PrismError::Database(DatabaseError::ConnectionError(e.to_string()))
}

impl RedisConnection {
    pub fn new(cfg: &RedisConfig) -> PrismResult<RedisConnection> {
        let connection_string = cfg.connection_string.clone();
        let try_client =
            Client::open(connection_string.clone()).map_err(convert_to_connection_error)?;
        let try_connection = try_client.get_connection();

        if try_connection.is_err() {
            debug!("starting redis-server...");

            let _child = Command::new("redis-server").spawn().map_err(|e| {
                PrismError::Database(DatabaseError::InitializationError(e.to_string()))
            })?;

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
    fn lock_connection(&self) -> PrismResult<MutexGuard<Connection>> {
        self.connection
            .lock()
            .map_err(|_| PrismError::Database(DatabaseError::LockError))
    }
}

impl Database for RedisConnection {
    fn get_keys(&self) -> PrismResult<Vec<String>> {
        let mut con = self.lock_connection()?;
        let keys: Vec<String> = con
            .keys("main:*")
            .map_err(|_| PrismError::Database(DatabaseError::KeysError("main".to_string())))?;
        Ok(keys.into_iter().map(|k| k.replace("main:", "")).collect())
    }

    fn get_derived_keys(&self) -> PrismResult<Vec<String>> {
        let mut con = self.lock_connection()?;
        let keys: Vec<String> = con
            .keys("derived:*")
            .map_err(|_| PrismError::Database(DatabaseError::KeysError("derived".to_string())))?;
        Ok(keys
            .into_iter()
            .map(|k| k.replace("derived:", ""))
            .collect())
    }

    fn get_hashchain(&self, key: &str) -> PrismResult<Vec<ChainEntry>> {
        let mut con = self.lock_connection()?;
        let value: String = con.get(format!("main:{}", key)).map_err(|_| {
            PrismError::Database(DatabaseError::NotFoundError(format!(
                "hashchain key {}",
                key
            )))
        })?;

        serde_json::from_str(&value).map_err(|e| {
            PrismError::General(GeneralError::ParsingError(format!("hashchain: {}", e)))
        })
    }

    fn get_derived_value(&self, key: &str) -> PrismResult<String> {
        let mut con = self.lock_connection()?;
        con.get::<String, String>(format!("derived:{}", key))
            .map_err(|e| {
                PrismError::Database(DatabaseError::NotFoundError(format!(
                    "derived key {} with err {}: ",
                    key, e
                )))
            })
    }

    // TODO: noticed a strange behavior with the get_derived_keys() function, it returns the values in seemingly random order. Need to investigate more
    // Questionable if it is not simply enough to return the values using the input_order table. This needs to be discussed again with @distractedm1nd :) Then the above function wouldn't be necessary anymore.
    // Does the order of the keys matter?
    fn get_derived_keys_in_order(&self) -> PrismResult<Vec<String>> {
        let mut con = self.lock_connection()?;
        con.lrange("input_order", 0, -1)
            .map_err(|_| PrismError::Database(DatabaseError::GetInputOrderError))
    }

    fn get_commitment(&self, epoch: &u64) -> PrismResult<String> {
        let mut con = self.lock_connection()?;
        let value = con
            .get::<&str, String>(&format!("commitments:epoch_{}", epoch))
            .map_err(|_| {
                PrismError::Database(DatabaseError::NotFoundError(format!(
                    "commitment from epoch_{}",
                    epoch
                )))
            })?;
        Ok(value.trim_matches('"').to_string())
    }

    fn get_proof(&self, id: &str) -> PrismResult<String> {
        let mut con = self.lock_connection()?;
        con.get(format!("merkle_proofs:{}", id)).map_err(|_| {
            PrismError::Database(DatabaseError::NotFoundError(format!(
                "Proof with id: {}",
                id
            )))
        })
    }

    fn get_proofs_in_epoch(&self, epoch: &u64) -> PrismResult<Vec<Proof>> {
        let mut con = self.lock_connection()?;
        let mut epoch_proofs: Vec<String> = con
            .keys::<&String, Vec<String>>(&format!("merkle_proofs:epoch_{}*", epoch))
            .map_err(|_| {
                PrismError::Database(DatabaseError::NotFoundError(format!("epoch: {}", epoch)))
            })?;

        epoch_proofs.sort_by(|a, b| {
            let a_parts: Vec<&str> = a.split('_').collect();
            let b_parts: Vec<&str> = b.split('_').collect();
            let a_number: u64 = a_parts[2].parse().unwrap_or(0);
            let b_number: u64 = b_parts[2].parse().unwrap_or(0);
            a_number.cmp(&b_number)
        });

        Ok(epoch_proofs
            .into_iter()
            .filter_map(|proof| {
                con.get::<&str, String>(&proof)
                    .ok()
                    .and_then(|proof_str| parse_json_to_proof(&proof_str).ok())
            })
            .collect())
    }

    fn get_epoch(&self) -> PrismResult<u64> {
        let mut con = self.lock_connection()?;
        con.get("app_state:epoch").map_err(|_| {
            PrismError::Database(DatabaseError::NotFoundError("current epoch".to_string()))
        })
    }

    fn set_epoch(&self, epoch: &u64) -> PrismResult<()> {
        let mut con = self.lock_connection()?;
        con.set::<&str, &u64, ()>("app_state:epoch", epoch)
            .map_err(|_| {
                PrismError::Database(DatabaseError::WriteError(format!("epoch: {}", epoch)))
            })
    }

    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &[ChainEntry],
    ) -> PrismResult<()> {
        let mut con = self.lock_connection()?;
        let value = serde_json::to_string(&value).map_err(|_| {
            PrismError::General(GeneralError::ParsingError(
                "hashchain to string".to_string(),
            ))
        })?;
        con.set::<&str, String, ()>(&format!("main:{}", incoming_entry.id), value)
            .map_err(|_| {
                PrismError::Database(DatabaseError::WriteError(format!(
                    "hashchain update for key: {}",
                    incoming_entry.id
                )))
            })
    }

    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> PrismResult<()> {
        let mut con = self.lock_connection()?;
        let hashed_key = sha256_mod(incoming_entry.id.as_bytes());
        let stored_value = hex::encode(value.hash.as_ref());
        con.set::<&str, String, String>(&format!("derived:{}", hashed_key), stored_value)
            .map_err(|_| {
                PrismError::Database(DatabaseError::WriteError(format!(
                    "derived dict update for key: {}",
                    hashed_key
                )))
            })?;

        if new {
            con.rpush::<&'static str, &String, u32>("input_order", &hashed_key.to_string())
                .map_err(|_| {
                    PrismError::Database(DatabaseError::WriteError(format!(
                        "input order update for key: {}",
                        hashed_key
                    )))
                })?;
        }
        Ok(())
    }

    fn get_epochs(&self) -> PrismResult<Vec<u64>> {
        let mut con = self.lock_connection()?;
        con.keys::<&str, Vec<String>>("commitments:*")
            .map_err(|_| {
                PrismError::Database(DatabaseError::NotFoundError("Commitments".to_string()))
            })?
            .into_iter()
            .map(|epoch| {
                epoch
                    .replace("commitments:epoch_", "")
                    .parse::<u64>()
                    .map_err(|_| {
                        PrismError::General(GeneralError::ParsingError(
                            "failed to parse epoch".to_string(),
                        ))
                    })
            })
            .collect()
    }

    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &Hash,
        proofs: &str,
    ) -> PrismResult<()> {
        let mut con = self.lock_connection()?;
        let formatted_epoch = format!(
            "merkle_proofs:epoch_{}_{}_{}",
            epoch, epoch_operation, commitment
        );
        con.set::<&String, &String, ()>(&formatted_epoch, &proofs.to_string())
            .map_err(|_| {
                PrismError::Database(DatabaseError::WriteError(format!(
                    "merkle proof for epoch: {}",
                    formatted_epoch
                )))
            })
    }

    fn add_commitment(&self, epoch: &u64, commitment: &Hash) -> PrismResult<()> {
        let mut con = self.lock_connection()?;
        con.set::<&String, &String, ()>(
            &format!("commitments:epoch_{}", epoch),
            &commitment.to_string(),
        )
        .map_err(|_| {
            PrismError::Database(DatabaseError::WriteError(format!(
                "commitment for epoch: {}",
                epoch
            )))
        })
    }

    fn initialize_derived_dict(&self) -> PrismResult<()> {
        let mut con = self.lock_connection()?;
        let empty_hash = Node::HEAD.to_string();

        con.set::<&String, &String, String>(&format!("derived:{}", empty_hash), &empty_hash)
            .map_err(|_| {
                PrismError::Database(DatabaseError::WriteError(
                    "empty hash as first entry in the derived dictionary".to_string(),
                ))
            })?;

        con.rpush::<String, String, u32>("input_order".to_string(), empty_hash.clone())
            .map_err(|_| {
                PrismError::Database(DatabaseError::WriteError(
                    "empty hash as first entry in input order".to_string(),
                ))
            })?;

        Ok(())
    }

    fn flush_database(&self) -> PrismResult<()> {
        let mut conn = self.lock_connection()?;
        redis::cmd("FLUSHALL").query::<()>(&mut conn).map_err(|_| {
            PrismError::Database(DatabaseError::DeleteError("all entries".to_string()))
        })
    }
}

#[cfg(not(feature = "ci"))]
#[cfg(test)]
mod tests {
    use indexed_merkle_tree::sha256_mod;

    use super::*;

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

    fn create_mock_chain_entry() -> ChainEntry {
        ChainEntry {
            hash: sha256_mod(b"test_hash"),
            previous_hash: sha256_mod(b"test_previous_hash"),
            operation: Operation::Add,
            value: sha256_mod(b"test_value"),
        }
    }

    fn create_incoming_entry_with_test_value(id: &str) -> IncomingEntry {
        IncomingEntry {
            id: id.to_string(),
            operation: Operation::Add,
            value: "test_value".to_string(),
        }
    }

    // TESTS FOR fn get_keys(&self) -> Vec<String>

    // TODO: In this context it occurs to me now that we should probably rename the get_keys() function to get_hashchain_keys() or something, because it actually only returns the keys of the hashchain.
    // Better yet, there's also the get_derived_keys() function, which returns the derived_dict keys. These are simply the hashed keys. So possibly: get_keys() and get_hashed_keys() ?!
    // probably not thaaat important
    // TODO: get_keys() returns the keys in reverse order
    #[test]
    fn test_get_keys() {
        // set up redis connection and flush database
        let redis_connections = setup();

        let incoming_entry1 = create_incoming_entry_with_test_value("main:test_key1");
        let incoming_entry2 = create_incoming_entry_with_test_value("main:test_key2");
        let incoming_entry3 = create_incoming_entry_with_test_value("main:test_key3");

        redis_connections
            .update_hashchain(&incoming_entry1, &[create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry2, &[create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry3, &[create_mock_chain_entry()])
            .unwrap();

        let mut keys = redis_connections.get_keys().unwrap();
        keys.sort();

        let expected_keys: Vec<String> = vec![
            "test_key1".to_string(),
            "test_key2".to_string(),
            "test_key3".to_string(),
        ];
        let returned_keys: Vec<String> = keys;

        assert_eq!(expected_keys, returned_keys);

        teardown(&redis_connections);
    }

    #[test]
    fn test_get_keys_from_empty_dictionary() {
        let redis_connections = setup();

        let keys = redis_connections.get_keys().unwrap();

        let expected_keys: Vec<String> = vec![];
        let returned_keys: Vec<String> = keys;

        assert_eq!(expected_keys, returned_keys);

        teardown(&redis_connections);
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_get_too_much_returned_keys() {
        let redis_connections = setup();

        let incoming_entry1 = create_incoming_entry_with_test_value("test_key_1");
        let incoming_entry2 = create_incoming_entry_with_test_value("test_key_2");
        let incoming_entry3 = create_incoming_entry_with_test_value("test_key_3");

        redis_connections
            .update_hashchain(&incoming_entry1, &[create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry2, &[create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry3, &[create_mock_chain_entry()])
            .unwrap();

        let mut keys = redis_connections.get_keys().unwrap();

        let too_little_keys: Vec<String> = vec!["test_key1".to_string(), "test_key2".to_string()];
        keys.reverse();
        let returned_keys: Vec<String> = keys;

        assert_eq!(too_little_keys, returned_keys);

        teardown(&redis_connections);
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_get_too_little_returned_keys() {
        let redis_connections = setup();

        let incoming_entry1 = create_incoming_entry_with_test_value("test_key_1");
        let incoming_entry2 = create_incoming_entry_with_test_value("test_key_2");
        let incoming_entry3 = create_incoming_entry_with_test_value("test_key_3");

        redis_connections
            .update_hashchain(&incoming_entry1, &[create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry2, &[create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry3, &[create_mock_chain_entry()])
            .unwrap();

        let mut keys = redis_connections.get_keys().unwrap();

        let too_little_keys: Vec<String> = vec![
            "test_key1".to_string(),
            "test_key2".to_string(),
            "test_key3".to_string(),
            "test_key4".to_string(),
        ];
        keys.reverse();
        let returned_keys: Vec<String> = keys;

        assert_eq!(too_little_keys, returned_keys);

        teardown(&redis_connections);
    }

    //    TESTS FOR fn get_derived_keys(&self) -> Vec<String>

    // TODO: shouldn't it be that the update function automatically continues the derived dict?
    // In addition, it should not be possible to write keys exclusively directly into the derived dict, right?
    #[test]
    fn test_get_hashed_keys() {
        let redis_connections = setup();

        let incoming_entry1 = create_incoming_entry_with_test_value("derived:test_key1");
        let incoming_entry2 = create_incoming_entry_with_test_value("derived:test_key2");
        let incoming_entry3 = create_incoming_entry_with_test_value("derived:test_key3");

        redis_connections
            .set_derived_entry(&incoming_entry1, &create_mock_chain_entry(), true)
            .unwrap();
        redis_connections
            .set_derived_entry(&incoming_entry2, &create_mock_chain_entry(), true)
            .unwrap();
        redis_connections
            .set_derived_entry(&incoming_entry3, &create_mock_chain_entry(), true)
            .unwrap();

        let keys = redis_connections.get_derived_keys_in_order().unwrap();

        // check if the returned keys are correct
        let expected_keys: Vec<String> = vec![
            sha256_mod(b"derived:test_key1").to_string(),
            sha256_mod(b"derived:test_key2").to_string(),
            sha256_mod(b"derived:test_key3").to_string(),
        ];
        let returned_keys: Vec<String> = keys;

        assert_eq!(expected_keys, returned_keys);

        teardown(&redis_connections);
    }

    // TESTS FOR fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, &str>

    #[test]
    fn test_get_hashchain() {
        let redis_connections = setup();

        let incoming_entry = create_incoming_entry_with_test_value("main:test_key");
        let chain_entry = create_mock_chain_entry();

        redis_connections
            .update_hashchain(&incoming_entry, &[chain_entry.clone()])
            .unwrap();

        let hashchain = redis_connections.get_hashchain(&incoming_entry.id).unwrap();
        assert_eq!(hashchain[0].hash, chain_entry.hash);
        assert_eq!(hashchain[0].previous_hash, chain_entry.previous_hash);
        assert_eq!(hashchain[0].operation, chain_entry.operation);
        assert_eq!(hashchain[0].value, chain_entry.value);

        teardown(&redis_connections);
    }

    #[test]
    fn test_try_getting_hashchain_for_missing_key() {
        let redis_connections = setup();

        let incoming_entry = create_incoming_entry_with_test_value("main:test_key");
        let chain_entry = create_mock_chain_entry();

        redis_connections
            .update_hashchain(&incoming_entry, &[chain_entry.clone()])
            .unwrap();

        let hashchain = redis_connections.get_hashchain("main:missing_test_key");
        println!("{:?}", hashchain);
        assert!(hashchain.is_err());

        teardown(&redis_connections);
    }

    #[test]
    fn test_try_getting_wrong_formatted_hashchain_value() {
        let redis_connection = setup();

        let mut con = redis_connection.lock_connection().unwrap();

        #[derive(Serialize, Deserialize, Clone)]
        struct WrongFormattedChainEntry {
            pub hash_val: String, // instead of just "hash"
            pub previous_hash: String,
            pub operation: Operation,
            pub value: String,
        }

        let wrong_chain_entry = WrongFormattedChainEntry {
            hash_val: "wrong".to_string(),
            previous_hash: "formatted".to_string(),
            operation: Operation::Add,
            value: "entry".to_string(),
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

    // TESTS FOR fn get_derived_value(&self, key: &String) -> Result<String, &str>

    #[test]
    /*
        TODO: In the test writing, it is noticeable that things may either not have been named correctly here, or need to be reconsidered. The update_hashchain function receives an IncomingEntry and a Vec<ChainEntry> as parameters.
        The Vec<ChainEntry> is the current state of the hashchain, the IncomingEntry is the new entry to be added. is to be added. Now, in hindsight, I would have expected that within the function the new hashchain would be created,
        or else just a value to a key-value pair is created. But neither is the case, instead there are two more update() functions outside of RedisConnections, which then creates the new hashchain is created. This needs to be discussed again with @distractedm1nd :)
        What should happen at the database level? Should the new hashchain be created? Or should only a new value be added to a key-value pair?
    */
    fn test_update_hashchain() {
        let redis_connections = setup();

        let incoming_entry: IncomingEntry = IncomingEntry {
            id: "test_key".to_string(),
            operation: Operation::Add,
            value: "test_value".to_string(),
        };

        let chain_entries: Vec<ChainEntry> = vec![create_mock_chain_entry()];

        match redis_connections.update_hashchain(&incoming_entry, &chain_entries) {
            Ok(_) => (),
            Err(e) => panic!("Failed to update hashchain: {}", e),
        }

        let hashchain = redis_connections.get_hashchain(&incoming_entry.id).unwrap();
        assert_eq!(hashchain[0].hash, sha256_mod(b"test_hash"));
        assert_eq!(hashchain.len(), 1);

        teardown(&redis_connections);
    }
}
