use indexed_merkle_tree::{node::Node, sha256_mod, tree::Proof};
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
    error::{DatabaseError, DeimosError, DeimosResult, GeneralError},
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

#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingEntry {
    pub id: String,
    pub operation: Operation,
    pub value: String,
}

pub struct RedisConnections {
    pub main_dict: Mutex<Connection>,    // clear text key with hashchain
    pub derived_dict: Mutex<Connection>, // hashed key with last hashchain entry hash
    pub input_order: Mutex<Connection>,  // input order of the hashchain keys
    pub app_state: Mutex<Connection>,    // app state (just epoch counter for now)
    pub merkle_proofs: Mutex<Connection>, // merkle proofs (in the form: epoch_{epochnumber}_{commitment})
    pub commitments: Mutex<Connection>,   // epoch commitments
}

#[automock]
pub trait Database: Send + Sync {
    fn get_keys(&self) -> DeimosResult<Vec<String>>;
    fn get_derived_keys(&self) -> DeimosResult<Vec<String>>;
    fn get_hashchain(&self, key: &str) -> DeimosResult<Vec<ChainEntry>>;
    fn get_derived_value(&self, key: &str) -> DeimosResult<String>;
    fn get_derived_keys_in_order(&self) -> DeimosResult<Vec<String>>;
    fn get_commitment(&self, epoch: &u64) -> DeimosResult<String>;
    fn get_proof(&self, id: &str) -> DeimosResult<String>;
    fn get_proofs_in_epoch(&self, epoch: &u64) -> DeimosResult<Vec<Proof>>;
    fn get_epoch(&self) -> DeimosResult<u64>;
    fn get_epoch_operation(&self) -> DeimosResult<u64>;
    fn set_epoch(&self, epoch: &u64) -> DeimosResult<()>;
    fn reset_epoch_operation_counter(&self) -> DeimosResult<()>;
    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &[ChainEntry],
    ) -> DeimosResult<()>;
    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> DeimosResult<()>;
    fn get_epochs(&self) -> DeimosResult<Vec<u64>>;
    fn increment_epoch_operation(&self) -> DeimosResult<u64>;
    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &Hash,
        proofs: &str,
    ) -> DeimosResult<()>;
    fn add_commitment(&self, epoch: &u64, commitment: &Hash) -> DeimosResult<()>;
    fn initialize_derived_dict(&self) -> DeimosResult<()>;
    fn flush_database(&self) -> DeimosResult<()>;
}

fn convert_to_connection_error(e: redis::RedisError) -> DeimosError {
    DeimosError::Database(DatabaseError::ConnectionError(e.to_string()))
}

impl RedisConnections {
    pub fn new(cfg: &RedisConfig) -> DeimosResult<RedisConnections> {
        let connection_string = cfg.connection_string.clone();
        let try_client =
            Client::open(connection_string.clone()).map_err(convert_to_connection_error)?;
        let try_connection = try_client.get_connection();

        if try_connection.is_err() {
            debug!("starting redis-server...");

            let _child = Command::new("redis-server").spawn().map_err(|e| {
                DeimosError::Database(DatabaseError::InitializationError(e.to_string()))
            })?;

            // TODO: fix this hack
            sleep(Duration::from_secs(5));
            debug!("redis-server started");
        }

        let client =
            Client::open(connection_string.clone()).map_err(convert_to_connection_error)?;
        let derived_client =
            Client::open(connection_string.clone() + "1").map_err(convert_to_connection_error)?;
        let input_order =
            Client::open(connection_string.clone() + "2").map_err(convert_to_connection_error)?;
        let app_state =
            Client::open(connection_string.clone() + "3").map_err(convert_to_connection_error)?;
        let merkle_proofs =
            Client::open(connection_string.clone() + "4").map_err(convert_to_connection_error)?;
        let commitments =
            Client::open(connection_string.clone() + "5").map_err(convert_to_connection_error)?;

        Ok(RedisConnections {
            main_dict: Mutex::new(
                client
                    .get_connection()
                    .map_err(convert_to_connection_error)?,
            ),
            derived_dict: Mutex::new(
                derived_client
                    .get_connection()
                    .map_err(convert_to_connection_error)?,
            ),
            input_order: Mutex::new(
                input_order
                    .get_connection()
                    .map_err(convert_to_connection_error)?,
            ),
            app_state: Mutex::new(
                app_state
                    .get_connection()
                    .map_err(convert_to_connection_error)?,
            ),
            merkle_proofs: Mutex::new(
                merkle_proofs
                    .get_connection()
                    .map_err(convert_to_connection_error)?,
            ),
            commitments: Mutex::new(
                commitments
                    .get_connection()
                    .map_err(convert_to_connection_error)?,
            ),
        })
    }
    // looks like we need lifetime annotations here, because we are returning a MutexGuard:
    // 'a is a generic lifetime and &'a Mutex<T> should make sure, that the MutexGuard is not dropped before the Mutex itself...
    // because rust can not make sure that that's the case, we need to use the 'static lifetime here
    // (but i dont really know why the issue pops up now and not before, i think we were using the same/similar pattern in the other functions)
    fn lock_connection<'a, T>(&self, mutex: &'a Mutex<T>) -> DeimosResult<MutexGuard<'a, T>> {
        mutex
            .lock()
            .map_err(|_| DeimosError::Database(DatabaseError::LockError))
    }
}

impl Database for RedisConnections {
    fn get_keys(&self) -> DeimosResult<Vec<String>> {
        let mut con = self.lock_connection(&self.main_dict)?;
        let keys: Vec<String> = con
            .keys("*")
            .map_err(|_| DeimosError::Database(DatabaseError::KeysError("main".to_string())))?;
        Ok(keys)
    }

    fn get_derived_keys(&self) -> DeimosResult<Vec<String>> {
        let mut con = self.lock_connection(&self.derived_dict)?;
        let keys: Vec<String> = con
            .keys("*")
            .map_err(|_| DeimosError::Database(DatabaseError::KeysError("derived".to_string())))?;
        Ok(keys)
    }

    fn get_hashchain(&self, key: &str) -> DeimosResult<Vec<ChainEntry>> {
        let mut con = self.lock_connection(&self.main_dict)?;
        let value: String = con.get(key).map_err(|_| {
            DeimosError::Database(DatabaseError::NotFoundError(format!("key: {}", key)))
        })?;

        serde_json::from_str(&value).map_err(|e| {
            DeimosError::General(GeneralError::ParsingError(format!("hashchain: {}", e)))
        })
    }

    fn get_derived_value(&self, key: &str) -> DeimosResult<String> {
        let mut con = self.lock_connection(&self.derived_dict)?;
        con.get(key).map_err(|_| {
            DeimosError::Database(DatabaseError::NotFoundError(format!("key: {}", key)))
        })
    }

    // TODO: noticed a strange behavior with the get_derived_keys() function, it returns the values in seemingly random order. Need to investigate more
    // Questionable if it is not simply enough to return the values using the input_order table. This needs to be discussed again with @distractedm1nd :) Then the above function wouldn't be necessary anymore.
    // Does the order of the keys matter?
    fn get_derived_keys_in_order(&self) -> DeimosResult<Vec<String>> {
        let mut input_con = self.lock_connection(&self.input_order)?;
        input_con
            .lrange("input_order", 0, -1)
            .map_err(|_| DeimosError::Database(DatabaseError::GetInputOrderError))
    }

    fn get_commitment(&self, epoch: &u64) -> DeimosResult<String> {
        let mut con = self.lock_connection(&self.commitments)?;
        let value = con
            .get::<&str, String>(&format!("epoch_{}", epoch))
            .map_err(|_| {
                DeimosError::Database(DatabaseError::NotFoundError(format!(
                    "commitment from epoch_{}",
                    epoch
                )))
            })?;
        Ok(value.trim_matches('"').to_string())
    }

    fn get_proof(&self, id: &str) -> DeimosResult<String> {
        let mut con = self.lock_connection(&self.merkle_proofs)?;
        con.get(id).map_err(|_| {
            DeimosError::Database(DatabaseError::NotFoundError(format!(
                "Proof with id: {}",
                id
            )))
        })
    }

    fn get_proofs_in_epoch(&self, epoch: &u64) -> DeimosResult<Vec<Proof>> {
        let mut con = self.lock_connection(&self.merkle_proofs)?;
        let mut epoch_proofs: Vec<String> = con
            .keys::<&String, Vec<String>>(&format!("epoch_{}*", epoch))
            .map_err(|_| {
                DeimosError::Database(DatabaseError::NotFoundError(format!("epoch: {}", epoch)))
            })?;

        epoch_proofs.sort_by(|a, b| {
            let a_parts: Vec<&str> = a.split('_').collect();
            let b_parts: Vec<&str> = b.split('_').collect();
            let a_number: u64 = a_parts[2].parse().unwrap_or(0);
            let b_number: u64 = b_parts[2].parse().unwrap_or(0);
            a_number.cmp(&b_number)
        });

        Ok(epoch_proofs
            .iter()
            .filter_map(|proof| {
                con.get::<&str, String>(proof)
                    .ok()
                    .and_then(|proof_str| parse_json_to_proof(&proof_str).ok())
            })
            .collect())
    }

    fn get_epoch(&self) -> DeimosResult<u64> {
        let mut con = self.lock_connection(&self.app_state)?;
        con.get("epoch").map_err(|_| {
            DeimosError::Database(DatabaseError::NotFoundError("current epoch".to_string()))
        })
    }

    fn get_epoch_operation(&self) -> DeimosResult<u64> {
        let mut con = self.lock_connection(&self.app_state)?;
        con.get("epoch_operation").map_err(|_| {
            DeimosError::Database(DatabaseError::NotFoundError("epoch operation".to_string()))
        })
    }

    fn set_epoch(&self, epoch: &u64) -> DeimosResult<()> {
        let mut con = self.lock_connection(&self.app_state)?;
        con.set::<&str, &u64, ()>("epoch", epoch).map_err(|_| {
            DeimosError::Database(DatabaseError::WriteError(format!("epoch: {}", epoch)))
        })
    }

    fn reset_epoch_operation_counter(&self) -> DeimosResult<()> {
        let mut con = self.lock_connection(&self.app_state)?;
        con.set::<&str, &u64, ()>("epoch_operation", &0)
            .map_err(|_| {
                DeimosError::Database(DatabaseError::WriteError("epoch_operation->0".to_string()))
            })
    }

    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &[ChainEntry],
    ) -> DeimosResult<()> {
        let mut con = self.lock_connection(&self.main_dict)?;
        let value = serde_json::to_string(&value).map_err(|_| {
            DeimosError::General(GeneralError::ParsingError(
                "hashchain to string".to_string(),
            ))
        })?;
        con.set::<&String, String, ()>(&incoming_entry.id, value)
            .map_err(|_| {
                DeimosError::Database(DatabaseError::WriteError(format!(
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
    ) -> DeimosResult<()> {
        let mut con = self.lock_connection(&self.derived_dict)?;
        let mut input_con = self.lock_connection(&self.input_order)?;
        let hashed_key = sha256_mod(&incoming_entry.id.as_bytes());
        // TODO: @distractedm1nd thought about saving the raw bytes of the hash for space effiency but it seems like redis needs at least the key to be a string and for consistency we should probably save then both value as a string wdyt?
        // to_string() Method works here because i've implemented the Display trait for Hash in indexed_merkle_tree crate
        con.set::<&String, &String, String>(&hashed_key.to_string(), &value.hash.to_string())
            .map_err(|_| {
                DeimosError::Database(DatabaseError::WriteError(format!(
                    "derived dict update for key: {}",
                    hashed_key
                )))
            })?;

        if new {
            input_con
                .rpush::<&'static str, &String, u32>("input_order", &hashed_key.to_string())
                .map_err(|_| {
                    DeimosError::Database(DatabaseError::WriteError(format!(
                        "input order update for key: {}",
                        hashed_key
                    )))
                })?;
        }
        Ok(())
    }

    fn get_epochs(&self) -> DeimosResult<Vec<u64>> {
        let mut con = self.lock_connection(&self.commitments)?;
        con.keys::<&str, Vec<String>>("*")
            .map_err(|_| {
                DeimosError::Database(DatabaseError::NotFoundError("Commitments".to_string()))
            })?
            .into_iter()
            .map(|epoch| {
                epoch.replace("epoch_", "").parse::<u64>().map_err(|_| {
                    DeimosError::General(GeneralError::ParsingError(
                        "failed to parse epoch".to_string(),
                    ))
                })
            })
            .collect()
    }

    fn increment_epoch_operation(&self) -> DeimosResult<u64> {
        let mut con = self.lock_connection(&self.app_state)?;
        con.incr::<&'static str, u64, u64>("epoch_operation", 1)
            .map_err(|_| {
                DeimosError::Database(DatabaseError::WriteError("incremented epoch".to_string()))
            })
    }

    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &Hash,
        proofs: &str,
    ) -> DeimosResult<()> {
        let mut con = self.lock_connection(&self.merkle_proofs)?;
        let formatted_epoch = format!("epoch_{}_{}_{}", epoch, epoch_operation, commitment);
        con.set::<&String, &String, ()>(&formatted_epoch, &proofs.to_string())
            .map_err(|_| {
                DeimosError::Database(DatabaseError::WriteError(format!(
                    "merkle proof for epoch: {}",
                    formatted_epoch
                )))
            })
    }

    fn add_commitment(&self, epoch: &u64, commitment: &Hash) -> DeimosResult<()> {
        let mut con = self.lock_connection(&self.commitments)?;
        con.set::<&String, &String, ()>(&format!("epoch_{}", epoch), &commitment.to_string())
            .map_err(|_| {
                DeimosError::Database(DatabaseError::WriteError(format!(
                    "commitment for epoch: {}",
                    epoch
                )))
            })
    }

    fn initialize_derived_dict(&self) -> DeimosResult<()> {
        let mut con = self.lock_connection(&self.derived_dict)?;
        let mut input_con = self.lock_connection(&self.input_order)?;

        let empty_hash = Node::HEAD.to_string();

        con.set::<&String, &String, String>(&empty_hash, &empty_hash)
            .map_err(|_| {
                DeimosError::Database(DatabaseError::WriteError(
                    "empty hash as first entry in the derived dictionary".to_string(),
                ))
            })?;

        input_con
            .rpush::<String, String, u32>("input_order".to_string(), empty_hash.clone())
            .map_err(|_| {
                DeimosError::Database(DatabaseError::WriteError(
                    "empty hash as first entry in input order".to_string(),
                ))
            })?;

        Ok(())
    }

    fn flush_database(&self) -> DeimosResult<()> {
        let connections = [
            (&self.main_dict, "main dict"),
            (&self.derived_dict, "derived dict"),
            (&self.input_order, "input order"),
            (&self.app_state, "app state"),
            (&self.merkle_proofs, "merkle proofs"),
            (&self.commitments, "commitments"),
        ];

        for (mutex, name) in connections.iter() {
            let mut conn = self.lock_connection(mutex)?;
            redis::cmd("FLUSHALL").query::<()>(&mut conn).map_err(|_| {
                DeimosError::Database(DatabaseError::DeleteError(format!(
                    "all entries in {}",
                    name
                )))
            })?;
        }
        Ok(())
    }
}

#[cfg(not(feature = "ci"))]
#[cfg(test)]
mod tests {
    use indexed_merkle_tree::sha256_mod;

    use super::*;

    // Helper functions

    // set up redis connection and flush database before each test
    fn setup() -> RedisConnections {
        let redis_connections = RedisConnections::new(&RedisConfig::default()).unwrap();
        redis_connections.flush_database().unwrap();
        redis_connections
    }

    // flush database after each test
    fn teardown(redis_connections: &RedisConnections) {
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

        let incoming_entry1 = create_incoming_entry_with_test_value("test_key1");
        let incoming_entry2 = create_incoming_entry_with_test_value("test_key2");
        let incoming_entry3 = create_incoming_entry_with_test_value("test_key3");

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

        let incoming_entry1 = create_incoming_entry_with_test_value("test_key1");
        let incoming_entry2 = create_incoming_entry_with_test_value("test_key2");
        let incoming_entry3 = create_incoming_entry_with_test_value("test_key3");

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
            sha256_mod(b"test_key1").to_string(),
            sha256_mod(b"test_key2").to_string(),
            sha256_mod(b"test_key3").to_string(),
        ];
        let returned_keys: Vec<String> = keys;

        assert_eq!(expected_keys, returned_keys);

        teardown(&redis_connections);
    }

    // TESTS FOR fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, &str>

    #[test]
    fn test_get_hashchain() {
        let redis_connections = setup();

        let incoming_entry = create_incoming_entry_with_test_value("test_key");
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

        let incoming_entry = create_incoming_entry_with_test_value("test_key");
        let chain_entry = create_mock_chain_entry();

        redis_connections
            .update_hashchain(&incoming_entry, &[chain_entry.clone()])
            .unwrap();

        let hashchain = redis_connections.get_hashchain("missing_test_key");
        println!("{:?}", hashchain);
        assert!(hashchain.is_err());

        teardown(&redis_connections);
    }

    #[test]
    fn test_try_getting_wrong_formatted_hashchain_value() {
        let redis_connections = setup();

        let mut con = redis_connections.main_dict.lock().unwrap();

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
            &"key_to_wrong_formatted_chain_entry".to_string(),
            value,
        )
        .unwrap();

        drop(con); // drop the lock on the connection bc get_hashchain also needs a lock on the connection

        let hashchain = redis_connections.get_hashchain("key_to_wrong_formatted_chain_entry");

        assert!(hashchain.is_err());

        teardown(&redis_connections);
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
