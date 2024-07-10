use indexed_merkle_tree::{node::Node, sha256, tree::Proof};
use mockall::predicate::*;
use redis::{Client, Commands, Connection};
use std::process::Command;
use std::sync::MutexGuard;
use std::thread::sleep;
use std::time::Duration;
use std::{self, sync::Mutex};

use crate::{config::RedisConfig, storage::Database, utils::parse_json_to_proof};

use deimos_types::types::{ChainEntry, IncomingEntry};
use deimos_errors::errors::{DeimosError, GeneralError, DatabaseError};

pub struct RedisConnections {
    pub main_dict: Mutex<Connection>,    // clear text key with hashchain
    pub derived_dict: Mutex<Connection>, // hashed key with last hashchain entry hash
    pub input_order: Mutex<Connection>,  // input order of the hashchain keys
    pub app_state: Mutex<Connection>,    // app state (just epoch counter for now)
    pub merkle_proofs: Mutex<Connection>, // merkle proofs (in the form: epoch_{epochnumber}_{commitment})
    pub commitments: Mutex<Connection>,   // epoch commitments
}

impl RedisConnections {
    pub fn new(cfg: &RedisConfig) -> Result<RedisConnections, Box<dyn std::error::Error>> {
        let try_client = Client::open(cfg.clone().connection_string)?;
        let try_connection = try_client.get_connection();

        if try_connection.is_err() {
            debug!("starting redis-server...");

            let _child = Command::new("redis-server").spawn()?;

            sleep(Duration::from_secs(5));
            debug!("redis-server started");
        }

        let client = Client::open("redis://127.0.0.1/")?;
        let derived_client = Client::open("redis://127.0.0.1/1")?;
        let input_order = Client::open("redis://127.0.0.1/2")?;
        let app_state = Client::open("redis://127.0.0.1/3")?;
        let merkle_proofs = Client::open("redis://127.0.0.1/4")?;
        let commitments = Client::open("redis://127.0.0.1/5")?;

        Ok(RedisConnections {
            main_dict: Mutex::new(client.get_connection()?),
            derived_dict: Mutex::new(derived_client.get_connection()?),
            input_order: Mutex::new(input_order.get_connection()?),
            app_state: Mutex::new(app_state.get_connection()?),
            merkle_proofs: Mutex::new(merkle_proofs.get_connection()?),
            commitments: Mutex::new(commitments.get_connection()?),
        })
    }

    // looks like we need lifetime annotations here, because we are returning a MutexGuard:
    // 'a is a generic lifetime and &'a Mutex<T> should make sure, that the MutexGuard is not dropped before the Mutex itself...
    // because rust can not make sure that that's the case, we need to use the 'static lifetime here
    // (but i dont really know why the issue pops up now and not before, i think we were using the same/similar pattern in the other functions)
    fn lock_connection<'a, T>(
        &self,
        mutex: &'a Mutex<T>,
    ) -> Result<MutexGuard<'a, T>, DatabaseError> {
        mutex.lock().map_err(|_| DatabaseError::LockError)
    }
}

impl Database for RedisConnections {
    fn get_keys(&self) -> Result<Vec<String>, DatabaseError> {
        let mut con = self.lock_connection(&self.main_dict)?;
        let keys: Vec<String> = con
            .keys("*")
            .map_err(|_| DatabaseError::KeysError("main".to_string()))?;
        Ok(keys)
    }

    fn get_derived_keys(&self) -> Result<Vec<String>, DatabaseError> {
        let mut con = self.lock_connection(&self.derived_dict)?;
        let keys: Vec<String> = con
            .keys("*")
            .map_err(|_| DatabaseError::KeysError("derived".to_string()))?;
        Ok(keys)
    }

    fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, DatabaseError> {
        let mut con = self
            .main_dict
            .lock()
            .map_err(|_| DatabaseError::LockError)?;
        let value: String = con
            .get(key)
            .map_err(|_| DatabaseError::NotFoundError(format!("key: {}", key)))?;

        serde_json::from_str(&value)
            .map_err(|e| GeneralError::ParsingError(format!("hashchain: {}", e)).into())
    }

    fn get_derived_value(&self, key: &String) -> Result<String, DatabaseError> {
        let mut con = self.lock_connection(&self.derived_dict)?;
        con.get(key)
            .map_err(|_| DatabaseError::NotFoundError(format!("key: {}", key)))
    }

    // TODO: noticed a strange behavior with the get_derived_keys() function, it returns the values in seemingly random order. Need to investigate more
    // Questionable if it is not simply enough to return the values using the input_order table. This needs to be discussed again with @distractedm1nd :) Then the above function wouldn't be necessary anymore.
    // Does the order of the keys matter?
    fn get_derived_keys_in_order(&self) -> Result<Vec<String>, DatabaseError> {
        let mut input_con = self.lock_connection(&self.input_order)?;

        // The lrange method returns a list of the elements between two indices. 0 and -1 mean the first and last element, i.e. the entire list.
        input_con
            .lrange("input_order", 0, -1)
            .map_err(|_| DatabaseError::GetInputOrderError)
    }

    fn get_commitment(&self, epoch: &u64) -> Result<String, DatabaseError> {
        let mut con = self.lock_connection(&self.commitments)?;
        match con.get::<&str, String>(&format!("epoch_{}", epoch)) {
            Ok(value) => {
                let trimmed_value = value.trim_matches('"').to_string();
                Ok(trimmed_value)
            }
            Err(_) => Err(DatabaseError::NotFoundError(format!(
                "commitment from epoch_{}",
                epoch
            ))),
        }
    }

    fn get_proof(&self, id: &String) -> Result<String, DatabaseError> {
        let mut con = self.lock_connection(&self.merkle_proofs)?;
        con.get(id)
            .map_err(|_| DatabaseError::NotFoundError(format!("Proof with id: {}", id)))
    }

    fn get_proofs_in_epoch(&self, epoch: &u64) -> Result<Vec<Proof>, DatabaseError> {
        let mut con = self.lock_connection(&self.merkle_proofs)?;
        let mut epoch_proofs: Vec<String> = con
            .keys::<&String, Vec<String>>(&format!("epoch_{}*", epoch))
            .map_err(|_| DatabaseError::NotFoundError(format!("epoch: {}", epoch)))?;

        // Sort epoch_proofs by extracting epoch number and number within the epoch
        epoch_proofs.sort_by(|a, b| {
            let a_parts: Vec<&str> = a.split('_').collect();
            let b_parts: Vec<&str> = b.split('_').collect();

            // use second number, for the format: epoch_1_1, epoch_1_2, epoch_1_3 etc. the second number is the number within the epoch
            // TODO: whats the best way to handle this? unwrap_or(0) is probably not ideal
            let a_number: u64 = a_parts[2].parse().unwrap_or(0);
            let b_number: u64 = b_parts[2].parse().unwrap_or(0);

            // Compare first by epoch number, then by number within the epoch
            a_number.cmp(&b_number)
        });

        // Parse the proofs from JSON to ProofVariant
        Ok(epoch_proofs
            .iter()
            .filter_map(|proof| {
                con.get::<&str, String>(proof)
                    .ok()
                    .and_then(|proof_str| parse_json_to_proof(&proof_str).ok())
            })
            .collect())
    }

    fn get_epoch(&self) -> Result<u64, DatabaseError> {
        let mut con = self.lock_connection(&self.app_state)?;
        let epoch: u64 = con
            .get("epoch")
            .map_err(|_| DatabaseError::NotFoundError(format!("current epoch")))?;
        Ok(epoch)
    }

    fn get_epoch_operation(&self) -> Result<u64, DatabaseError> {
        let mut con = self.lock_connection(&self.app_state)?;
        con.get("epoch_operation")
            .map_err(|_| DatabaseError::NotFoundError(format!("epoch operation")))
    }

    fn set_epoch(&self, epoch: &u64) -> Result<(), DatabaseError> {
        let mut con = self.lock_connection(&self.app_state)?;
        con.set::<&str, &u64, String>("epoch", epoch)
            .map_err(|_| DatabaseError::WriteError(format!("epoch: {}", epoch)))?;
        Ok(())
    }

    fn reset_epoch_operation_counter(&self) -> Result<(), DatabaseError> {
        let mut con = self.lock_connection(&self.app_state)?;
        con.set::<&str, &u64, String>("epoch_operation", &0)
            .map_err(|_| DatabaseError::WriteError(format!("epoch_operation->0")))?;
        Ok(())
    }

    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &Vec<ChainEntry>,
    ) -> Result<(), DeimosError> {
        let mut con = self
            .main_dict
            .lock()
            .map_err(|_| DeimosError::Database(DatabaseError::LockError))?;
        let value = serde_json::to_string(&value).map_err(|_| {
            DeimosError::General(GeneralError::ParsingError(format!("hashchain to string")))
        })?;
        con.set::<&String, String, String>(&incoming_entry.id, value)
            .map_err(|_| {
                DeimosError::Database(DatabaseError::WriteError(format!(
                    "hashchain update for key: {}",
                    incoming_entry.id
                )))
            })?;
        Ok(())
    }

    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> Result<(), DatabaseError> {
        let mut con = self.lock_connection(&self.derived_dict)?;
        let mut input_con = self.lock_connection(&self.input_order)?;
        let hashed_key = sha256(&incoming_entry.id);
        con.set::<&String, &String, String>(&hashed_key, &value.hash)
            .map_err(|_| {
                DatabaseError::WriteError(format!("derived dict update for key: {}", hashed_key))
            })?;

        if new {
            input_con
                .rpush::<&'static str, &String, u32>("input_order", &hashed_key)
                .map_err(|_| {
                    DatabaseError::WriteError(format!("input order update for key: {}", hashed_key))
                })?;
        }
        Ok(())
    }

    fn get_epochs(&self) -> Result<Vec<u64>, DeimosError> {
        let mut con = self
            .commitments
            .lock()
            .map_err(|_| DeimosError::Database(DatabaseError::LockError))?;

        con.keys::<&str, Vec<String>>("*")
            .map_err(|_| {
                DeimosError::Database(DatabaseError::NotFoundError("Commitments".to_string()))
            })?
            .into_iter()
            .map(|epoch| {
                epoch.replace("epoch_", "").parse::<u64>().map_err(|_| {
                    DeimosError::General(GeneralError::ParsingError(format!(
                        "failed to parse epoch"
                    )))
                })
            })
            .collect()
    }

    fn increment_epoch_operation(&self) -> Result<u64, DatabaseError> {
        let mut con = self.lock_connection(&self.app_state)?;
        con.incr::<&'static str, u64, u64>("epoch_operation", 1)
            .map_err(|_| DatabaseError::WriteError(format!("incremented epoch")))
    }

    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &String,
        proofs: &String,
    ) -> Result<(), DatabaseError> {
        let mut con = self.lock_connection(&self.merkle_proofs)?;
        let formatted_epoch = format!("epoch_{}_{}_{}", epoch, epoch_operation, commitment);
        con.set::<&String, &String, String>(&formatted_epoch, &proofs)
            .map_err(|_| {
                DatabaseError::WriteError(format!("merkle proof for epoch: {}", formatted_epoch))
            })?;
        Ok(())
    }

    fn add_commitment(&self, epoch: &u64, commitment: &String) -> Result<(), DatabaseError> {
        let mut con = self.lock_connection(&self.commitments)?;
        con.set::<&String, &String, String>(&format!("epoch_{}", epoch), commitment)
            .map_err(|_| DatabaseError::WriteError(format!("commitment for epoch: {}", epoch)))?;
        Ok(())
    }

    fn initialize_derived_dict(&self) -> Result<(), DatabaseError> {
        let mut con = self.lock_connection(&self.derived_dict)?;
        let mut input_con = self.lock_connection(&self.input_order)?;

        let empty_hash = Node::EMPTY_HASH.to_string(); // empty hash is always the first node (H(active=true, label=0^w, value=0^w, next=1^w))

        // set the empty hash as the first node in the derived dict
        con.set::<&String, &String, String>(&empty_hash, &empty_hash)
            .map_err(|_| {
                DatabaseError::WriteError(format!(
                    "empty hash as first entry in the derived dictionary"
                ))
            })?;
        debug!("added empty hash to derived dict");

        // add the empty hash to the input order as first node
        input_con
            .rpush::<&str, String, u32>("input_order", empty_hash.clone())
            .map_err(|_| {
                DatabaseError::WriteError(format!("empty hash as first entry in input order"))
            })?;
        debug!("added empty hash to input order");

        Ok(())
    }

    fn flush_database(&self) -> Result<(), DatabaseError> {
        let mut main_conn = self.lock_connection(&self.main_dict)?;
        let mut derived_conn = self.lock_connection(&self.derived_dict)?;
        let mut input_order_conn = self.lock_connection(&self.input_order)?;
        let mut app_state_conn = self.lock_connection(&self.app_state)?;
        let mut merkle_proof_conn = self.lock_connection(&self.merkle_proofs)?;
        let mut commitments_conn = self.lock_connection(&self.commitments)?;

        redis::cmd("FLUSHALL")
            .query(&mut main_conn)
            .map_err(|_| DatabaseError::DeleteError(format!("all entries in main dict")))?;
        redis::cmd("FLUSHALL")
            .query(&mut derived_conn)
            .map_err(|_| DatabaseError::DeleteError(format!("all entries in derived dict")))?;
        redis::cmd("FLUSHALL")
            .query(&mut input_order_conn)
            .map_err(|_| DatabaseError::DeleteError(format!("all entries in input order")))?;
        redis::cmd("FLUSHALL")
            .query(&mut app_state_conn)
            .map_err(|_| DatabaseError::DeleteError(format!("all entries in app state")))?;
        redis::cmd("FLUSHALL")
            .query(&mut merkle_proof_conn)
            .map_err(|_| DatabaseError::DeleteError(format!("all merkle proofs")))?;
        redis::cmd("FLUSHALL")
            .query(&mut commitments_conn)
            .map_err(|_| DatabaseError::DeleteError(format!("all commitments")))?;
        Ok(())
    }
}

#[cfg(not(feature = "ci"))]
#[cfg(test)]
mod tests {
    use super::*;
    use deimos_types::types::Operation;
    use serde::{Serialize, Deserialize};

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
            hash: "test_hash".to_string(),
            previous_hash: "test_previous_hash".to_string(),
            operation: Operation::Add,
            value: "test_value".to_string(),
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
            .update_hashchain(&incoming_entry1, &vec![create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry2, &vec![create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry3, &vec![create_mock_chain_entry()])
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
            .update_hashchain(&incoming_entry1, &vec![create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry2, &vec![create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry3, &vec![create_mock_chain_entry()])
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
            .update_hashchain(&incoming_entry1, &vec![create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry2, &vec![create_mock_chain_entry()])
            .unwrap();
        redis_connections
            .update_hashchain(&incoming_entry3, &vec![create_mock_chain_entry()])
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
            sha256(&"test_key1".to_string()),
            sha256(&"test_key2".to_string()),
            sha256(&"test_key3".to_string()),
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
            .update_hashchain(&incoming_entry, &vec![chain_entry.clone()])
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
            .update_hashchain(&incoming_entry, &vec![chain_entry.clone()])
            .unwrap();

        let hashchain = redis_connections.get_hashchain(&"missing_test_key".to_string());
        assert!(hashchain.is_err());
        let error = hashchain.unwrap_err();
        assert!(
            matches!(error, DatabaseError::NotFoundError(msg) if msg == "key: missing_test_key")
        );

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

        let hashchain =
            redis_connections.get_hashchain(&"key_to_wrong_formatted_chain_entry".to_string());

        assert!(hashchain.is_err());
        let error = hashchain.unwrap_err();
        assert!(
            matches!(error, DatabaseError::GeneralError(msg) if msg == "failed to parse hashchain")
        );

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
        assert_eq!(hashchain[0].hash, "test_hash");
        assert_eq!(hashchain.len(), 1);

        teardown(&redis_connections);
    }
}
