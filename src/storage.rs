use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use std::{self, fmt::Display, sync::Mutex};

use crate::{
    indexed_merkle_tree::{sha256, Node, ProofVariant},
    utils::parse_json_to_proof,
};

#[derive(Clone, Serialize, Deserialize, Debug)]
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

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ChainEntry {
    pub hash: String,
    pub previous_hash: String,
    pub operation: Operation,
    pub value: String,
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

#[derive(Deserialize, Debug)]
pub struct UpdateEntryJson {
    pub id: String,
    pub signed_message: String,
    pub public_key: String,
}

pub struct RedisConnections {
    pub main_dict: Mutex<Connection>,    // clear text key with hashchain
    pub derived_dict: Mutex<Connection>, // hashed key with last hashchain entry hash
    pub input_order: Mutex<Connection>,  // input order of the hashchain keys
    pub app_state: Mutex<Connection>,    // app state (just epoch counter for now)
    pub merkle_proofs: Mutex<Connection>, // merkle proofs (in the form: epoch_{epochnumber}_{commitment})
    pub commitments: Mutex<Connection>,   // epoch commitments
}

pub trait Database: Send + Sync {
    fn get_keys(&self) -> Vec<String>;
    fn get_derived_keys(&self) -> Vec<String>;
    fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, &str>;
    fn get_derived_value(&self, key: &String) -> Result<String, &str>;
    fn get_commitment(&self, epoch: &u64) -> Result<String, &str>;
    fn get_proof(&self, id: &String) -> Result<String, &str>;
    fn get_proofs_in_epoch(&self, epoch: &u64) -> Result<Vec<ProofVariant>, &str>;
    fn get_epoch(&self) -> Result<u64, &str>;
    fn get_epoch_operation(&self) -> Result<u64, &str>;
    fn set_epoch(&self, epoch: &u64) -> Result<(), String>;
    fn reset_epoch_operation_counter(&self) -> Result<(), String>;
    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &Vec<ChainEntry>,
    ) -> Result<(), String>;
    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> Result<(), String>;
    fn get_derived_dict_keys_in_order(&self) -> Result<Vec<String>, String>;
    fn get_epochs(&self) -> Result<Vec<u64>, String>;
    fn increment_epoch_operation(&self) -> Result<u64, String>;
    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &String,
        proofs: &String,
    );
    fn add_commitment(&self, epoch: &u64, commitment: &String);
    fn initialize_derived_dict(&self);
}

impl RedisConnections {
    pub fn new() -> RedisConnections {
        let client = redis::Client::open("redis://127.0.0.1/").unwrap();
        let derived_client = redis::Client::open("redis://127.0.0.1/1").unwrap();
        let input_order = redis::Client::open("redis://127.0.0.1/2").unwrap();
        let app_state = redis::Client::open("redis://127.0.0.1/3").unwrap();
        let merkle_proofs = redis::Client::open("redis://127.0.0.1/4").unwrap();
        let commitments = redis::Client::open("redis://127.0.0.1/5").unwrap();

        RedisConnections {
            main_dict: Mutex::new(client.get_connection().unwrap()),
            derived_dict: Mutex::new(derived_client.get_connection().unwrap()),
            input_order: Mutex::new(input_order.get_connection().unwrap()),
            app_state: Mutex::new(app_state.get_connection().unwrap()),
            merkle_proofs: Mutex::new(merkle_proofs.get_connection().unwrap()),
            commitments: Mutex::new(commitments.get_connection().unwrap()),
        }
    }
}

impl Database for RedisConnections {
    fn get_keys(&self) -> Vec<String> {
        let mut con = self.main_dict.lock().unwrap();
        let keys: Vec<String> = con.keys("*").unwrap();
        keys
    }

    fn get_derived_keys(&self) -> Vec<String> {
        let mut con = self.derived_dict.lock().unwrap();
        let keys: Vec<String> = con.keys("*").unwrap();
        keys
    }

    fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, &str> {
        let mut con = self.main_dict.lock().unwrap();
        let value: String = match con.get(key) {
            Ok(value) => value,
            Err(_) => return Err("Key not found"),
        };
        match serde_json::from_str(&value) {
            Ok(value) => Ok(value),
            Err(e) => Err("Internal error parsing value"),
        }
    }

    fn get_derived_value(&self, key: &String) -> Result<String, &str> {
        let mut con = self.derived_dict.lock().unwrap();
        match con.get(key) {
            Ok(value) => Ok(value),
            Err(_) => Err("Key not found"),
        }
    }

    fn get_commitment(&self, epoch: &u64) -> Result<String, &str> {
        let mut con = self.commitments.lock().unwrap();
        match con.get::<&str, String>(&format!("epoch_{}", epoch)) {
            Ok(value) => {
                let trimmed_value = value.trim_matches('"').to_string();
                Ok(trimmed_value)
            }
            Err(_) => Err("Commitment not found"),
        }
    }

    fn get_proof(&self, id: &String) -> Result<String, &str> {
        let mut con = self.merkle_proofs.lock().unwrap();
        match con.get(id) {
            Ok(value) => Ok(value),
            Err(_) => Err("Proof ID not found"),
        }
    }

    fn get_proofs_in_epoch(&self, epoch: &u64) -> Result<Vec<ProofVariant>, &str> {
        let mut con = self.merkle_proofs.lock().unwrap();
        let mut epoch_proofs: Vec<String> =
            match con.keys::<&String, Vec<String>>(&format!("epoch_{}*", epoch)) {
                Ok(value) => value,
                Err(_) => return Err("Epoch not found"),
            };

        // Sort epoch_proofs by extracting epoch number and number within the epoch
        epoch_proofs.sort_by(|a, b| {
            let a_parts: Vec<&str> = a.split('_').collect();
            let b_parts: Vec<&str> = b.split('_').collect();

            // use second number, for the format: epoch_1_1, epoch_1_2, epoch_1_3 etc. the second number is the number within the epoch
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

    fn get_epoch(&self) -> Result<u64, &str> {
        let mut con = self.app_state.lock().unwrap();
        let epoch: u64 = match con.get("epoch") {
            Ok(value) => value,
            Err(_) => return Err("Epoch could not be fetched"),
        };
        Ok(epoch)
    }

    fn get_epoch_operation(&self) -> Result<u64, &str> {
        let mut con = self.app_state.lock().unwrap();
        let epoch_operation: u64 = match con.get("epoch_operation") {
            Ok(value) => value,
            Err(_) => return Err("Epoch operation could not be fetched"),
        };
        Ok(epoch_operation)
    }

    fn set_epoch(&self, epoch: &u64) -> Result<(), String> {
        let mut con = self.app_state.lock().unwrap();
        match con.set::<&str, &u64, String>("epoch", epoch) {
            Ok(_) => Ok(()),
            Err(_) => Err("Epoch could not be set".to_string()),
        }
    }

    fn reset_epoch_operation_counter(&self) -> Result<(), String> {
        let mut con = self.app_state.lock().unwrap();
        match con.set::<&str, &u64, String>("epoch_operation", &0) {
            Ok(_) => Ok(()),
            Err(_) => Err("Epoch operation could not be reset".to_string()),
        }
    }

    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &Vec<ChainEntry>,
    ) -> Result<(), String> {
        let mut con = self.main_dict.lock().unwrap();
        let value = serde_json::to_string(&value).unwrap();

        match con.set::<&String, String, String>(&incoming_entry.id, value) {
            Ok(_) => Ok(()),
            Err(_) => Err(format!(
                "Could not update hashchain for key {}",
                incoming_entry.id
            )),
        }
    }

    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> Result<(), String> {
        let mut con = self.derived_dict.lock().unwrap();
        let mut input_con = self.input_order.lock().unwrap();
        let hashed_key = sha256(&incoming_entry.id);
        con.set::<&String, &String, String>(&hashed_key, &value.hash)
            .unwrap();
        if new {
            match input_con.rpush::<&'static str, &String, u32>("input_order", &hashed_key) {
                Ok(_) => Ok(()),
                Err(_) => Err(format!("Could not push {} to input order", &hashed_key)),
            }
        } else {
            Ok(())
        }
    }

    fn get_derived_dict_keys_in_order(&self) -> Result<Vec<String>, String> {
        let mut con = self.input_order.lock().unwrap();
        match con.lrange("input_order", 0, -1) {
            Ok(value) => Ok(value),
            Err(_) => Err(format!("Could not fetch input order")),
        }
    }

    fn get_epochs(&self) -> Result<Vec<u64>, String> {
        let mut con = self.commitments.lock().unwrap();

        let epochs: Vec<u64> = match con.keys::<&str, Vec<String>>("*") {
            Ok(value) => value
                .iter()
                .map(|epoch| epoch.replace("epoch_", "").parse::<u64>().unwrap())
                .collect(),
            Err(_) => return Err(format!("Epochs could not be fetched")),
        };
        Ok(epochs)
    }

    fn increment_epoch_operation(&self) -> Result<u64, String> {
        let mut con = self.app_state.lock().unwrap();
        match con.incr::<&'static str, u64, u64>("epoch_operation", 1) {
            Ok(value) => Ok(value),
            Err(_) => Err(format!("Epoch operation could not be incremented")),
        }
    }

    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &String,
        proofs: &String,
    ) {
        let mut con = self.merkle_proofs.lock().unwrap();
        let key = format!("epoch_{}_{}_{}", epoch, epoch_operation, commitment);
        match con.set::<&String, &String, String>(&key, &proofs) {
            Ok(_) => debug!("Added merkle proof for key {}", key),
            Err(_) => debug!("Could not add merkle proof for key {}", key),
        };
    }

    fn add_commitment(&self, epoch: &u64, commitment: &String) {
        let mut con = self.commitments.lock().unwrap();
        match con.set::<&String, &String, String>(&format!("epoch_{}", epoch), commitment) {
            Ok(_) => debug!("Added commitment for epoch {}", epoch),
            Err(_) => debug!("Could not add commitment for epoch {}", epoch),
        };
    }

    fn initialize_derived_dict(&self) {
        let mut con = self.derived_dict.lock().unwrap();
        let mut input_con = self.input_order.lock().unwrap();

        let empty_hash = Node::EMPTY_HASH.to_string(); // empty hash is always the first node (H(active=true, label=0^w, value=0^w, next=1^w))
        match con.set::<&String, &String, String>(&empty_hash, &empty_hash) {
            Ok(_) => debug!("Added empty hash to derived dict"),
            Err(_) => debug!("Could not add empty hash to derived dict"),
        }; // set the empty hash as the first node in the derived dict
        match input_con.rpush::<&str, String, u32>("input_order", empty_hash.clone()) {
            Ok(_) => debug!("Added empty hash to input order"),
            Err(_) => debug!("Could not add empty hash to input order"),
        }; // add the empty hash to the input order as first node
    }
}
