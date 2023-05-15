use std;
use redis::{Commands, Connection};
use serde::{Serialize, Deserialize};
use crypto_hash::{Algorithm, hex_digest};
use std::fmt::Display;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use base64::{Engine as _, engine::general_purpose};
use bellman::groth16::Proof;
use bls12_381::Bls12;

use crate::indexed_merkle_tree::{IndexedMerkleTree, Node, ProofVariant, sha256};
use crate::utils::{is_not_revoked, parse_json_to_proof, validate_epoch};

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
    pub public_key: String,
}

pub struct RedisConnections {
    pub main_dict: Connection, // clear text key with hashchain
    pub derived_dict: Connection, // hashed key with last hashchain entry hash
    pub input_order: Connection, // input order of the hashchain keys
    pub app_state: Connection, // app state (just epoch counter for now)
    pub merkle_proofs: Connection, // merkle proofs (in the form: epoch_{epochnumber}_{commitment})
    pub commitments: Connection, // epoch commitments
}

impl RedisConnections {
    pub fn new() -> RedisConnections {
        let client = redis::Client::open("redis://127.0.0.1/").unwrap();
        let derived_client = redis::Client::open("redis://127.0.0.1/1").unwrap();
        let input_order = redis::Client::open("redis://127.0.0.1/2").unwrap();
        let app_state = redis::Client::open("redis://127.0.0.1/3").unwrap();
        let merkle_proos = redis::Client::open("redis://127.0.0.1/4").unwrap();
        let commitments = redis::Client::open("redis://127.0.0.1/5").unwrap();

        RedisConnections {
            main_dict: client.get_connection().unwrap(),
            derived_dict: derived_client.get_connection().unwrap(),
            input_order: input_order.get_connection().unwrap(),
            app_state: app_state.get_connection().unwrap(),
            merkle_proofs: merkle_proos.get_connection().unwrap(),
            commitments: commitments.get_connection().unwrap(),
        }
    }

    pub fn get_keys(&mut self) -> Vec<String> {
        let keys: Vec<String> = self.main_dict.keys("*").unwrap();
        keys
    }

    pub fn get_derived_keys(&mut self) -> Vec<String> {
        let keys: Vec<String> = self.derived_dict.keys("*").unwrap();
        keys
    }

    pub fn get_hashchain(&mut self, key: &String) -> Result<Vec<ChainEntry>, &str> {
        let value: String = match self.main_dict.get(key) {
            Ok(value) => value,
            Err(_) => return Err("Key not found"),
        };
        match serde_json::from_str(&value) {
            Ok(value) => Ok(value),
            Err(e) => {
                Err("Internal error parsing value")
            }
        }
    }

    pub fn get_derived_value(&mut self, key: &String) -> Result<String, &str> {
        match self.derived_dict.get(key) {
            Ok(value) => Ok(value),
            Err(_) => Err("Key not found"),
        }
    }

    pub fn get_commitment(&mut self, epoch: &u64) -> Result<String, &str> {
        match self.commitments.get::<&str, String>(&format!("epoch_{}", epoch)) {
            Ok(value) => {
                let trimmed_value = value.trim_matches('"').to_string();
                Ok(trimmed_value)
            },
            Err(_) => Err("Commitment not found"),
        }
    }

    pub fn get_proof(&mut self, id: &String) -> Result<String, &str> {
        match self.merkle_proofs.get(id) {
            Ok(value) => Ok(value),
            Err(_) => Err("Proof ID not found"),
        }
    }

    pub fn get_proofs_in_epoch(&mut self, epoch: &u64) -> Result<Vec<ProofVariant>, &str> {
        let mut epoch_proofs: Vec<String> = match self.merkle_proofs.keys::<&String, Vec<String>>(&format!("epoch_{}*", epoch)) {
            Ok(value) => value,
            Err(_) => return Err("Epoch not found"),
        };


        // Sort epoch_proofs by extracting epoch number and number within the epoch
        epoch_proofs.sort_by(|a, b| {
            let a_parts: Vec<&str> = a.split('_').collect();
            let b_parts: Vec<&str> = b.split('_').collect();

            // zweite Zahl nutzen, da: epoch_1_1, epoch_1_2, epoch_1_3 usw. dann ist die zweite Zahl die Nummer innerhalb der Epoche
            let a_number: u64 = a_parts[2].parse().unwrap_or(0);
            let b_number: u64 = b_parts[2].parse().unwrap_or(0);

            // Compare first by epoch number, then by number within the epoch
            a_number.cmp(&b_number)
        });

        // Parse the proofs from JSON to ProofVariant
       Ok(epoch_proofs
            .iter()
            .filter_map(|proof| {
                self.merkle_proofs.get::<&str, String>(proof)
                    .ok()
                    .and_then(|proof_str| parse_json_to_proof(&proof_str).ok())
            })
            .collect()
       )
    }

    pub fn get_epoch(&mut self) -> Result<u64, &str> {
        let epoch: u64 = match self.app_state.get("epoch") {
            Ok(value) => value,
            Err(_) => return Err("Epoch could not be fetched"),
        };
        Ok(epoch)
    }

    pub fn get_epoch_operation(&mut self) -> Result<u64, &str> {
        let epoch_operation: u64 = match self.app_state.get("epoch_operation") {
            Ok(value) => value,
            Err(_) => return Err("Epoch operation could not be fetched"),
        };
        Ok(epoch_operation)
    }

    /// Checks if a signature is valid for a given incoming entry.
    /// 
    /// This function takes two arguments, an IncomingEntry and a Signature, and returns a boolean.
    /// It checks if there is an entry for the id of the incoming entry in the redis database and 
    /// if there is, it checks if any public key in the hashchain can verify the signature.
    /// 
    /// Returns true if there is a public key for the id which can verify the signature
    /// Returns false if there is no public key for the id or if no public key can verify the signature
    pub fn signature_is_valid(&mut self, incoming_entry: &IncomingEntry, signature: &Signature) -> bool {
        // try to extract the value of the id from the incoming entry from the redis database
        // if the id does not exist, there is no id registered for the incoming entry and so the signature is invalid
        let current_chain: Vec<ChainEntry> = match self.get_hashchain(&incoming_entry.id) {
            Ok(value) => value,
            Err(_) => return false, // if the id does not exist, return false
        };
        
        // iterate over the parsed hashchain and check if any non-revoked public key can verify the signature
        current_chain.iter().any(|entry| {
            if !is_not_revoked(&current_chain, entry.value.clone()) {
                return false;
            }

            // decode the base64 encoded public key
            let public_key = PublicKey::from_bytes(&general_purpose::STANDARD_NO_PAD.decode(&entry.value.as_bytes()).unwrap()).unwrap();
            
            // try to verify verify the signature
            public_key.verify(incoming_entry.public_key.as_bytes(), &signature).is_ok()
        })
    }

    fn update_hashchain(&mut self, incoming_entry: &IncomingEntry, value: &Vec<ChainEntry>) -> Result<(), String> {
        let value = serde_json::to_string(&value).unwrap();
        match self.main_dict.set::<&String, String, String>(&incoming_entry.id, value) {
            Ok(_) => Ok(()),
            Err(_) => Err(format!("Could not update hashchain for key {}", incoming_entry.id)),
        }
    }

    fn set_derived_entry(&mut self, incoming_entry: &IncomingEntry, value: &ChainEntry, new: bool) -> Result<(), &str> {
        let hashed_key = sha256(&incoming_entry.id);
        self.derived_dict.set::<&String, &String, String>(&hashed_key, &value.hash).unwrap();
        if new {
            match self.input_order.rpush::<&'static str, String, u32>("input_order", hashed_key) {
                Ok(_) => Ok(()),
                Err(_) => Err("Could not push to input order"),
            }
        } else {
            Ok(())
        }
    }

    pub fn get_epochs(&mut self) -> Result<Vec<u64>, &str> {
        let epochs: Vec<u64> = match self.commitments.keys::<&str, Vec<String>>("*") {
            Ok(value) => value.iter().map(|epoch| epoch.replace("epoch_", "").parse::<u64>().unwrap()).collect(),
            Err(_) => return Err("Epochs could not be fetched"),
        };
        Ok(epochs)
    }

    /// Updates an entry in the Redis database based on the given operation, incoming entry, and the signature from the user.
    ///
    /// # Arguments
    ///
    /// * `operation` - An `Operation` enum variant representing the type of operation to be performed (Add or Revoke).
    /// * `incoming_entry` - A reference to an `IncomingEntry` struct containing the key and the entry data to be updated.
    /// * `signature` - A `Signature` struct representing the signature.
    ///
    /// # Returns
    ///
    /// * `true` if the operation was successful and the entry was updated.
    /// * `false` if the operation was unsuccessful, e.g., due to an invalid signature or other errors.
    ///
    pub fn update_entry(&mut self, operation: Operation, incoming_entry: &IncomingEntry, signature: &Signature) -> bool {
        // add a new key to an existing id  ( type for the value retrieved from the Redis database explicitly set to string)
        match self.get_hashchain(&incoming_entry.id) {
            Ok(value) => {
            // hashchain already exists
            let mut current_chain = value.clone();

            if !self.signature_is_valid(&incoming_entry, signature) {
                return false;
            }
            let new_chain_entry = ChainEntry {
                hash: hex_digest(Algorithm::SHA256, format!("{}, {}, {}", operation, &incoming_entry.public_key, &current_chain.last().unwrap().hash).as_bytes()),
                previous_hash: current_chain.last().unwrap().hash.clone(),
                operation,
                value: incoming_entry.public_key.clone(),
            };

            current_chain.push(new_chain_entry.clone());
            self.update_hashchain(&incoming_entry, &current_chain).unwrap();
            self.set_derived_entry(&incoming_entry, &new_chain_entry, false).unwrap();

            true
            },
            Err(_) => {
                let new_chain = vec![ChainEntry {
                    hash: hex_digest(Algorithm::SHA256, format!("{}, {}, {}", Operation::Add, &incoming_entry.public_key, Node::EMPTY_HASH.to_string()).as_bytes()),
                    previous_hash: Node::EMPTY_HASH.to_string(),
                    operation,
                    value: incoming_entry.public_key.clone(),
                }];
                self.update_hashchain(&incoming_entry, &new_chain).unwrap();
                self.set_derived_entry(&incoming_entry, new_chain.last().unwrap(), true).unwrap();

                true
            }
        }
    }

    pub fn increment_epoch_operation(&mut self) -> u64 {
        self.app_state.incr::<&'static str, u64, u64>("epoch_operation", 1).unwrap()
    }

    pub fn add_merkle_proof(&mut self, epoch: &u64, epoch_operation: &u64, commitment: &String, proofs: &String) {
        let key = format!("epoch_{}_{}_{}", epoch, epoch_operation, commitment);
        self.merkle_proofs.set::<&String, &String, String>(&key, &proofs).unwrap();
    }

    pub fn add_commitment(&mut self, epoch: &u64, commitment: &String) {
        self.commitments.set::<&String, &String, String>(&format!("epoch_{}", epoch), commitment).unwrap();
    }

    pub(crate) fn initialize_derived_dict(&mut self) {
        let empty_hash = Node::EMPTY_HASH.to_string(); // empty hash is always the first node (H(active=true, label=0^w, value=0^w, next=1^w))
        self.derived_dict.set::<&String, &String, String>(&empty_hash, &empty_hash).unwrap(); // set the empty hash as the first node in the derived dict
        self.input_order.rpush::<&str, String, u32>("input_order", empty_hash.clone()).unwrap(); // add the empty hash to the input order as first node
    }

    /// Initializes the epoch state by setting up the input table and incrementing the epoch number.
    /// Periodically calls the `set_epoch_commitment` function to update the commitment for the current epoch.
    ///
    /// # Behavior
    /// 1. Initializes the input table by inserting an empty hash if it is empty.
    /// 2. Updates the epoch number in the app state.
    /// 3. Waits for a specified duration before starting the next epoch.
    /// 4. Calls `set_epoch_commitment` to fetch and set the commitment for the current epoch.
    /// 5. Repeats steps 2-4 periodically.
    pub fn finalize_epoch(&mut self) -> Result<Proof<Bls12>, String> {
        let epoch = match self.get_epoch() {
            Ok(epoch) => epoch + 1,
            Err(_) => 0,
        };

        // TODO(@distractedm1nd): dont call app_state set directly, abstract so we can swap out data layer
        // set the new epoch and reset the epoch operation counter
        self.app_state.set::<&'static str, &u64, String>(&"epoch", &epoch).unwrap();
        self.app_state.set::<&'static str, &'static str, String>("epoch_operation", "0").unwrap();

        // add the commitment for the operations ran since the last epoch
        let current_commitment = self.create_tree().get_commitment();
        self.add_commitment(&epoch, &current_commitment);

        let proofs = if epoch > 0 {
            let prev_epoch = epoch - 1;
            self.get_proofs_in_epoch(&prev_epoch).unwrap()
        } else {
            vec![]
        };
        
        let prev_commitment = if epoch > 0 {
            let prev_epoch = epoch - 1;
            self.get_commitment(&prev_epoch).unwrap()
        } else {
            let empty_commitment = IndexedMerkleTree::create_tree_from_redis(&mut self.derived_dict, &mut self.input_order);
            empty_commitment.get_commitment()
        };
        
        validate_epoch(&prev_commitment, &current_commitment, &proofs)
    
    }

    pub fn create_tree(&mut self) -> IndexedMerkleTree {
        // Retrieve the keys from input order and sort them.
        let ordered_derived_dict_keys: Vec<String> = self.input_order.lrange("input_order", 0, -1).unwrap();
        let mut sorted_keys = ordered_derived_dict_keys.clone();
        sorted_keys.sort();
    
        // Initialize the leaf nodes with the value corresponding to the given key. Set the next node to the tail for now.
        let mut nodes: Vec<Node> = sorted_keys.iter().map(|key| {
            let value: String = self.get_derived_value(&key.to_string()).unwrap(); // we retrieved the keys from the input order, so we know they exist and can get the value
            Node::initialize_leaf(true, true, key.clone(), value, Node::TAIL.to_string())
        }).collect();
        
        // calculate the next power of two, tree size is at least 8 for now
        let mut next_power_of_two: usize = 8;
        while next_power_of_two < ordered_derived_dict_keys.len() + 1 {
            next_power_of_two *= 2;
        }
        
        // Calculate the node hashes and sort the keys (right now they are sorted, so the next node is always the one bigger than the current one)
        for i in 0..nodes.len() - 1 {
            let is_next_node_active = nodes[i + 1].is_active();
            if is_next_node_active {
                let next_label = match &nodes[i + 1] {
                    Node::Leaf(next_leaf) => next_leaf.label.clone(),
                    _ => unreachable!(),
                };
            
                match &mut nodes[i] {
                    Node::Leaf(leaf) => {
                        leaf.next = next_label;
                    }
                    _ => (),
                }
            
                nodes[i].generate_hash();
            }
            
        }
        
        // resort the nodes based on the input order
        nodes.sort_by_cached_key(|node| {
            let label = match node {
                Node::Inner(_) => {
                    None
                }
                Node::Leaf(leaf) => {
                    let label = leaf.label.clone(); // get the label of the node
                    Some(label)
                }
            };
            ordered_derived_dict_keys
                .iter()
                .enumerate() // use index 
                .find(|(_, k)| {
                    *k == &label.clone().unwrap() // ohne dereferenzierung wird ein &&String mit &String verglichen
                })
                .unwrap()
                .0 // enumerate gibt tupel zurück, also index zurückgeben
        });
    
        // Add empty nodes to ensure the total number of nodes is a power of two.
        while nodes.len() < next_power_of_two {
            nodes.push(Node::initialize_leaf(false, true, Node::EMPTY_HASH.to_string(), Node::EMPTY_HASH.to_string(), Node::TAIL.to_string()));
        }
    
        // baum erstellen und dabei alle nodes überprüfen, ob sie linkes oder rechtes kind sind
        let tree = IndexedMerkleTree::new(nodes);
        tree
    }
}
