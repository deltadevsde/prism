use std;
use actix_web::rt::spawn;
use async_trait::async_trait;
use celestia_rpc::client::new_websocket;
use celestia_rpc::{HeaderClient, BlobClient};
use celestia_types::Blob;
use celestia_types::nmt::Namespace;
use jsonrpsee::ws_client::WsClient;
use redis::{Commands, Connection};
use serde::{Serialize, Deserialize};
use crypto_hash::{Algorithm, hex_digest};
use std::fmt::Display;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use base64::{Engine as _, engine::general_purpose};
use bellman::groth16::{Proof, PreparedVerifyingKey};
use bls12_381::Bls12;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use std::thread;


use crate::indexed_merkle_tree::{IndexedMerkleTree, Node, ProofVariant, sha256};
use crate::utils::{is_not_revoked, parse_json_to_proof, validate_epoch, validate_epoch_from_proof_variants};
use crate::zk_snark::{Bls12Proof, serialize_proof, deserialize_proof, VerifyingKey, serialize_verifying_key_to_custom, deserialize_custom_to_verifying_key};

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

// TODO: Add signature from sequencer for lc to verify (#2)
#[derive(Serialize, Deserialize)]
pub struct EpochJson {
    pub height: u64,
    pub prev_commitment: String,
    pub current_commitment: String,
    pub proof: Bls12Proof,
    pub verifying_key: VerifyingKey,
}

impl TryFrom<&Blob> for EpochJson {
    type Error = ();

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        match serde_json::from_str::<EpochJson>(String::from_utf8(value.data.clone()).unwrap().as_str()) {
            Ok(epoch_json) => Ok(epoch_json),
            Err(e) => Err(()),
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

pub struct Session {
    pub db: Arc<dyn Database>,
    pub da: Arc<dyn DataAvailabilityLayer>
}

pub struct RedisConnections {
    pub main_dict: Mutex<Connection>, // clear text key with hashchain
    pub derived_dict: Mutex<Connection>, // hashed key with last hashchain entry hash
    pub input_order: Mutex<Connection>, // input order of the hashchain keys
    pub app_state: Mutex<Connection>, // app state (just epoch counter for now)
    pub merkle_proofs: Mutex<Connection>, // merkle proofs (in the form: epoch_{epochnumber}_{commitment})
    pub commitments: Mutex<Connection>, // epoch commitments
}

enum Message {
    UpdateTarget(u64)
}

pub struct CelestiaConnection {
    pub client: WsClient,
    pub namespace_id: Namespace,
    tx: Arc<mpsc::Sender<Message>>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Message>>>,
}

impl CelestiaConnection {
    pub async fn new(connection_string: &String, auth_token: Option<&str>, namespace_hex: &String) -> Self {
        // TODO: Is 5 a reasonable buffer size for this?
        let (tx, rx) = mpsc::channel(5);

        CelestiaConnection {
            client: new_websocket(&connection_string, auth_token).await.unwrap(),
            namespace_id: Namespace::new_v0(&hex::decode(namespace_hex).unwrap()).unwrap(),
            tx: Arc::new(tx),
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
        }
    }
    
}

#[async_trait]
pub trait DataAvailabilityLayer: Send + Sync {
    async fn get_message(&self) -> Result<u64, String>;
    async fn initialize_sync_target(&self) -> Result<u64, String>;
    async fn get(&self, height: u64) -> Result<Vec<EpochJson>, String>;
    async fn submit(&self, epoch: &EpochJson) -> Result<u64, String>;
    async fn start(&self) -> Result<(), String>;
}

#[async_trait]
impl DataAvailabilityLayer for CelestiaConnection {
    async fn get_message(&self) -> Result<u64, String> {
        match self.rx.lock().await.recv().await {
            Some(Message::UpdateTarget(height)) => Ok(height),
            None => Err(format!("Failed to get message from new header chennel")),
        }
    }

    async fn initialize_sync_target(&self) -> Result<u64, String> {
        match HeaderClient::header_network_head(&self.client).await {
            Ok(extended_header) => Ok(extended_header.header.height.value()),
            Err(err) => Err(format!("Could not get network head from DA layer: {}", err)), 
        }
    }

    async fn get(&self, height: u64) -> Result<Vec<EpochJson>, String> {
        debug!{"Getting epoch {} from DA layer", height};
        match BlobClient::blob_get_all(&self.client, height, &[self.namespace_id]).await {
            Ok(blobs) => {
                let mut epochs = Vec::new();
                for blob in blobs.iter() {
                    match EpochJson::try_from(blob) {
                        Ok(epoch_json) => epochs.push(epoch_json),
                        Err(_) => debug!("Could not parse epoch json for blob at height {}", height),
                    }
                }
                Ok(epochs)
            },
            Err(err) => Err(format!("Could not get height {} from DA layer: {}", height, err))
        }
    }

    async fn submit(&self, epoch: &EpochJson) -> Result<u64, String> {
        debug!{"Posting epoch {} to DA layer", epoch.height};
        // todo: unwraps (#11)
        let data = serde_json::to_string(&epoch).unwrap();
        let blob = Blob::new(self.namespace_id.clone(), data.into_bytes()).unwrap();
        debug!("blob: {}", serde_json::to_string(&blob).unwrap());
        match BlobClient::blob_submit(&self.client, &[blob]).await {
            Ok(height) => {
                debug!("Submitted epoch {} to DA layer at height {}", epoch.height, height);
                Ok(height)
            },
            // TODO implement retries (#10)
            Err(err) => {
                Err(format!("Could not submit epoch to DA layer: {}", err))
            }
        }
    }

    async fn start(&self) -> Result<(), String> {
        let mut header_sub = HeaderClient::header_subscribe(&self.client).await.unwrap();

        let tx1 = self.tx.clone();
        spawn(async move {
            while let Some(extended_header) = header_sub.next().await {
                let height = extended_header.unwrap().header.height.value();
                match tx1.send(Message::UpdateTarget(height)).await {
                    Ok(_) => {
                        debug!("Sent message to channel. Height: {}", height);
                    },
                    Err(_) => {
                        debug!("Could not send message to channel");
                    }
                }
            }
        });
        Ok(())
    }
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
    fn update_hashchain(&self, incoming_entry: &IncomingEntry, value: &Vec<ChainEntry>) -> Result<(), String>;
    fn set_derived_entry(&self, incoming_entry: &IncomingEntry, value: &ChainEntry, new: bool) -> Result<(), String>;
    fn get_derived_dict_keys_in_order(&self) -> Result<Vec<String>, String>;
    fn get_epochs(&self) -> Result<Vec<u64>, String>;
    fn increment_epoch_operation(&self) -> Result<u64, String>;
    fn add_merkle_proof(&self, epoch: &u64, epoch_operation: &u64, commitment: &String, proofs: &String);
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
            Err(e) => {
                Err("Internal error parsing value")
            }
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
            },
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
        let mut epoch_proofs: Vec<String> = match con.keys::<&String, Vec<String>>(&format!("epoch_{}*", epoch)) {
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
            .collect()
       )
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

    fn update_hashchain(&self, incoming_entry: &IncomingEntry, value: &Vec<ChainEntry>) -> Result<(), String> {
        let mut con = self.main_dict.lock().unwrap();
        let value = serde_json::to_string(&value).unwrap();

        match con.set::<&String, String, String>(&incoming_entry.id, value) {
            Ok(_) => Ok(()),
            Err(_) => Err(format!("Could not update hashchain for key {}", incoming_entry.id)),
        }
    }

    fn set_derived_entry(&self, incoming_entry: &IncomingEntry, value: &ChainEntry, new: bool) -> Result<(), String> {
        let mut con = self.derived_dict.lock().unwrap();
        let mut input_con = self.input_order.lock().unwrap();
        let hashed_key = sha256(&incoming_entry.id);
        con.set::<&String, &String, String>(&hashed_key, &value.hash).unwrap();
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
            Ok(value) => value.iter().map(|epoch| epoch.replace("epoch_", "").parse::<u64>().unwrap()).collect(),
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

    fn add_merkle_proof(&self, epoch: &u64, epoch_operation: &u64, commitment: &String, proofs: &String) {
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

impl Session {
    /// Initializes the epoch state by setting up the input table and incrementing the epoch number.
    /// Periodically calls the `set_epoch_commitment` function to update the commitment for the current epoch.
    ///
    /// # Behavior
    /// 1. Initializes the input table by inserting an empty hash if it is empty.
    /// 2. Updates the epoch number in the app state.
    /// 3. Waits for a specified duration before starting the next epoch.
    /// 4. Calls `set_epoch_commitment` to fetch and set the commitment for the current epoch.
    /// 5. Repeats steps 2-4 periodically.
    pub async fn finalize_epoch(&self) -> Result<Proof<Bls12>, String> {
        let epoch = match self.db.get_epoch() {
            Ok(epoch) => epoch + 1,
            Err(_) => 0,
        };

        self.db.set_epoch(&epoch);
        self.db.reset_epoch_operation_counter();

        // add the commitment for the operations ran since the last epoch
        let current_commitment = self.create_tree().get_commitment();

        self.db.add_commitment(&epoch, &current_commitment);

        let proofs = if epoch > 0 {
            let prev_epoch = epoch - 1;
            self.db.get_proofs_in_epoch(&prev_epoch).unwrap()
        } else {
            vec![]
        };
        
        let prev_commitment = if epoch > 0 {
            let prev_epoch = epoch - 1;
            self.db.get_commitment(&prev_epoch).unwrap()
        } else {
            let empty_commitment = self.create_tree();
            empty_commitment.get_commitment()
        };

        let (proof, verifying_key) = match validate_epoch_from_proof_variants(&prev_commitment, &current_commitment, &proofs) {
            Ok(proof) => proof,
            Err(_) => return Err("Epoch validation failed".to_string()),
        };
        let epoch_json = EpochJson {
            height: epoch,
            prev_commitment: prev_commitment.clone(),
            current_commitment: current_commitment.clone(),
            proof: serialize_proof(&proof),
            verifying_key: serialize_verifying_key_to_custom(&verifying_key),
        };
        // TODO: retries (#10)
        self.da.submit(&epoch_json).await;
        Ok(proof)
    }

    pub fn create_tree(&self) -> IndexedMerkleTree {
        // TODO: better error handling (#11)
        // Retrieve the keys from input order and sort them. 
        let ordered_derived_dict_keys: Vec<String> = self.db.get_derived_dict_keys_in_order().unwrap_or(vec![]);
        let mut sorted_keys = ordered_derived_dict_keys.clone();
        sorted_keys.sort();
    
        // Initialize the leaf nodes with the value corresponding to the given key. Set the next node to the tail for now.
        let mut nodes: Vec<Node> = sorted_keys.iter().map(|key| {
            let value: String = self.db.get_derived_value(&key.to_string()).unwrap(); // we retrieved the keys from the input order, so we know they exist and can get the value
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
                    *k == &label.clone().unwrap() // without dereferencing we compare  &&string with &string
                })
                .unwrap()
                .0 
        });
    
        // Add empty nodes to ensure the total number of nodes is a power of two.
        while nodes.len() < next_power_of_two {
            nodes.push(Node::initialize_leaf(false, true, Node::EMPTY_HASH.to_string(), Node::EMPTY_HASH.to_string(), Node::TAIL.to_string()));
        }
    
        // create tree, setting left / right child property for each node
        let tree = IndexedMerkleTree::new(nodes);
        tree
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
    pub fn update_entry(&self, signature: &UpdateEntryJson) -> bool {
        println!("Updating entry...");
        // add a new key to an existing id  ( type for the value retrieved from the Redis database explicitly set to string)
        match self.db.get_hashchain(&signature.id) {
            Ok(value) => {
                // hashchain already exists
                let mut current_chain = value.clone();

                // check with given key if the signature is valid
                let incoming_entry = match self.verify_signature_wrapper(&signature) {
                    Ok(entry) => entry,
                    Err(_) => {
                        println!("Signature is invalid");
                        return false;
                    }
                };
                
                let new_chain_entry = ChainEntry {
                    hash: hex_digest(Algorithm::SHA256, format!("{}, {}, {}", &incoming_entry.operation, &incoming_entry.value, &current_chain.last().unwrap().hash).as_bytes()),
                    previous_hash: current_chain.last().unwrap().hash.clone(),
                    operation: incoming_entry.operation.clone(),
                    value: incoming_entry.value.clone(),
                };

                current_chain.push(new_chain_entry.clone());
                self.db.update_hashchain(&incoming_entry, &current_chain).unwrap();
                self.db.set_derived_entry(&incoming_entry, &new_chain_entry, false).unwrap();

                true
            },
            Err(_) => {
                debug!("Hashchain does not exist, creating new one...");
                let incoming_entry = match self.verify_signature_wrapper(&signature) {
                    Ok(entry) => entry,
                    Err(_) => {
                        error!("Signature is invalid");
                        return false;
                    }
                };
                let new_chain = vec![ChainEntry {
                    hash: hex_digest(Algorithm::SHA256, format!("{}, {}, {}", Operation::Add, &incoming_entry.value, Node::EMPTY_HASH.to_string()).as_bytes()),
                    previous_hash: Node::EMPTY_HASH.to_string(),
                    operation: incoming_entry.operation.clone(),
                    value: incoming_entry.value.clone(),
                }];
                self.db.update_hashchain(&incoming_entry, &new_chain).unwrap();
                self.db.set_derived_entry(&incoming_entry, new_chain.last().unwrap(), true).unwrap();

                true
            }
        }
    }

    fn verify_signature_wrapper(&self, signature_with_key: &UpdateEntryJson) -> Result<IncomingEntry, &'static str> {
        // to use this we have to build the project with cargo build --features "key_transparency"
        #[cfg(feature = "key_transparency")]
        {
            self.verify_signature(signature_with_key)
        }
        #[cfg(not(feature = "key_transparency"))]
        {
            self.verify_signature_with_given_key(signature_with_key)
        }
    }

    /// Checks if a signature is valid for a given incoming entry.
    /// 
    /// This function takes two arguments, an IncomingEntry and a Signature, and returns a boolean.
    /// It checks if there is an entry for the id of the incoming entry in the redis database and 
    /// if there is, it checks if any public key in the hashchain can verify the signature.
    /// 
    /// Returns true if there is a public key for the id which can verify the signature
    /// Returns false if there is no public key for the id or if no public key can verify the signature
    /// 
    /// ONLY FOR KEY TRANSPARENCY APPLICATION
    fn verify_signature(&self, signature_with_key: &UpdateEntryJson) -> Result<IncomingEntry, &'static str>  {
        // try to extract the value of the id from the incoming entry from the redis database
        // if the id does not exist, there is no id registered for the incoming entry and so the signature is invalid
        let received_signed_message = &signature_with_key.signed_message; 
        let signed_message_bytes = general_purpose::STANDARD.decode(&received_signed_message).expect("Error while decoding signed message");

        // Split the signed message into the signature and the message.
        let (signature_bytes, message_bytes) = signed_message_bytes.split_at(64);

        // Create PublicKey and Signature objects.
        let signature = Signature::from_bytes(signature_bytes).expect("Error while creating Signature object");

        let mut current_chain: Vec<ChainEntry> = self.db
            .get_hashchain(&signature_with_key.id)
            .map_err(|_| "Error while getting hashchain")?;

        current_chain.reverse(); //check latest added keys first

        for entry in current_chain.iter() {
            if !is_not_revoked(&current_chain, entry.value.clone()) {
                continue;
            }
    
            let public_key = PublicKey::from_bytes(
                &general_purpose::STANDARD
                    .decode(&entry.value)
                    .map_err(|_| "Error while decoding public key bytes")?,
            )
            .map_err(|_| "Error while creating PublicKey object")?;
    
            if public_key.verify(message_bytes, &signature).is_ok() {
                // Deserialize the message
                let message = String::from_utf8(message_bytes.to_vec())
                    .map_err(|_| "Invalid message")?;
                let message_obj: IncomingEntry = serde_json::from_str(&message)
                    .map_err(|_| "Invalid message")?;

                return Ok(IncomingEntry { 
                    id: signature_with_key.id.clone(), 
                    operation: message_obj.operation, 
                    value: message_obj.value 
                });
            }
        }
    
        Err("No valid signature found")
    }

    fn verify_signature_with_given_key(&self, signature_with_key: &UpdateEntryJson) -> Result<IncomingEntry, &'static str>  {
        // try to extract the value of the id from the incoming entry from the redis database
        // if the id does not exist, there is no id registered for the incoming entry and so the signature is invalid
        let received_public_key = &signature_with_key.public_key;
        let received_signed_message =  &signature_with_key.signed_message; 

        // TODO: better error handling (#11)
        let received_public_key_bytes = general_purpose::STANDARD.decode(&received_public_key).expect("Error while decoding public key");
        let signed_message_bytes = general_purpose::STANDARD.decode(&received_signed_message).expect("Error while decoding signed message");

        // Split the signed message into the signature and the message.
        let (signature_bytes, message_bytes) = signed_message_bytes.split_at(64);

        // Create PublicKey and Signature objects.
        let received_public_key = PublicKey::from_bytes(&received_public_key_bytes).expect("Error while creating PublicKey object");
        let signature = Signature::from_bytes(signature_bytes).expect("Error while creating Signature object");

        if received_public_key.verify(message_bytes, &signature).is_ok() {
            // Deserialize the message
            let message = String::from_utf8(message_bytes.to_vec())
                .map_err(|_| "Invalid message")?;
            let message_obj: IncomingEntry = serde_json::from_str(&message)
                .map_err(|_| "Invalid message")?;

            return Ok(IncomingEntry { 
                id: signature_with_key.id.clone(), 
                operation: message_obj.operation, 
                value: message_obj.value 
            });
        } else {
            Err("No valid signature found")
        }
    }
    
}