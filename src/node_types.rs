use async_trait::async_trait;
use bellman::groth16::Proof;
use bls12_381::Bls12;
use crypto_hash::{hex_digest, Algorithm};
use ed25519_dalek::{Signer, SigningKey};
use indexed_merkle_tree::{
    error::MerkleTreeError, node::LeafNode, node::Node, tree::IndexedMerkleTree,
};
use std::{self, io::ErrorKind, sync::Arc, time::Duration};
use tokio::{task::spawn, time::sleep};

use crate::{
    cfg::Config,
    da::{DataAvailabilityLayer, EpochJson},
    error::{DeimosError, GeneralError},
    storage::{ChainEntry, Database, IncomingEntry, Operation, UpdateEntryJson},
    utils::{validate_epoch, verify_signature},
    webserver::WebServer,
    zk_snark::{
        deserialize_custom_to_verifying_key, deserialize_proof, serialize_proof,
        serialize_verifying_key_to_custom, BatchMerkleProofCircuit,
    },
};

#[async_trait]
pub trait NodeType {
    async fn start(self: Arc<Self>) -> std::result::Result<(), std::io::Error>;
    // async fn stop(&self) -> Result<(), String>;
}

pub struct Sequencer {
    pub db: Arc<dyn Database>,
    pub da: Option<Arc<dyn DataAvailabilityLayer>>,
    pub epoch_duration: u64,
    pub ws: WebServer,
    pub key: SigningKey,
}

pub struct LightClient {
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub sequencer_public_key: Option<String>,
}

#[async_trait]
impl NodeType for Sequencer {
    async fn start(self: Arc<Self>) -> std::result::Result<(), std::io::Error> {
        // start listening for new headers to update sync target
        if let Some(da) = &self.da {
            da.start().await.unwrap();
        }

        let derived_keys = self.db.get_derived_keys();
        match derived_keys {
            Ok(keys) => {
                if keys.len() == 0 {
                    // if the dict is empty, we need to initialize the dict and the input order
                    self.db.initialize_derived_dict();
                }
            }
            Err(e) => {
                // TODO: custom error
                error!("sequencer_loop: getting derived keys: {}", e);
            }
        }

        let cloned_self = self.clone();

        debug!("starting main sequencer loop");
        spawn(async move {
            loop {
                match self.finalize_epoch().await {
                    Ok(_) => {
                        info!(
                            "sequencer_loop: finalized epoch {}",
                            self.db.get_epoch().unwrap()
                        );
                    }
                    Err(e) => error!("sequencer_loop: finalizing epoch: {}", e),
                }
                sleep(Duration::from_secs(self.epoch_duration)).await;
            }
        });

        // starting the webserver
        cloned_self.ws.start(cloned_self.clone()).await
    }
}

#[async_trait]
impl NodeType for LightClient {
    async fn start(self: Arc<Self>) -> std::result::Result<(), std::io::Error> {
        // start listening for new headers to update sync target
        self.da.start().await.unwrap();

        info!("starting main light client loop");
        // todo: persist current_position in datastore
        // also: have initial starting position be configurable

        let handle = spawn(async move {
            let mut current_position = 0;
            loop {
                // target is updated when a new header is received
                let target = self.da.get_message().await.unwrap();
                for i in current_position..target {
                    trace!("processing height: {}", i);
                    match self.da.get(i + 1).await {
                        Ok(epoch_json_vec) => {
                            // Verify adjacency to last heights, <- for this we need some sort of storage of epochs
                            // Verify zk proofs,
                            for epoch_json in epoch_json_vec {
                                let prev_commitment = &epoch_json.prev_commitment;
                                let current_commitment = &epoch_json.current_commitment;
                                let proof = deserialize_proof(&epoch_json.proof).unwrap();
                                let verifying_key =
                                    deserialize_custom_to_verifying_key(&epoch_json.verifying_key)
                                        .unwrap();
                                if self.sequencer_public_key.is_some() {
                                    if verify_signature(
                                        &epoch_json.clone(),
                                        self.sequencer_public_key.clone(),
                                    )
                                    .is_ok()
                                    {
                                        debug!("Signature is valid");
                                    } else {
                                        panic!("Invalid signature");
                                    }
                                } else {
                                    warn!("No public key found");
                                }

                                match validate_epoch(
                                    &prev_commitment,
                                    &current_commitment,
                                    proof,
                                    verifying_key,
                                ) {
                                    Ok(_) => (),
                                    Err(err) => panic!("Failed to validate epoch: {:?}", err),
                                }
                            }

                            info!("light client: got epochs at height {}", i + 1);
                        }
                        Err(e) => debug!("light client: getting epoch: {}", e),
                    };
                }
                sleep(Duration::from_secs(1)).await; // only for testing purposes
                current_position = target; // Update the current position to the latest target
            }
        });

        handle
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("Join error: {}", e)))
    }
}

impl LightClient {
    pub fn new(
        da: Arc<dyn DataAvailabilityLayer>,
        sequencer_pub_key: Option<String>,
    ) -> LightClient {
        LightClient {
            da,
            sequencer_public_key: sequencer_pub_key,
        }
    }
}

impl Sequencer {
    pub fn new(
        db: Arc<dyn Database>,
        da: Option<Arc<dyn DataAvailabilityLayer>>,
        cfg: Config,
        key: SigningKey,
    ) -> Sequencer {
        Sequencer {
            db,
            da,
            epoch_duration: cfg.epoch_time,
            ws: WebServer::new(cfg.webserver.unwrap()),
            key,
        }
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
    pub async fn finalize_epoch(&self) -> Result<Proof<Bls12>, DeimosError> {
        let epoch = match self.db.get_epoch() {
            Ok(epoch) => epoch + 1,
            Err(_) => 0,
        };

        self.db.set_epoch(&epoch).map_err(DeimosError::Database)?;
        self.db
            .reset_epoch_operation_counter()
            .map_err(DeimosError::Database)?;

        // add the commitment for the operations ran since the last epoch
        let current_commitment = self
            .create_tree()
            .map_err(DeimosError::MerkleTree)?
            .get_commitment()
            .map_err(DeimosError::MerkleTree)?;

        self.db
            .add_commitment(&epoch, &current_commitment)
            .map_err(DeimosError::Database)?;

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
            let empty_commitment = self.create_tree().map_err(DeimosError::MerkleTree)?;
            empty_commitment
                .get_commitment()
                .map_err(DeimosError::MerkleTree)?
        };

        let batch_circuit =
            BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs)?;
        let (proof, verifying_key) = batch_circuit.create_and_verify_snark()?;

        let signed_prev_commitment = self.key.sign(&prev_commitment.as_bytes()).to_string();
        let signed_current_commitment = self.key.sign(&current_commitment.as_bytes()).to_string();

        let epoch_json = EpochJson {
            height: epoch,
            prev_commitment: signed_prev_commitment,
            current_commitment: signed_current_commitment,
            proof: serialize_proof(&proof),
            verifying_key: serialize_verifying_key_to_custom(&verifying_key),
            signature: None,
        };

        let serialized_epoch_json_without_signature =
            serde_json::to_string(&epoch_json).map_err(|_| {
                DeimosError::General(GeneralError::ParsingError(
                    "Cannot parse epoch json".to_string(),
                ))
            })?;
        let signature = self
            .key
            .sign(serialized_epoch_json_without_signature.as_bytes())
            .to_string();
        let mut epoch_json_with_signature = epoch_json;
        epoch_json_with_signature.signature = Some(signature.clone());

        if let Some(da) = &self.da {
            // TODO: retries (#10)
            da.submit(&epoch_json_with_signature).await;
        }
        Ok(proof)
    }

    pub fn create_tree(&self) -> Result<IndexedMerkleTree, MerkleTreeError> {
        // TODO: better error handling (#11)
        // Retrieve the keys from input order and sort them.
        let ordered_derived_dict_keys: Vec<String> =
            self.db.get_derived_keys_in_order().unwrap_or(vec![]);
        let mut sorted_keys = ordered_derived_dict_keys.clone();
        sorted_keys.sort();

        // Initialize the leaf nodes with the value corresponding to the given key. Set the next node to the tail for now.
        let mut nodes: Vec<Node> = sorted_keys
            .iter()
            .map(|key| {
                let value: String = self.db.get_derived_value(&key.to_string()).unwrap(); // we retrieved the keys from the input order, so we know they exist and can get the value
                Node::new_leaf(true, true, key.clone(), value, Node::TAIL.to_string())
            })
            .collect();

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
                Node::Inner(_) => None,
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
            nodes.push(Node::new_leaf(
                false,
                true,
                Node::EMPTY_HASH.to_string(),
                Node::EMPTY_HASH.to_string(),
                Node::TAIL.to_string(),
            ));
        }

        // create tree, setting left / right child property for each node
        IndexedMerkleTree::new(nodes)
    }

    /// Updates an entry in the database based on the given operation, incoming entry, and the signature from the user.
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
        info!("Updating entry...");
        let signed_content = match verify_signature(signature, Some(signature.public_key.clone())) {
            Ok(content) => content,
            Err(_) => {
                info!("Signature is invalid");
                return false;
            }
        };

        let message_obj: IncomingEntry = match serde_json::from_str(&signed_content) {
            Ok(obj) => obj,
            Err(e) => {
                error!("Failed to parse signed content: {}", e);
                return false;
            }
        };

        // check with given key if the signature is valid
        let incoming_entry = IncomingEntry {
            id: signature.id.clone(),
            operation: message_obj.operation,
            value: message_obj.value,
        };
        // add a new key to an existing id  ( type for the value retrieved from the database explicitly set to string)
        match self.db.get_hashchain(&signature.id) {
            Ok(value) => {
                // hashchain already exists
                let mut current_chain = value.clone();

                let new_chain_entry = ChainEntry {
                    hash: hex_digest(
                        Algorithm::SHA256,
                        format!(
                            "{}, {}, {}",
                            &incoming_entry.operation,
                            &incoming_entry.value,
                            &current_chain.last().unwrap().hash
                        )
                        .as_bytes(),
                    ),
                    previous_hash: current_chain.last().unwrap().hash.clone(),
                    operation: incoming_entry.operation.clone(),
                    value: incoming_entry.value.clone(),
                };

                current_chain.push(new_chain_entry.clone());
                self.db
                    .update_hashchain(&incoming_entry, &current_chain)
                    .unwrap();
                self.db
                    .set_derived_entry(&incoming_entry, &new_chain_entry, false)
                    .unwrap();

                true
            }
            Err(_) => {
                debug!("Hashchain does not exist, creating new one...");
                let new_chain = vec![ChainEntry {
                    hash: hex_digest(
                        Algorithm::SHA256,
                        format!(
                            "{}, {}, {}",
                            Operation::Add,
                            &incoming_entry.value,
                            Node::EMPTY_HASH.to_string()
                        )
                        .as_bytes(),
                    ),
                    previous_hash: Node::EMPTY_HASH.to_string(),
                    operation: incoming_entry.operation.clone(),
                    value: incoming_entry.value.clone(),
                }];
                self.db
                    .update_hashchain(&incoming_entry, &new_chain)
                    .unwrap();
                self.db
                    .set_derived_entry(&incoming_entry, new_chain.last().unwrap(), true)
                    .unwrap();

                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::UpdateEntryJson;
    use base64::{engine::general_purpose, Engine as _};

    fn setup_signature(valid_signature: bool) -> UpdateEntryJson {
        let signed_message = if valid_signature {
            "NRtq1sgoxllsPvljXZd5f4DV7570PdA9zWHa4ych2jBCDU1uUYXZvW72BS9O+C68hptk/4Y34sTJj4x92gq9DHsiaWQiOiJDb3NSWE9vU0xHN2E4c0NHeDc4S2h0ZkxFdWl5Tlk3TDRrc0Z0NzhtcDJNPSIsIm9wZXJhdGlvbiI6IkFkZCIsInZhbHVlIjoiMjE3OWM0YmIzMjc0NDQ1NGE0OTlhYTMwZTI0NTJlMTZhODcwMGQ5ODQyYjI5ZThlODcyN2VjMzczNWMwYjdhNiJ9".to_string()
        } else {
            "QVmk3wgoxllsPvljXZd5f4DV7570PdA9zWHa4ych2jBCDU1uUYXZvW72BS9O+C68hptk/4Y34sTJj4x92gq9DHsiaWQiOiJDb3NSWE9vU0xHN2E4c0NHeDc4S2h0ZkxFdWl5Tlk3TDRrc0Z0NzhtcDJNPSIsIm9wZXJhdGlvbiI6IkFkZCIsInZhbHVlIjoiMjE3OWM0YmIzMjc0NDQ1NGE0OTlhYTMwZTI0NTJlMTZhODcwMGQ5ODQyYjI5ZThlODcyN2VjMzczNWMwYjdhNiJ9".to_string()
        };
        let id_public_key = "CosRXOoSLG7a8sCGx78KhtfLEuiyNY7L4ksFt78mp2M=".to_string();

        UpdateEntryJson {
            id: id_public_key.clone(),
            signed_message,
            public_key: id_public_key,
        }
    }

    #[test]
    fn test_verify_valid_signature() {
        let signature_with_key = setup_signature(true);

        let result = verify_signature(
            &signature_with_key,
            Some(signature_with_key.public_key.clone()),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let signature_with_key = setup_signature(false);

        let result = verify_signature(
            &signature_with_key,
            Some(signature_with_key.public_key.clone()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_short_message() {
        let signature_with_key = setup_signature(true);

        let short_message =
            general_purpose::STANDARD.encode(&"this is a short message".to_string());

        let signature_with_key = UpdateEntryJson {
            signed_message: short_message,
            ..signature_with_key
        };

        let result = verify_signature(
            &signature_with_key,
            Some(signature_with_key.public_key.clone()),
        );
        assert!(result.is_err());
    }
}
