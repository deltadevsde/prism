use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use bellman::groth16::Proof;
use bls12_381::Bls12;
use crypto_hash::{hex_digest, Algorithm};
use ed25519_dalek::{Signature, Verifier};
use std::{self, sync::Arc, time::Duration, io::ErrorKind};
use tokio::{time::sleep, task::spawn};
use indexed_merkle_tree::{IndexedMerkleTree, Node, error::MerkleTreeError};


use crate::{
    da::{DataAvailabilityLayer, EpochJson},
    storage::{ChainEntry, Database, IncomingEntry, Operation, UpdateEntryJson},
    utils::{is_not_revoked, validate_epoch, validate_epoch_from_proof_variants, decode_public_key},
    webserver::WebServer,
    zk_snark::{
        deserialize_custom_to_verifying_key, deserialize_proof, serialize_proof,
        serialize_verifying_key_to_custom,
    },
    Config, error::DeimosError,
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
}

pub struct LightClient {
    pub da: Arc<dyn DataAvailabilityLayer>,
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
                            // TODO: Verify sequencer signatures,
                            // Verify adjacency to last heights, <- for this we need some sort of storage of epochs
                            // Verify zk proofs,
                            for epoch_json in epoch_json_vec {
                                let prev_commitment = epoch_json.prev_commitment;
                                let current_commitment = epoch_json.current_commitment;
                                let proof = deserialize_proof(&epoch_json.proof).unwrap();
                                let verifying_key =
                                    deserialize_custom_to_verifying_key(&epoch_json.verifying_key)
                                        .unwrap();

                                match validate_epoch(&prev_commitment, &current_commitment, proof, verifying_key) {
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

        handle.await.map_err(|e| {
            std::io::Error::new(ErrorKind::Other, format!("Join error: {}", e))
        })
    }
}

impl LightClient {
    pub fn new(da: Arc<dyn DataAvailabilityLayer>) -> LightClient {
        LightClient { da }
    }
}

impl Sequencer {
    pub fn new(
        db: Arc<dyn Database>,
        da: Option<Arc<dyn DataAvailabilityLayer>>,
        cfg: Config,
    ) -> Sequencer {
        Sequencer {
            db,
            da,
            epoch_duration: cfg.epoch_time,
            ws: WebServer::new(cfg.webserver.unwrap()),
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
        self.db.reset_epoch_operation_counter().map_err(DeimosError::Database)?;

        // add the commitment for the operations ran since the last epoch
        let current_commitment = self.create_tree().map_err(DeimosError::MerkleTree)?.get_commitment().map_err(DeimosError::MerkleTree)?;

        self.db.add_commitment(&epoch, &current_commitment).map_err(DeimosError::Database)?;

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
            empty_commitment.get_commitment().map_err(DeimosError::MerkleTree)?
        };

        let (proof, verifying_key) = validate_epoch_from_proof_variants(
            &prev_commitment,
            &current_commitment,
            &proofs,
        )?;
        let epoch_json = EpochJson {
            height: epoch,
            prev_commitment: prev_commitment.clone(),
            current_commitment: current_commitment.clone(),
            proof: serialize_proof(&proof),
            verifying_key: serialize_verifying_key_to_custom(&verifying_key),
        };
        if let Some(da) = &self.da {
            // TODO: retries (#10)
            da.submit(&epoch_json).await;
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
                Node::initialize_leaf(true, true, key.clone(), value, Node::TAIL.to_string())
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
            nodes.push(Node::initialize_leaf(
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
        // add a new key to an existing id  ( type for the value retrieved from the database explicitly set to string)
        match self.db.get_hashchain(&signature.id) {
            Ok(value) => {
                // hashchain already exists
                let mut current_chain = value.clone();

                // check with given key if the signature is valid
                let incoming_entry = match self.verify_signature_wrapper(&signature) {
                    Ok(entry) => entry,
                    Err(_) => {
                        info!("Signature is invalid");
                        return false;
                    }
                };

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
                let incoming_entry = match self.verify_signature_wrapper(&signature) {
                    Ok(entry) => entry,
                    Err(_) => {
                        error!("Signature is invalid");
                        return false;
                    }
                };
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

    fn verify_signature_wrapper(
        &self,
        signature_with_key: &UpdateEntryJson,
    ) -> Result<IncomingEntry, &'static str> {
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
    /// It checks if there is an entry for the id of the incoming entry in the database and
    /// if there is, it checks if any public key in the hashchain can verify the signature.
    ///
    /// Returns true if there is a public key for the id which can verify the signature
    /// Returns false if there is no public key for the id or if no public key can verify the signature
    ///
    /// ONLY FOR KEY TRANSPARENCY APPLICATION
    fn _verify_signature(
        &self,
        signature_with_key: &UpdateEntryJson,
    ) -> Result<IncomingEntry, &'static str> {
        // try to extract the value of the id from the incoming entry from the database
        // if the id does not exist, there is no id registered for the incoming entry and so the signature is invalid
        let received_signed_message = &signature_with_key.signed_message;
        let signed_message_bytes = general_purpose::STANDARD
            .decode(&received_signed_message)
            .expect("Error while decoding signed message");

        // check if the signed message is (at least) 64 bytes long
        if signed_message_bytes.len() < 64 {
            return Err("Signed message is too short");
        }

        let message_bytes = &signed_message_bytes[64..];

        // extract the first 64 bytes from the signed message
        let signature_bytes: &[u8; 64] = match signed_message_bytes.get(..64) {
            Some(array_section) => match array_section.try_into() {
                Ok(array) => array,
                Err(_) => panic!("Error while converting slice to array"),
            },
            None => panic!("Failed to get first 64 bytes from signed message"),
        };

        // Create PublicKey and Signature objects.
        let signature = Signature::from_bytes(signature_bytes);

        let mut current_chain: Vec<ChainEntry> = self
            .db
            .get_hashchain(&signature_with_key.id)
            .map_err(|_| "Error while getting hashchain")?;

        current_chain.reverse(); //check latest added keys first

        for entry in current_chain.iter() {
            if !is_not_revoked(&current_chain, entry.value.clone()) {
                continue;
            }

            let public_key = decode_public_key(&entry.value).map_err(|_| "Error while decoding public key")?;

            if public_key.verify(&message_bytes, &signature).is_ok() {
                // Deserialize the message
                let message =
                    String::from_utf8(message_bytes.to_vec()).map_err(|_| "Invalid message")?;
                let message_obj: IncomingEntry =
                    serde_json::from_str(&message).map_err(|_| "Invalid message")?;

                return Ok(IncomingEntry {
                    id: signature_with_key.id.clone(),
                    operation: message_obj.operation,
                    value: message_obj.value,
                });
            }
        }

        Err("No valid signature found")
    }

    fn verify_signature_with_given_key(
        &self,
        signature_with_key: &UpdateEntryJson,
    ) -> Result<IncomingEntry, &'static str> {
        // try to extract the value of the id from the incoming entry from the database
        // if the id does not exist, there is no id registered for the incoming entry and so the signature is invalid
        let received_public_key = &signature_with_key.public_key;
        let received_signed_message = &signature_with_key.signed_message;

        // TODO: better error handling (#11)
        let signed_message_bytes = general_purpose::STANDARD
            .decode(&received_signed_message)
            .expect("Error while decoding signed message");

        // check if the signed message is (at least) 64 bytes long
        if signed_message_bytes.len() < 64 {
            return Err("Signed message is too short");
        }

        let message_bytes = &signed_message_bytes[64..];

        // extract the first 64 bytes from the signed message
        let signature_bytes: &[u8; 64] = match signed_message_bytes.get(..64) {
            Some(array_section) => match array_section.try_into() {
                Ok(array) => array,
                Err(_) => panic!("Error while converting slice to array"),
            },
            None => panic!("Failed to get first 64 bytes from signed message"),
        };

        // Create PublicKey and Signature objects.
        let received_public_key = decode_public_key(&received_public_key).map_err(|_| "Error while decoding public key")?;
        let signature = Signature::from_bytes(signature_bytes);

        if received_public_key
            .verify(message_bytes, &signature)
            .is_ok()
        {
            // Deserialize the message
            let message =
                String::from_utf8(message_bytes.to_vec()).map_err(|_| "Invalid message")?;
            let message_obj: IncomingEntry =
                serde_json::from_str(&message).map_err(|_| "Invalid message")?;

            return Ok(IncomingEntry {
                id: signature_with_key.id.clone(),
                operation: message_obj.operation,
                value: message_obj.value,
            });
        } else {
            Err("No valid signature found")
        }
    }

}    

#[cfg(test)]
mod tests {
    use mockall::predicate;

    use super::*;
    use crate::{storage::{UpdateEntryJson, MockDatabase}, error::DatabaseError};

    const MOCK_PUBLIC_KEY: &str = "CosRXOoSLG7a8sCGx78KhtfLEuiyNY7L4ksFt78mp2M=";

    fn setup_logging() {
        pretty_env_logger::formatted_builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    }

    fn setup_sequencer() -> Sequencer {
        let mut mock_db = MockDatabase::new();

        mock_db.expect_get_epoch().returning(|| Ok(1));
        mock_db.expect_set_epoch().returning(|_| Ok(()));
        
        mock_db.expect_get_hashchain()
        .with(predicate::eq(MOCK_PUBLIC_KEY.to_string()))
            .returning(|_| Ok(vec![
                setup_first_chain_entry(),
                setup_second_chain_entry(),
            ]));

        mock_db.expect_get_hashchain()
            .with(predicate::eq("invalid_key".to_string()))
            .returning(|_| Err(DeimosError::Database(DatabaseError::NotFoundError("not found".to_string()))));

        //  Mocking update_hashchain and set derived entry to return Ok for any input for now, but i have to think about withf()-functions, what is needed and what not?!
        mock_db.expect_update_hashchain()
            .returning(|_, _| Ok(()));

        mock_db.expect_set_derived_entry()
            .returning(|_, _, _| Ok(()));

        Sequencer::new(
            Arc::new(mock_db),
            None,
            Config::default(),
        )
    }

    fn setup_sequencer_for_no_hashchain() -> Sequencer {
        let mut mock_db = MockDatabase::new();
    
        mock_db.expect_get_hashchain()
            .returning(|_| Err( DeimosError::Database(DatabaseError::NotFoundError(MOCK_PUBLIC_KEY.to_string()))));
    
        mock_db.expect_update_hashchain().returning(|_, _| Ok(()));
        mock_db.expect_set_derived_entry().returning(|_, _, _| Ok(()));
    
        Sequencer::new(
            Arc::new(mock_db),
            None,
            Config::default(),
        )
    }
    

    fn setup_first_chain_entry() -> ChainEntry {
        ChainEntry {
            hash: "dac1dd5c45e3646ee4133c6e298c31b7f79be55413bfd550eb83a8ecfab0eac5".to_string(),
            previous_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            operation: Operation::Add,
            value: "f239ed423e1bfb6cd9cd648b6088e641a33a22ea56d5a32e4b3921d8fe8d1fc6".to_string(),
        }
    }

    fn setup_second_chain_entry() -> ChainEntry {
        ChainEntry {
            hash: "2db91ce87fdc8673c3aa79c7eb4ecc7a4d22813be14939a68fd6d5f7c0be34c5".to_string(),
            previous_hash: "dac1dd5c45e3646ee4133c6e298c31b7f79be55413bfd550eb83a8ecfab0eac5".to_string(),
            operation: Operation::Add,
            value: "5fdc48c5d30ce17ca119bd96cdd5b4a0d388c8fb63169516adca69a24266a4e5".to_string(),
        }
    }

    /* fn setup_third_chain_entry() -> ChainEntry {
        ChainEntry {
            hash: "b80e52c1abc9c4a514862c5b507ad98bbc4d0f9a83f49932ee690038cbf59bfd".to_string(),
            previous_hash: "2db91ce87fdc8673c3aa79c7eb4ecc7a4d22813be14939a68fd6d5f7c0be34c5".to_string(),
            operation: Operation::Add,
            value: "d8a33fa1cc01cc9b05d35495a574cdfbfabbefcf6c7b09d16fdafacbff927d5e".to_string(),
        }
    } */

    fn setup_signature(valid_signature: bool) -> UpdateEntryJson {
        let signed_message = if valid_signature {
            "NRtq1sgoxllsPvljXZd5f4DV7570PdA9zWHa4ych2jBCDU1uUYXZvW72BS9O+C68hptk/4Y34sTJj4x92gq9DHsiaWQiOiJDb3NSWE9vU0xHN2E4c0NHeDc4S2h0ZkxFdWl5Tlk3TDRrc0Z0NzhtcDJNPSIsIm9wZXJhdGlvbiI6IkFkZCIsInZhbHVlIjoiMjE3OWM0YmIzMjc0NDQ1NGE0OTlhYTMwZTI0NTJlMTZhODcwMGQ5ODQyYjI5ZThlODcyN2VjMzczNWMwYjdhNiJ9".to_string()
        } else {
            "QVmk3wgoxllsPvljXZd5f4DV7570PdA9zWHa4ych2jBCDU1uUYXZvW72BS9O+C68hptk/4Y34sTJj4x92gq9DHsiaWQiOiJDb3NSWE9vU0xHN2E4c0NHeDc4S2h0ZkxFdWl5Tlk3TDRrc0Z0NzhtcDJNPSIsIm9wZXJhdGlvbiI6IkFkZCIsInZhbHVlIjoiMjE3OWM0YmIzMjc0NDQ1NGE0OTlhYTMwZTI0NTJlMTZhODcwMGQ5ODQyYjI5ZThlODcyN2VjMzczNWMwYjdhNiJ9".to_string()
        };

        UpdateEntryJson {
            id: MOCK_PUBLIC_KEY.to_string(),
            signed_message,
            public_key: MOCK_PUBLIC_KEY.to_string(),
        }
    }


    #[test]
    fn test_update_entry() {
        let sequencer = setup_sequencer();
        let signature_with_key = setup_signature(true);

        let result = sequencer.update_entry(&signature_with_key);
        assert!(result);
    }

    #[test]
    fn test_update_entry_with_invalid_signature() {
        let sequencer = setup_sequencer();
        let invalid_signature_entry = setup_signature(false);

        let update_result = sequencer.update_entry(&invalid_signature_entry);
        assert_eq!(update_result, false);
    }


    #[test]
    fn test_add_new_key() {
        let sequencer = setup_sequencer();
        let signature_with_key = setup_signature(true);

        let result = sequencer.update_entry(&signature_with_key);
        assert!(result);
    }

    #[test]
    fn test_update_entry_with_no_existing_hashchain() {
        setup_logging();
        let sequencer = setup_sequencer_for_no_hashchain();
        let signature_with_key = setup_signature(true); 

        let result = sequencer.update_entry(&signature_with_key);
        assert_eq!(result, true);
    }

    #[test]
    fn test_verify_valid_signature() {
        let sequencer = setup_sequencer();
        let signature_with_key = setup_signature(true);

        let result = sequencer.verify_signature_with_given_key(&signature_with_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let sequencer = setup_sequencer();
        let signature_with_key = setup_signature(false);

        let result = sequencer.verify_signature_with_given_key(&signature_with_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_short_message() {
        let sequencer = setup_sequencer();
        let signature_with_key = setup_signature(true);

        let short_message = general_purpose::STANDARD
            .encode(&"this is a short message".to_string());


        let signature_with_key = UpdateEntryJson {
            signed_message: short_message,
            ..signature_with_key
        };

        let result = sequencer.verify_signature_with_given_key(&signature_with_key);
        assert!(result.is_err());
    }
}