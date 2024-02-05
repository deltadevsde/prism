use crate::error::{DataAvailabilityError, DatabaseError, DeimosError, GeneralError};
use crate::utils::Signable;
use crate::zk_snark::{Bls12Proof, VerifyingKey};
use celestia_types::blob::SubmitOptions;
use ed25519::Signature;
use fs2::FileExt;
use tokio::task::spawn;
use async_trait::async_trait;
use celestia_rpc::{Client, BlobClient, HeaderClient};
use celestia_types::{nmt::Namespace, Blob};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{self, sync::Arc};
use tokio::sync::mpsc;
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek};
use serde_json::Value;


#[derive(Serialize, Deserialize, Clone)]
pub struct EpochJson {
    pub height: u64,
    pub prev_commitment: String,
    pub current_commitment: String,
    pub proof: Bls12Proof,
    pub verifying_key: VerifyingKey,
    pub signature: Option<String>,
}

impl TryFrom<&Blob> for EpochJson {
    type Error = GeneralError;

    fn try_from(value: &Blob) -> Result<Self, GeneralError> {
        // convert blob data to utf8 string
        let data_str = String::from_utf8(value.data.clone()).map_err(|e| {
            GeneralError::ParsingError(format!(
                "Could not convert blob data to utf8 string: {}",
                e
            ))
        })?;

        // convert utf8 string to EpochJson
        serde_json::from_str(&data_str).map_err(|e| {
            GeneralError::ParsingError(format!(
                "Could not parse epoch json: {}",
                e
            ))
        })
    }
    
}

impl Signable for EpochJson {
    fn get_signature(&self) -> Result<Signature, DeimosError> {
        match &self.signature {
            Some(signature) => {
                let signature = Signature::from_str(signature).map_err(|_| DeimosError::General(GeneralError::ParsingError("Cannot parse signature".to_string())))?;
                Ok(signature)
            },
            None => Err(DeimosError::General(GeneralError::MissingArgumentError))
        }
    }

    fn get_content_to_sign(&self) -> Result<String, DeimosError> {
        let mut copy = self.clone();
        copy.signature = None; 
        serde_json::to_string(&copy).map_err(|_| DeimosError::General(GeneralError::ParsingError("Cannot serialize".to_string())))
    }

    fn get_public_key(&self) -> Result<String, DeimosError> {
        // for epoch json the public key to verify is the one from the sequencer which should be already be public and known from every light client
        // so if we use this function there should be an error
        Err(DeimosError::Database(DatabaseError::NotFoundError("Public key not found".to_string())))
    }
}


enum Message {
    UpdateTarget(u64),
}

#[async_trait]
pub trait DataAvailabilityLayer: Send + Sync {
    async fn get_message(&self) -> Result<u64, DataAvailabilityError>;
    async fn initialize_sync_target(&self) -> Result<u64, DataAvailabilityError>;
    async fn get(&self, height: u64) -> Result<Vec<EpochJson>, DataAvailabilityError>;
    async fn submit(&self, epoch: &EpochJson) -> Result<u64, DataAvailabilityError>;
    async fn start(&self) -> Result<(), DataAvailabilityError>;
}

pub struct CelestiaConnection {
    pub client: celestia_rpc::Client,
    pub namespace_id: Namespace,
    tx: Arc<mpsc::Sender<Message>>,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Message>>>,
}

/// The `LocalDataAvailabilityLayer` is a mock implementation of the `DataAvailabilityLayer` trait.
/// It simulates the behavior of a data availability layer, storing and retrieving epoch-objects in-memory only. 
/// This allows to write and test the functionality of systems that interact with a data availability layer without the need for an actual external service or network like we do with Celestia.
/// 
/// This implementation is intended for testing and development only and should not be used in production environments. It provides a way to test the interactions with the data availability layer without the overhead of real network communication or data persistence.
pub struct LocalDataAvailabilityLayer {}

impl CelestiaConnection {
    // TODO: Should take config
    pub async fn new(
        connection_string: &String,
        auth_token: Option<&str>,
        namespace_hex: &String,
    ) -> Result<Self, DataAvailabilityError> {
        // TODO: Should buffer size be configurable? Is 5 a reasonable default?
        let (tx, rx) = mpsc::channel(5);

        let client = Client::new(&connection_string, auth_token).await.map_err(|e| {
            DataAvailabilityError::InitializationError(format!("Websocket initialization failed: {}", e))
        })?;

        let decoded_hex = match hex::decode(namespace_hex) {
            Ok(hex) => hex,
            Err(e) => return Err(DataAvailabilityError::InitializationError(format!("Hex decoding failed: {}", e))),
        };

        let namespace_id = Namespace::new_v0(&decoded_hex).map_err(|e| {
            DataAvailabilityError::InitializationError(format!("Namespace creation failed: {}", e))
        })?;

        Ok(CelestiaConnection {
            client,
            namespace_id,
            tx: Arc::new(tx),
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
        })
    }
}

#[async_trait]
impl DataAvailabilityLayer for CelestiaConnection {
    async fn get_message(&self) -> Result<u64, DataAvailabilityError> {
        match self.rx.lock().await.recv().await {
            Some(Message::UpdateTarget(height)) => Ok(height),
            None => Err(DataAvailabilityError::ChannelReceiveError),
        }
    }

    async fn initialize_sync_target(&self) -> Result<u64, DataAvailabilityError> {
        match HeaderClient::header_network_head(&self.client).await {
            Ok(extended_header) => Ok(extended_header.header.height.value()),
            Err(err) => Err(DataAvailabilityError::NetworkError(format!("Could not get network head from DA layer: {}", err))),
        }
    }

    async fn get(&self, height: u64) -> Result<Vec<EpochJson>, DataAvailabilityError> {
        debug! {"Getting epoch {} from DA layer", height};
        match BlobClient::blob_get_all(&self.client, height, &[self.namespace_id]).await {
            Ok(blobs) => {
                let mut epochs = Vec::new();
                for blob in blobs.iter() {
                    match EpochJson::try_from(blob) {
                        Ok(epoch_json) => epochs.push(epoch_json),
                        Err(_) => {
                            DataAvailabilityError::DataRetrievalError(
                                height,
                                "Could not parse epoch json for blob".to_string(),
                            );
                        }
                    }
                }
                Ok(epochs)
            }
            Err(err) => Err(DataAvailabilityError::DataRetrievalError(
                height,
                format!("Could not get epoch from DA layer: {}", err),
            )),
        }
    }

    async fn submit(&self, epoch: &EpochJson) -> Result<u64, DataAvailabilityError> {
        debug! {"Posting epoch {} to DA layer", epoch.height};
        
        let data = serde_json::to_string(&epoch).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::ParsingError(format!(
                "Could not serialize epoch json: {}",
                e
            )))})?;
        let blob = Blob::new(self.namespace_id.clone(), data.into_bytes()).map_err(|_| {
            DataAvailabilityError::GeneralError(GeneralError::BlobCreationError)
        })?;
        debug!("blob: {:?}", serde_json::to_string(&blob));
        match self.client.blob_submit(&[blob], SubmitOptions::default()).await {
            Ok(height) => {
                debug!(
                    "Submitted epoch {} to DA layer at height {}",
                    epoch.height, height
                );
                Ok(height)
            }
            // TODO implement retries (#10)
            Err(err) => Err(
                DataAvailabilityError::NetworkError(format!(
                    "Could not submit epoch to DA layer: {}",
                    err
                )),
            ),
        }
    }

    async fn start(&self) -> Result<(), DataAvailabilityError> {
        let mut header_sub = HeaderClient::header_subscribe(&self.client).await.map_err(|e| {
            DataAvailabilityError::NetworkError(format!(
                "Could not subscribe to header updates from DA layer: {}",
                e
            ))
        })?;

        let tx1 = self.tx.clone();
        spawn(async move {
            while let Some(extended_header_result) = header_sub.next().await {
                match extended_header_result {
                    Ok(extended_header) => {
                        let height = extended_header.header.height.value();
                        match tx1.send(Message::UpdateTarget(height)).await {
                            Ok(_) => {
                                debug!("Sent message to channel. Height: {}", height);
                            }
                            Err(_) => {
                                DataAvailabilityError::SyncTargetError(
                                    "sending".to_string(),
                                    format!("Failed to send sync target update message for height {}", height)
                                );
                            }
                        }
                    }
                    Err(_) => {
                        DataAvailabilityError::NetworkError(
                            "Could not get header from DA layer".to_string(),
                        );
                    }
                }
            }
        });
        Ok(())
    }
}


impl LocalDataAvailabilityLayer {
    pub fn new() -> Self {
        LocalDataAvailabilityLayer {  }
    }
}

#[async_trait]
impl DataAvailabilityLayer for LocalDataAvailabilityLayer {
    async fn get_message(&self) -> Result<u64, DataAvailabilityError> {
        Ok(100)
    }

    async fn initialize_sync_target(&self) -> Result<u64, DataAvailabilityError> {
        Ok(0)  // header starts always at zero in test cases
    }

    async fn get(&self, height: u64) -> Result<Vec<EpochJson>, DataAvailabilityError> {
        let mut file = File::open("data.json").expect("Unable to open file");
        let mut contents = String::new();
        file.lock_exclusive().expect("Unable to lock file");
        file.read_to_string(&mut contents).expect("Unable to read file");

        let data: Value = serde_json::from_str(&contents).expect("Invalid JSON format");

        if let Some(epoch) = data.get(height.to_string()) {
            // convert arbit. json value to EpochJson
            let result_epoch: Result<EpochJson,_> = serde_json::from_value(epoch.clone());
            file.unlock().expect("Unable to unlock file");
            Ok(vec![result_epoch.expect("WRON FORMT")])
        } else {
            file.unlock().expect("Unable to unlock file");
            Err(DataAvailabilityError::DataRetrievalError(
                height,
                "Could not get epoch from DA layer".to_string(),
            ))
        }
    }

    async fn submit(&self, epoch: &EpochJson) -> Result<u64, DataAvailabilityError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("data.json")
            .expect("Unable to open file");

        let mut contents = String::new();

        file.lock_exclusive().expect("Unable to lock file");
        info!("File locked");

        file.read_to_string(&mut contents).expect("Unable to read file");


        let mut data: Value = if contents.is_empty() {
            json!({})
        } else {
            serde_json::from_str(&contents).expect("Invalid JSON format")
        };

        // add new epoch to existing json-file data
        data[epoch.height.to_string()] = json!(epoch);

        // Reset the file pointer to the beginning of the file
        file.seek(std::io::SeekFrom::Start(0)).expect("Unable to seek to start");

        // Write the updated data into the file
        file.write_all(data.to_string().as_bytes()).expect("Unable to write file");

        // Truncate the file to the current pointer to remove any extra data
        file.set_len(data.to_string().as_bytes().len() as u64).expect("Unable to set file length");

        file.unlock().expect("Unable to unlock file");
        info!("File unlocked");

        Ok(epoch.height)
    }

    async fn start(&self) -> Result<(), DataAvailabilityError> {
        Ok(())
    }
}

#[cfg(test)]
mod da_tests {
    use crate::{
        zk_snark::{deserialize_proof, BatchMerkleProofCircuit, serialize_proof, VerifyingKey, serialize_verifying_key_to_custom, deserialize_custom_to_verifying_key}, utils::validate_epoch,
    };

    use super::*;
    use indexed_merkle_tree::{sha256, IndexedMerkleTree, Node, ProofVariant};
    use bellman::groth16;
    use bls12_381::Bls12;
    use rand::rngs::OsRng;
    use std::fs::OpenOptions;
    use std::io::{Error, Seek, SeekFrom};

    const EMPTY_HASH: &str = Node::EMPTY_HASH;
    const TAIL: &str = Node::TAIL;

    pub fn clear_file(filename: &str) -> Result<(), Error> {
        // Open file for writing
        let mut file = OpenOptions::new()
            .write(true)
            .open(filename)?;
    
        // Set file length to 0 to delete all data in the file
        file.set_len(0)?;
    
        // Set pointer to the beginning of the file
        file.seek(SeekFrom::Start(0))?;
    
        Ok(())
    }

    fn build_empty_tree() -> IndexedMerkleTree {
        let active_node = Node::initialize_leaf(
            true,
            true,
            EMPTY_HASH.to_string(),
            EMPTY_HASH.to_string(),
            TAIL.to_string(),
        );
        let inactive_node = Node::initialize_leaf(
            false,
            true,
            EMPTY_HASH.to_string(),
            EMPTY_HASH.to_string(),
            TAIL.to_string(),
        );

        // build a tree with 4 nodes
        IndexedMerkleTree::new(vec![
            active_node,
            inactive_node.clone(),
            inactive_node.clone(),
            inactive_node,
        ]).unwrap()
    }

    fn create_node(label: &str, value: &str) -> Node {
        let label = sha256(&label.to_string());
        let value = sha256(&value.to_string());
        Node::initialize_leaf(true, true, label, value, TAIL.to_string())
    }

    fn create_proof_and_vk(prev_commitment: String, current_commitment: String, proofs: Vec<ProofVariant>) -> (Bls12Proof, VerifyingKey) {
        let batched_proof =
            BatchMerkleProofCircuit::create(&prev_commitment, &current_commitment, proofs).unwrap();

        let rng = &mut OsRng;
        let params =
            groth16::generate_random_parameters::<Bls12, _, _>(batched_proof.clone(), rng).unwrap();
        let proof = groth16::create_random_proof(batched_proof.clone(), &params, rng).unwrap();

        // the serialized proof is posted
        (serialize_proof(&proof), serialize_verifying_key_to_custom(&params.vk))
    }

    fn verify_epoch_json(epoch: Vec<EpochJson>) {
        for epoch_json in epoch {
            let prev_commitment = epoch_json.prev_commitment;
            let current_commitment = epoch_json.current_commitment;

            let proof = deserialize_proof(&epoch_json.proof).unwrap();
            let verifying_key =
                deserialize_custom_to_verifying_key(&epoch_json.verifying_key)
                    .unwrap();

            match validate_epoch(&prev_commitment, &current_commitment, proof, verifying_key) {
                Ok(_) => {
                    info!("\n\nvalidating epochs with commitments: [{}, {}]\n\n proof\n a: {},\n b: {},\n c: {}\n\n verifying key \n alpha_g1: {},\n beta_1: {},\n beta_2: {},\n delta_1: {},\n delta_2: {},\n gamma_2: {}\n", prev_commitment, current_commitment, &epoch_json.proof.a, &epoch_json.proof.b, &epoch_json.proof.c, &epoch_json.verifying_key.alpha_g1, &epoch_json.verifying_key.beta_g1, &epoch_json.verifying_key.beta_g2, &epoch_json.verifying_key.delta_g1, &epoch_json.verifying_key.delta_g2, &epoch_json.verifying_key.gamma_g2);
                }
                Err(err) => panic!("Failed to validate epoch: {:?}", err),
            }
        }
    }

    #[tokio::test]
    async fn test_sequencer_and_light_client() {
        if let Err(e) = clear_file("data.json") {
            debug!("Fehler beim Löschen der Datei: {}", e);
        }

        // simulate sequencer start
        let sequencer = tokio::spawn(async {
            let sequencer_layer = LocalDataAvailabilityLayer::new();
            // write all 60 seconds proofs and commitments
            // create a new tree
            let mut tree = build_empty_tree();
            let prev_commitment = tree.get_commitment().unwrap();

            // insert a first node
            let node_1 = create_node("test1", "test2");

            // generate proof for the first insert
            let first_insert_proof = tree.generate_proof_of_insert(&node_1).unwrap();
            let first_insert_zk_snark = ProofVariant::Insert(first_insert_proof);

            // create bls12 proof for posting
            let (bls12proof, vk) = create_proof_and_vk(prev_commitment.clone(), tree.get_commitment().unwrap(), vec![first_insert_zk_snark]);

            sequencer_layer.submit(&EpochJson { 
                height: 1, 
                prev_commitment: prev_commitment, 
                current_commitment: tree.get_commitment().unwrap(),
                proof: bls12proof, 
                verifying_key: vk,
                signature: None
            }).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(65)).await;

            // update prev commitment
            let prev_commitment = tree.get_commitment().unwrap();

            // insert a second and third node
            let node_2 = create_node("test3", "test4");
            let node_3 = create_node("test5", "test6");

            // generate proof for the second and third insert
            let second_insert_proof = tree.generate_proof_of_insert(&node_2).unwrap();
            let third_insert_proof = tree.generate_proof_of_insert(&node_3).unwrap();
            let second_insert_zk_snark = ProofVariant::Insert(second_insert_proof);
            let third_insert_zk_snark = ProofVariant::Insert(third_insert_proof);

            // proof and vk
            let (proof, vk) = create_proof_and_vk(prev_commitment.clone(), tree.get_commitment().unwrap(), vec![second_insert_zk_snark, third_insert_zk_snark]);
            sequencer_layer.submit(&EpochJson { 
                height: 2, 
                prev_commitment: prev_commitment, 
                current_commitment: tree.get_commitment().unwrap(),
                proof: proof, 
                verifying_key: vk,
                signature: None
            }).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(65)).await;
        });
    
        let light_client = tokio::spawn(async {
            debug!("light client started");
            let light_client_layer = LocalDataAvailabilityLayer::new();
            loop {
                let epoch = light_client_layer.get(1).await.unwrap();
                // verify proofs
                verify_epoch_json(epoch);
                debug!("light client verified epoch 1");
                
                // light_client checks time etc. tbdiscussed with distractedm1nd
                tokio::time::sleep(tokio::time::Duration::from_secs(70)).await;

                // Der Light Client liest Beweise und Commitments
                let epoch = light_client_layer.get(2).await.unwrap();
                // verify proofs
                verify_epoch_json(epoch);
                debug!("light client verified epoch 2");
            }
       
        });
    
        // run the test for example 3 minutes
        tokio::time::sleep(tokio::time::Duration::from_secs(150)).await;
    
        sequencer.abort();
        light_client.abort();
    } 
}



