use crate::error::{DAResult, DataAvailabilityError};
use async_trait::async_trait;
use fs2::FileExt;
use serde_json::{json, Value};
use std::{
    self,
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
};

use crate::da::{DataAvailabilityLayer, EpochJson};

/// The `NoopDataAvailabilityLayer` is a mock implementation of the `DataAvailabilityLayer` trait.
pub struct NoopDataAvailabilityLayer {}

#[async_trait]
impl DataAvailabilityLayer for NoopDataAvailabilityLayer {
    async fn get_latest_height(&self) -> DAResult<u64> {
        Ok(0)
    }

    async fn initialize_sync_target(&self) -> DAResult<u64> {
        Ok(0)
    }

    async fn get(&self, _: u64) -> DAResult<Vec<EpochJson>> {
        Ok(vec![])
    }

    async fn submit(&self, _: &EpochJson) -> DAResult<u64> {
        Ok(0)
    }

    async fn start(&self) -> DAResult<()> {
        Ok(())
    }
}

/// The `LocalDataAvailabilityLayer` is a mock implementation of the `DataAvailabilityLayer` trait.
/// It simulates the behavior of a data availability layer, storing and retrieving epoch-objects in-memory only.
/// This allows to write and test the functionality of systems that interact with a data availability layer without the need for an actual external service or network like we do with Celestia.
///
/// This implementation is intended for testing and development only and should not be used in production environments. It provides a way to test the interactions with the data availability layer without the overhead of real network communication or data persistence.
pub struct LocalDataAvailabilityLayer {}

impl LocalDataAvailabilityLayer {
    pub fn new() -> Self {
        LocalDataAvailabilityLayer {}
    }
}

#[async_trait]
impl DataAvailabilityLayer for LocalDataAvailabilityLayer {
    async fn get_latest_height(&self) -> DAResult<u64> {
        Ok(100)
    }

    async fn initialize_sync_target(&self) -> DAResult<u64> {
        Ok(0) // header starts always at zero in test cases
    }

    async fn get(&self, height: u64) -> DAResult<Vec<EpochJson>> {
        let mut file = File::open("data.json").expect("Unable to open file");
        let mut contents = String::new();
        file.lock_exclusive().expect("Unable to lock file");
        file.read_to_string(&mut contents)
            .expect("Unable to read file");

        let data: Value = serde_json::from_str(&contents).expect("Invalid JSON format");

        if let Some(epoch) = data.get(height.to_string()) {
            // convert arbit. json value to EpochJson
            let result_epoch: Result<EpochJson, _> = serde_json::from_value(epoch.clone());
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

    async fn submit(&self, epoch: &EpochJson) -> DAResult<u64> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("data.json")
            .expect("Unable to open file");

        let mut contents = String::new();

        file.lock_exclusive().expect("Unable to lock file");
        info!("file locked");

        file.read_to_string(&mut contents)
            .expect("Unable to read file");

        let mut data: Value = if contents.is_empty() {
            json!({})
        } else {
            serde_json::from_str(&contents).expect("Invalid JSON format")
        };

        // add new epoch to existing json-file data
        data[epoch.height.to_string()] = json!(epoch);

        // Reset the file pointer to the beginning of the file
        file.seek(std::io::SeekFrom::Start(0))
            .expect("Unable to seek to start");

        // Write the updated data into the file
        file.write_all(data.to_string().as_bytes())
            .expect("Unable to write file");

        // Truncate the file to the current pointer to remove any extra data
        file.set_len(data.to_string().as_bytes().len() as u64)
            .expect("Unable to set file length");

        file.unlock().expect("Unable to unlock file");
        info!("file unlocked");

        Ok(epoch.height)
    }

    async fn start(&self) -> DAResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        utils::validate_epoch,
        zk_snark::{BatchMerkleProofCircuit, Bls12Proof, VerifyingKey},
    };

    use super::*;
    use bellman::groth16;
    use bls12_381::Bls12;
    use indexed_merkle_tree::{
        node::Node,
        sha256,
        tree::{IndexedMerkleTree, Proof},
    };
    use rand::rngs::OsRng;
    use std::{
        fs::OpenOptions,
        io::{Error, Seek, SeekFrom},
    };

    const EMPTY_HASH: &str = Node::EMPTY_HASH;
    const TAIL: &str = Node::TAIL;

    pub fn clear_file(filename: &str) -> Result<(), Error> {
        // Open file for writing
        let mut file = OpenOptions::new().write(true).open(filename)?;

        // Set file length to 0 to delete all data in the file
        file.set_len(0)?;

        // Set pointer to the beginning of the file
        file.seek(SeekFrom::Start(0))?;

        Ok(())
    }

    fn build_empty_tree() -> IndexedMerkleTree {
        let active_node = Node::new_leaf(
            true,
            true,
            EMPTY_HASH.to_string(),
            EMPTY_HASH.to_string(),
            TAIL.to_string(),
        );
        let inactive_node = Node::new_leaf(
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
        ])
        .unwrap()
    }

    fn create_node(label: &str, value: &str) -> Node {
        let label = sha256(&label.to_string());
        let value = sha256(&value.to_string());
        Node::new_leaf(true, true, label, value, TAIL.to_string())
    }

    fn create_proof_and_vk(
        prev_commitment: String,
        current_commitment: String,
        proofs: Vec<Proof>,
    ) -> (Bls12Proof, VerifyingKey) {
        let batched_proof =
            BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs).unwrap();

        let rng = &mut OsRng;
        let params =
            groth16::generate_random_parameters::<Bls12, _, _>(batched_proof.clone(), rng).unwrap();
        let proof = groth16::create_random_proof(batched_proof.clone(), &params, rng).unwrap();

        // the serialized proof is posted
        (proof.into(), params.vk.into())
    }

    fn verify_epoch_json(epoch: Vec<EpochJson>) {
        for epoch_json in epoch {
            let prev_commitment = epoch_json.prev_commitment;
            let current_commitment = epoch_json.current_commitment;

            let proof = epoch_json.proof.clone().try_into().unwrap();
            let verifying_key = epoch_json.verifying_key.clone().try_into().unwrap();

            match validate_epoch(&prev_commitment, &current_commitment, proof, verifying_key) {
                Ok(_) => {
                    info!("\n\nvalidating epochs with commitments: [{}, {}]\n\n proof\n a: {},\n b: {},\n c: {}\n\n verifying key \n alpha_g1: {},\n beta_1: {},\n beta_2: {},\n delta_1: {},\n delta_2: {},\n gamma_2: {}\n", prev_commitment, current_commitment, &epoch_json.proof.a, &epoch_json.proof.b, &epoch_json.proof.c, &epoch_json.verifying_key.alpha_g1, &epoch_json.verifying_key.beta_g1, &epoch_json.verifying_key.beta_g2, &epoch_json.verifying_key.delta_g1, &epoch_json.verifying_key.delta_g2, &epoch_json.verifying_key.gamma_g2);
                }
                Err(err) => panic!("failed to validate epoch: {:?}", err),
            }
        }
    }

    #[tokio::test]
    async fn test_sequencer_and_light_client() {
        if let Err(e) = clear_file("data.json") {
            error!("deleting file: {}", e);
        }

        // simulate sequencer start
        let sequencer = tokio::spawn(async {
            let sequencer_layer = LocalDataAvailabilityLayer::new();
            // write all 60 seconds proofs and commitments
            // create a new tree
            let mut tree = build_empty_tree();
            let prev_commitment = tree.get_commitment().unwrap();

            // insert a first node
            let mut node_1 = create_node("test1", "test2");

            // generate proof for the first insert
            let first_insert_proof = tree.insert_node(&mut node_1).unwrap();
            let first_insert_zk_snark = Proof::Insert(first_insert_proof);

            // create bls12 proof for posting
            let (bls12proof, vk) = create_proof_and_vk(
                prev_commitment.clone(),
                tree.get_commitment().unwrap(),
                vec![first_insert_zk_snark],
            );

            sequencer_layer
                .submit(&EpochJson {
                    height: 1,
                    prev_commitment: prev_commitment,
                    current_commitment: tree.get_commitment().unwrap(),
                    proof: bls12proof,
                    verifying_key: vk,
                    signature: None,
                })
                .await
                .unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(65)).await;

            // update prev commitment
            let prev_commitment = tree.get_commitment().unwrap();

            // insert a second and third node
            let mut node_2 = create_node("test3", "test4");
            let mut node_3 = create_node("test5", "test6");

            // generate proof for the second and third insert
            let second_insert_proof = tree.insert_node(&mut node_2).unwrap();
            let third_insert_proof = tree.insert_node(&mut node_3).unwrap();
            let second_insert_zk_snark = Proof::Insert(second_insert_proof);
            let third_insert_zk_snark = Proof::Insert(third_insert_proof);

            // proof and vk
            let (proof, vk) = create_proof_and_vk(
                prev_commitment.clone(),
                tree.get_commitment().unwrap(),
                vec![second_insert_zk_snark, third_insert_zk_snark],
            );
            sequencer_layer
                .submit(&EpochJson {
                    height: 2,
                    prev_commitment: prev_commitment,
                    current_commitment: tree.get_commitment().unwrap(),
                    proof: proof,
                    verifying_key: vk,
                    signature: None,
                })
                .await
                .unwrap();
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
