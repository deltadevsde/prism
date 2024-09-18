use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ed25519::Signature;
use ed25519_dalek::{Signer, SigningKey};
use jmt::KeyHash;

use prism_common::{
    operation::{CreateAccountArgs, KeyOperationArgs},
    tree::{hash, Batch, Digest, Hasher, KeyDirectoryTree, Proof, SnarkableTree},
};
use std::{self, collections::VecDeque, str::FromStr, sync::Arc};
use tokio::sync::{broadcast, Mutex};

use sp1_sdk::{ProverClient, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

use crate::{
    cfg::Config,
    da::{DataAvailabilityLayer, FinalizedEpoch},
    node_types::NodeType,
    storage::Database,
    webserver::{OperationInput, WebServer},
};
use prism_common::{
    hashchain::{Hashchain, HashchainEntry},
    operation::{AccountSource, Operation},
};
use prism_errors::{DatabaseError, GeneralError};

pub const PRISM_ELF: &[u8] = include_bytes!("../../../../elf/riscv32im-succinct-zkvm-elf");

pub struct Sequencer {
    pub db: Arc<dyn Database>,
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub ws: WebServer,

    // [`start_height`] is the DA layer height the sequencer should start syncing operations from.
    pub start_height: u64,

    // [`key`] is the [`SigningKey`] used to sign [`Operation::CreateAccount`]s
    // (specifically, [`AccountSource::SignedBySequencer`]), as well as [`FinalizedEpoch`]s.
    pub key: SigningKey,

    // [`pending_operations`] is a buffer for operations that have not yet been
    // posted to the DA layer.
    pending_operations: Arc<Mutex<Vec<Operation>>>,
    tree: Arc<Mutex<KeyDirectoryTree<Box<dyn Database>>>>,
    prover_client: Arc<Mutex<ProverClient>>,

    proving_key: SP1ProvingKey,
    verifying_key: SP1VerifyingKey,
}

#[async_trait]
impl NodeType for Sequencer {
    async fn start(self: Arc<Self>) -> Result<()> {
        self.da.start().await.context("Failed to start DA layer")?;

        let main_loop = self.clone().main_loop();
        let batch_poster = self.clone().post_batch_loop();

        let ws_self = self.clone();
        let ws = ws_self.ws.start(self.clone());

        tokio::select! {
            res = main_loop => Ok(res.context("main loop failed")?),
            res = batch_poster => Ok(res.context("batch poster failed")?),
            res = ws => Ok(res.context("WebServer failed")?),
        }
    }
}

impl Sequencer {
    pub fn new(
        db: Arc<Box<dyn Database>>,
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: Config,
        key: SigningKey,
    ) -> Result<Sequencer> {
        let ws = cfg.webserver.context("Missing webserver configuration")?;
        let start_height = cfg.celestia_config.unwrap_or_default().start_height;

        // Create the KeyDirectory
        let tree = Arc::new(Mutex::new(KeyDirectoryTree::new(db.clone())));
        let prover_client = ProverClient::new();

        let (pk, vk) = prover_client.setup(PRISM_ELF);

        Ok(Sequencer {
            db: db.clone(),
            da,
            ws: WebServer::new(ws),
            proving_key: pk,
            verifying_key: vk,
            key,
            start_height,
            prover_client: Arc::new(Mutex::new(prover_client)),
            tree,
            pending_operations: Arc::new(Mutex::new(Vec::new())),
        })
    }

    async fn main_loop(self: Arc<Self>) -> Result<()> {
        let mut height_rx = self.da.subscribe_to_heights();
        let current_height = height_rx.recv().await?;
        let historical_sync_height = current_height - 1;

        self.sync_range(self.start_height, historical_sync_height)
            .await?;
        self.real_time_sync(height_rx).await
    }

    async fn sync_range(&self, start_height: u64, end_height: u64) -> Result<()> {
        let saved_epoch = match self.db.get_epoch() {
            Ok(epoch) => epoch,
            Err(_) => {
                debug!("no existing epoch state found, setting epoch to 0");
                self.db.set_epoch(&0)?;
                0
            }
        };
        let mut current_epoch: u64 = 0;
        let mut buffered_operations: VecDeque<Vec<Operation>> = VecDeque::new();
        let mut current_height = start_height;

        while current_height < end_height {
            let height = current_height + 1;
            let operations = self.da.get_operations(height).await?;
            let epoch_result = self.da.get_finalized_epoch(height).await?;

            self.process_height(
                height,
                operations,
                epoch_result,
                &mut current_epoch,
                &mut buffered_operations,
                saved_epoch,
            )
            .await?;

            current_height += 1;
        }

        info!(
            "finished historical sync from height {} to {}",
            start_height, end_height
        );
        Ok(())
    }

    async fn post_batch_loop(self: Arc<Self>) -> Result<()> {
        let mut height_rx = self.da.subscribe_to_heights();

        loop {
            let height = height_rx.recv().await?;
            debug!("received height {}", height);

            // Get pending operations
            let pending_operations = {
                let mut ops = self.pending_operations.lock().await;
                std::mem::take(&mut *ops)
            };

            let op_count = pending_operations.len();

            // If there are pending operations, submit them
            if !pending_operations.clone().is_empty() {
                match self.da.submit_operations(pending_operations).await {
                    Ok(submitted_height) => {
                        info!(
                            "post_batch_loop: submitted {} operations at height {}",
                            op_count, submitted_height
                        );
                    }
                    Err(e) => {
                        error!("post_batch_loop: Failed to submit operations: {}", e);
                    }
                }
            } else {
                debug!(
                    "post_batch_loop: No pending operations to submit at height {}",
                    height
                );
            }
        }
    }

    async fn real_time_sync(&self, mut height_rx: broadcast::Receiver<u64>) -> Result<()> {
        let saved_epoch = self.db.get_epoch()?;
        let mut current_epoch: u64 = saved_epoch;
        let mut buffered_operations: VecDeque<Vec<Operation>> = VecDeque::new();

        loop {
            let height = height_rx.recv().await?;
            let operations = self.da.get_operations(height).await?;
            let epoch_result = self.da.get_finalized_epoch(height).await?;

            self.process_height(
                height,
                operations,
                epoch_result,
                &mut current_epoch,
                &mut buffered_operations,
                saved_epoch,
            )
            .await?;
        }
    }

    async fn process_height(
        &self,
        height: u64,
        operations: Vec<Operation>,
        epoch_result: Option<FinalizedEpoch>,
        current_epoch: &mut u64,
        buffered_operations: &mut VecDeque<Vec<Operation>>,
        saved_epoch: u64,
    ) -> Result<()> {
        let mut tree = self.tree.lock().await;
        let prev_commitment = tree.get_commitment()?;

        debug!(
            "processing height {}, saved_epoch: {}, current_epoch: {}",
            height, saved_epoch, current_epoch
        );

        if !operations.is_empty() {
            buffered_operations.push_back(operations);
        }

        if !buffered_operations.is_empty() && height > saved_epoch {
            let all_ops: Vec<Operation> = buffered_operations.drain(..).flatten().collect();
            *current_epoch = height;
            self.finalize_new_epoch(*current_epoch, all_ops, &mut tree)
                .await?;
        } else if let Some(epoch) = epoch_result {
            self.process_existing_epoch(
                epoch,
                current_epoch,
                buffered_operations,
                &mut tree,
                prev_commitment,
                height,
            )
            .await?;
        } else {
            debug!("No operations to process at height {}", height);
        }

        Ok(())
    }

    async fn process_existing_epoch(
        &self,
        epoch: FinalizedEpoch,
        current_epoch: &mut u64,
        buffered_operations: &mut VecDeque<Vec<Operation>>,
        tree: &mut KeyDirectoryTree<Box<dyn Database>>,
        prev_commitment: Digest,
        height: u64,
    ) -> Result<()> {
        if epoch.height != *current_epoch {
            return Err(anyhow!(
                "Epoch height mismatch: expected {}, got {}",
                current_epoch,
                epoch.height
            ));
        }
        if epoch.prev_commitment != prev_commitment {
            return Err(anyhow!("Commitment mismatch at epoch {}", current_epoch));
        }

        while let Some(buffered_ops) = buffered_operations.pop_front() {
            self.execute_block(buffered_ops, tree).await?;
        }

        let new_commitment = tree.get_commitment()?;
        if epoch.current_commitment != new_commitment {
            return Err(anyhow!("Commitment mismatch at epoch {}", current_epoch));
        }

        debug!(
            "Processed height {}. New commitment: {:?}",
            height, new_commitment
        );
        *current_epoch += 1;
        Ok(())
    }

    async fn execute_block(
        &self,
        operations: Vec<Operation>,
        tree: &mut KeyDirectoryTree<Box<dyn Database>>,
    ) -> Result<Vec<Proof>> {
        debug!("executing block with {} operations", operations.len());

        let mut proofs = Vec::new();

        for operation in operations {
            match self.process_operation(&operation, tree).await {
                Ok(proof) => proofs.push(proof),
                Err(e) => {
                    // Log the error and continue with the next operation
                    warn!("Failed to process operation: {:?}. Error: {}", operation, e);
                }
            }
        }

        Ok(proofs)
    }

    async fn finalize_new_epoch(
        &self,
        height: u64,
        operations: Vec<Operation>,
        tree: &mut KeyDirectoryTree<Box<dyn Database>>,
    ) -> Result<()> {
        let prev_commitment = tree.get_commitment()?;

        let proofs = self.execute_block(operations, tree).await?;

        let new_commitment = tree.get_commitment()?;

        let finalized_epoch = self
            .prove_epoch(height, prev_commitment, new_commitment, proofs)
            .await?;

        self.da.submit_finalized_epoch(finalized_epoch).await?;

        self.db.set_commitment(&height, &new_commitment)?;
        self.db.set_epoch(&height)?;

        info!("Finalized new epoch at height {}", height);

        Ok(())
    }

    async fn prove_epoch(
        &self,
        height: u64,
        prev_commitment: Digest,
        new_commitment: Digest,
        proofs: Vec<Proof>,
    ) -> Result<FinalizedEpoch> {
        let batch = Batch {
            prev_root: prev_commitment,
            new_root: new_commitment,
            proofs,
        };

        let mut stdin = SP1Stdin::new();
        stdin.write(&batch);

        let client = self.prover_client.lock().await;

        info!("generating proof for epoch height {}", height);
        #[cfg(not(feature = "plonk"))]
        let proof = client.prove(&self.proving_key, stdin).run()?;

        #[cfg(feature = "plonk")]
        let proof = client.prove(&self.proving_key, stdin).plonk().run()?;
        info!("successfully generated proof for epoch height {}", height);

        client.verify(&proof, &self.verifying_key)?;
        info!("verified proof for epoch height {}", height);

        let epoch_json = FinalizedEpoch {
            height,
            prev_commitment,
            current_commitment: new_commitment,
            proof,
            signature: None,
        };

        let serialized_epoch_json_without_signature =
            bincode::serialize(&epoch_json).context("Failed to serialize epoch json")?;
        let signature = self
            .key
            .sign(serialized_epoch_json_without_signature.as_slice())
            .to_string();
        let mut epoch_json_with_signature = epoch_json;
        epoch_json_with_signature.signature = Some(signature.clone());
        Ok(epoch_json_with_signature)
    }

    pub async fn get_commitment(&self) -> Result<Digest> {
        let tree = self.tree.lock().await;
        tree.get_commitment().context("Failed to get commitment")
    }

    /// Updates the state from an already verified pending operation.
    async fn process_operation(
        &self,
        operation: &Operation,
        tree: &mut KeyDirectoryTree<Box<dyn Database>>,
    ) -> Result<Proof> {
        match operation {
            Operation::AddKey(KeyOperationArgs {
                id,
                value,
                signature,
            })
            | Operation::RevokeKey(KeyOperationArgs {
                id,
                value,
                signature,
            }) => {
                // verify that the hashchain already exists
                let mut current_chain = self
                    .db
                    .get_hashchain(id)
                    .context(format!("Failed to get hashchain for ID {}", id))?;

                let hashed_id = hash(id.as_bytes());

                let previous_hash = current_chain.last().context("Hashchain is empty")?.hash;

                let new_chain_entry = HashchainEntry::new(operation.clone(), previous_hash);
                current_chain.push(new_chain_entry.operation.clone())?;

                debug!("updating hashchain for user id {}", id.clone());
                let proof =
                    tree.update(KeyHash::with::<Hasher>(hashed_id), current_chain.clone())?;
                self.db
                    .set_hashchain(operation, &current_chain)
                    .context(format!(
                        "Failed to update hashchain for operation {:?}",
                        operation
                    ))?;

                Ok(Proof::Update(proof))
            }
            Operation::CreateAccount(CreateAccountArgs {
                id,
                value,
                service_id,
                challenge,
            }) => {
                // validation of account source
                match challenge {
                    // TODO: use Signature, not String
                    AccountSource::SignedBySequencer { signature } => {
                        let sig = Signature::from_str(signature)
                            .context("Failed to parse sequencer's signature")?;
                        self.key
                            .verify(format!("{}{}", id, value).as_bytes(), &sig)
                            .map_err(GeneralError::InvalidSignature)
                    }
                }?;

                let hashchain: Result<Hashchain> = self.db.get_hashchain(id);
                if hashchain.is_ok() {
                    return Err(DatabaseError::NotFoundError(format!(
                        "empty slot for ID {}",
                        id.clone()
                    ))
                    .into());
                }

                debug!("creating new hashchain for user id {}", id.clone());
                let mut chain = Hashchain::new(id.clone());
                chain.create_account(value.into(), source.clone())?;

                self.db.set_hashchain(operation, &chain).context(format!(
                    "Failed to create hashchain for operation {:?}",
                    operation
                ))?;

                let hashed_id = hash(id.as_bytes());

                Ok(Proof::Insert(
                    tree.insert(KeyHash::with::<Hasher>(hashed_id), chain)?,
                ))
            }
        }
    }

    /// Adds an operation to be posted to the DA layer and applied in the next epoch.
    pub async fn validate_and_queue_update(
        self: Arc<Self>,
        incoming_operation: &OperationInput,
    ) -> Result<()> {
        // TODO: this is only basic validation. The validation over if an entry can be added to the hashchain or not is done in the process_operation function
        incoming_operation.validate()?;
        let mut pending = self.pending_operations.lock().await;
        pending.push(incoming_operation.operation.clone());
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cfg::{Config, RedisConfig},
        da::memory::InMemoryDataAvailabilityLayer,
        storage::RedisConnection,
    };
    use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
    use keystore_rs::create_signing_key;
    use prism_common::operation::PublicKey;
    use prism_common::test_utils::TestTreeState;
    use serial_test::serial;

    // Helper function to set up redis connection and flush database before each test
    fn setup_db() -> RedisConnection {
        let redis_connection = RedisConnection::new(&RedisConfig::default()).unwrap();
        redis_connection.flush_database().unwrap();
        redis_connection
    }

    // Helper function to flush database after each test
    fn teardown_db(redis_connection: Arc<dyn Database>) {
        redis_connection.flush_database().unwrap();
    }

    // Helper function to create a test Sequencer instance
    async fn create_test_sequencer() -> Arc<Sequencer> {
        let (da_layer, _rx, _brx) = InMemoryDataAvailabilityLayer::new(1);
        let da_layer = Arc::new(da_layer);
        let db: Arc<Box<dyn Database>> = Arc::new(Box::new(setup_db()));
        let signing_key = create_signing_key();
        Arc::new(
            Sequencer::new(db.clone(), da_layer, Config::default(), signing_key.clone()).unwrap(),
        )
    }

    // fn create_new_account_operation(id: String, value: String, key: &SigningKey) -> OperationInput {
    //     let incoming = Operation::CreateAccount {
    //         id: id.clone(),
    //         value: value.clone(),
    //         source: AccountSource::SignedBySequencer {
    //             signature: key.sign(format!("{}{}", id, value).as_bytes()).to_string(),
    //         },
    //     };
    //     let content = serde_json::to_string(&incoming).unwrap();
    //     let sig = key.sign(content.clone().as_bytes());

    //     OperationInput {
    //         operation: incoming,
    //         signed_operation: sig.to_string(),
    //         public_key: engine.encode(key.verifying_key().to_bytes()),
    //     }
    // }

    // fn create_update_operation(id: String, value: PublicKey) -> OperationInput {
    //     let key = create_signing_key();
    //     let incoming = Operation::AddKey(KeyOperationArgs {
    //         id: id.clone(),
    //         value: value.clone(),
    //         signature: unimplemented!("signature"),
    //     });
    //     let content = serde_json::to_string(&incoming).unwrap();
    //     let sig = key.sign(content.clone().as_bytes());

    //     OperationInput {
    //         operation: incoming,
    //         signed_operation: sig.to_string(),
    //         public_key: engine.encode(key.verifying_key().to_bytes()),
    //     }
    // }

    #[tokio::test]
    #[serial]
    async fn test_validate_and_queue_update() {
        let test_tree = TestTreeState::default();
        let sequencer = create_test_sequencer().await;

        let update_entry =
            create_update_operation("test@example.com".to_string(), "test".to_string());

        let (keyhash, hashchain) = test_tree.create_account();
        let update_key = OperationInput {

        }

        sequencer
            .clone()
            .validate_and_queue_update(&update_entry)
            .await
            .unwrap();

        let pending_ops = sequencer.pending_operations.lock().await;
        assert_eq!(pending_ops.len(), 1);

        teardown_db(sequencer.db.clone());
    }

    #[tokio::test]
    #[serial]
    async fn test_process_operation() {
        let sequencer = create_test_sequencer().await;
        let mut tree = sequencer.tree.lock().await;

        // Test CreateAccount operation
        let create_op = create_new_account_operation(
            "user@example.com".to_string(),
            "initial".to_string(),
            &sequencer.key,
        )
        .operation;
        let proof = sequencer
            .process_operation(&create_op, &mut tree)
            .await
            .unwrap();
        assert!(matches!(proof, Proof::Insert(_)));

        let pub_key = create_signing_key().verifying_key().to_bytes().to_vec();

        // Then, add a new value
        let add_op = Operation::AddKey(KeyOperationArgs {
            id: "user@example.com".to_string(),
            value: PublicKey::Ed25519(pub_key),
            signature: unimplemented!("signature"),
        });
        let proof = sequencer
            .process_operation(&add_op, &mut tree)
            .await
            .unwrap();

        assert!(matches!(proof, Proof::Update(_)));

        // Test Revoke operation
        let revoke_op = Operation::RevokeKey(KeyOperationArgs {
            id: "user@example.com".to_string(),
            value: "new_value".to_string(),
            signature: unimplemented!("signature"),
        });
        let proof = sequencer
            .process_operation(&revoke_op, &mut tree)
            .await
            .unwrap();
        assert!(matches!(proof, Proof::Update(_)));

        teardown_db(sequencer.db.clone());
    }

    #[tokio::test]
    #[serial]
    async fn test_execute_block() {
        let sequencer = create_test_sequencer().await;
        let mut tree = sequencer.tree.lock().await;

        let operations = vec![
            create_new_account_operation(
                "user1@example.com".to_string(),
                "value1".to_string(),
                &sequencer.key,
            )
            .operation,
            create_new_account_operation(
                "user2@example.com".to_string(),
                "value2".to_string(),
                &sequencer.key,
            )
            .operation,
            Operation::Add {
                id: "user1@example.com".to_string(),
                value: "new_value1".to_string(),
            },
        ];

        let proofs = sequencer
            .execute_block(operations, &mut tree)
            .await
            .unwrap();
        assert_eq!(proofs.len(), 3);

        teardown_db(sequencer.db.clone());
    }

    #[tokio::test]
    #[serial]
    async fn test_finalize_new_epoch() {
        let sequencer = create_test_sequencer().await;
        let mut tree = sequencer.tree.lock().await;

        let operations = vec![
            create_new_account_operation(
                "user1@example.com".to_string(),
                "value1".to_string(),
                &sequencer.key,
            )
            .operation,
            create_new_account_operation(
                "user2@example.com".to_string(),
                "value2".to_string(),
                &sequencer.key,
            )
            .operation,
        ];

        let prev_commitment = tree.get_commitment().unwrap();
        sequencer
            .finalize_new_epoch(0, operations, &mut tree)
            .await
            .unwrap();

        let new_commitment = tree.get_commitment().unwrap();
        assert_ne!(prev_commitment, new_commitment);

        teardown_db(sequencer.db.clone());
    }
}
