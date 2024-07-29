use anyhow::Context;
use async_trait::async_trait;
use ed25519::Signature;
use ed25519_dalek::{Signer, SigningKey};
use indexed_merkle_tree::{
    node::Node,
    sha256_mod,
    tree::{IndexedMerkleTree, Proof},
    Hash,
};
use std::{self, str::FromStr, sync::Arc};
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::spawn,
    time::interval,
};

#[cfg(test)]
use crate::error::DataAvailabilityError;

use crate::{
    cfg::Config,
    common::{AccountSource, HashchainEntry, Operation},
    consts::{CHANNEL_BUFFER_SIZE, DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    da::{DataAvailabilityLayer, FinalizedEpoch},
    error::{DatabaseError, GeneralError, PrismError, PrismResult},
    node_types::NodeType,
    storage::Database,
    webserver::{OperationInput, WebServer},
    zk_snark::BatchMerkleProofCircuit,
};

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
    tree: Arc<Mutex<IndexedMerkleTree>>,

    epoch_buffer_tx: Arc<Sender<FinalizedEpoch>>,
    epoch_buffer_rx: Arc<Mutex<Receiver<FinalizedEpoch>>>,
}

#[async_trait]
impl NodeType for Sequencer {
    async fn start(self: Arc<Self>) -> PrismResult<()> {
        self.da.start().await.context("Failed to start DA layer")?;

        let sync_loop = self.clone().sync_loop();
        let da_loop = self.clone().da_loop();

        let ws_self = self.clone();
        let ws = ws_self.ws.start(self.clone());

        tokio::select! {
            res = sync_loop => Ok(res.context("sync loop failed")?),
            res = da_loop => Ok(res.context("DA loop failed")?),
            res = ws => Ok(res.context("WebServer failed")?),
        }
    }
}

impl Sequencer {
    pub fn new(
        db: Arc<dyn Database>,
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: Config,
        key: SigningKey,
    ) -> PrismResult<Sequencer> {
        let (tx, rx) = channel(CHANNEL_BUFFER_SIZE);

        let ws = cfg.webserver.context("Missing webserver configuration")?;

        let start_height = cfg.celestia_config.unwrap_or_default().start_height;

        Ok(Sequencer {
            db,
            da,
            ws: WebServer::new(ws),
            key,
            start_height,
            tree: Arc::new(Mutex::new(IndexedMerkleTree::new_with_size(1024).unwrap())),
            pending_operations: Arc::new(Mutex::new(Vec::new())),
            epoch_buffer_tx: Arc::new(tx),
            epoch_buffer_rx: Arc::new(Mutex::new(rx)),
        })
    }

    // sync_loop is responsible for downloading operations from the DA layer
    async fn sync_loop(self: Arc<Self>) -> Result<(), tokio::task::JoinError> {
        info!("starting operation sync loop");
        let epoch_buffer = self.epoch_buffer_tx.clone();
        spawn(async move {
            let mut current_position = self.start_height;
            loop {
                // target is updated when a new header is received
                let target = match self.da.get_latest_height().await {
                    Ok(target) => target,
                    Err(e) => {
                        error!("failed to update sync target, retrying: {:?}", e);
                        continue;
                    }
                };

                debug!("updated sync target to height {}", target);
                while current_position < target {
                    trace!("processing height: {}", current_position);
                    match self.da.get_operations(current_position + 1).await {
                        Ok(operations) => {
                            if !operations.is_empty() {
                                debug!(
                                    "sequencer: got operations at height {}",
                                    current_position + 1
                                );
                            }

                            let epoch = match self.finalize_epoch(operations).await {
                                Ok(e) => e,
                                Err(e) => {
                                    error!("sequencer_loop: finalizing epoch: {}", e);
                                    continue;
                                }
                            };

                            info!("sequencer_loop: finalized epoch {}", epoch.height);
                            match epoch_buffer.send(epoch).await {
                                Ok(_) => {
                                    current_position += 1;
                                }
                                Err(e) => {
                                    error!("sequencer_loop: sending epoch to buffer: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            debug!("light client: getting epoch: {}", e)
                        }
                    };
                }
                current_position = target; // Update the current position to the latest target
            }
        })
        .await
    }

    // da_loop is responsible for submitting finalized epochs to the DA layer.
    async fn da_loop(self: Arc<Self>) -> Result<(), tokio::task::JoinError> {
        info!("starting da submission loop");
        let mut ticker = interval(DA_RETRY_INTERVAL);
        spawn(async move {
            loop {
                let epochs = match self.receive_finalized_epochs().await {
                    Ok(epochs) => epochs,
                    Err(e) => {
                        error!("da_loop: getting finalized epochs: {}", e);
                        continue;
                    }
                };

                let mut retry_counter = 0;
                loop {
                    if retry_counter > DA_RETRY_COUNT {
                        // todo: graceful shutdown
                        panic!("da_loop: too many retries, giving up");
                    }
                    match self.da.submit_snarks(epochs.clone()).await {
                        Ok(height) => {
                            info!("da_loop: submitted epoch at height {}", height);
                            break;
                        }
                        Err(e) => {
                            // code = NotFound means the account is not funded
                            if e.to_string().contains("rpc error: code = NotFound") {
                                panic!("da_loop: celestia account not funded, causing: {}", e);
                            }
                            error!("da_loop: submitting epoch: {}", e);
                            retry_counter += 1;
                        }
                    };
                    ticker.tick().await;
                }
            }
        })
        .await
    }

    pub async fn get_commitment(&self) -> PrismResult<Hash> {
        let tree = self.tree.lock().await;
        tree.get_commitment()
            .context("Failed to get commitment")
            .map_err(|e| e.into())
    }

    // finalize_epoch is responsible for finalizing the pending epoch and returning the epoch json to be posted on the DA layer.
    pub async fn finalize_epoch(&self, operations: Vec<Operation>) -> PrismResult<FinalizedEpoch> {
        let epoch = match self.db.get_epoch() {
            Ok(epoch) => epoch + 1,
            Err(_) => 0,
        };

        let prev_commitment = if epoch > 0 {
            let prev_epoch = epoch - 1;
            let hash_string = self.db.get_commitment(&prev_epoch).context(format!(
                "Failed to get commitment for previous epoch {}",
                prev_epoch
            ))?;
            Hash::from_hex(&hash_string).context("Failed to parse commitment")?
        } else {
            self.get_commitment().await?
        };

        let mut proofs = Vec::new();
        for entry in operations.iter() {
            let proof = self.process_operation(entry).await?;
            proofs.push(proof);
        }

        let current_commitment = {
            let tree = self.tree.lock().await;
            tree.get_commitment()
                .context("Failed to get current commitment")?
        };

        self.db
            .set_epoch(&epoch)
            .context("Failed to set new epoch")?;
        // add the commitment for the operations ran since the last epoch
        self.db
            .add_commitment(&epoch, &current_commitment)
            .context("Failed to add commitment for new epoch")?;

        let batch_circuit =
            BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs)
                .context("Failed to create BatchMerkleProofCircuit")?;
        let (proof, verifying_key) = batch_circuit
            .create_and_verify_snark()
            .context("Failed to create and verify snark")?;

        let epoch_json = FinalizedEpoch {
            height: epoch,
            prev_commitment,
            current_commitment,
            proof: proof.into(),
            verifying_key: verifying_key.into(),
            signature: None,
        };

        let serialized_epoch_json_without_signature =
            borsh::to_vec(&epoch_json).context("Failed to serialize epoch json")?;
        let signature = self
            .key
            .sign(serialized_epoch_json_without_signature.as_slice())
            .to_string();
        let mut epoch_json_with_signature = epoch_json;
        epoch_json_with_signature.signature = Some(signature.clone());
        Ok(epoch_json_with_signature)
    }

    // receive_finalized_epochs empties the epoch buffer into a vector and returns it.
    async fn receive_finalized_epochs(&self) -> PrismResult<Vec<FinalizedEpoch>> {
        let mut epochs = Vec::new();
        let mut receiver = self.epoch_buffer_rx.lock().await;

        while let Ok(epoch) = receiver.try_recv() {
            epochs.push(epoch);
        }

        Ok(epochs)
    }

    #[cfg(test)]
    pub async fn send_finalized_epoch(&self, epoch: &FinalizedEpoch) -> PrismResult<()> {
        self.epoch_buffer_tx
            .send(epoch.clone())
            .await
            .map_err(|_| DataAvailabilityError::ChannelClosed.into())
    }

    /// Updates the state from an already verified pending operation.
    async fn process_operation(&self, operation: &Operation) -> PrismResult<Proof> {
        match operation {
            Operation::Add { id, .. } | Operation::Revoke { id, .. } => {
                // verify that the hashchain already exists
                let mut current_chain = self
                    .db
                    .get_hashchain(id)
                    .context(format!("Failed to get hashchain for ID {}", id))?;

                let mut tree = self.tree.lock().await;
                let hashed_id = sha256_mod(id.as_bytes());

                let node = tree.find_leaf_by_label(&hashed_id).context(format!(
                    "Node with label {} not found in the tree",
                    hashed_id
                ))?;

                let previous_hash = current_chain.last().context("Hashchain is empty")?.hash;

                let new_chain_entry = HashchainEntry::new(operation.clone(), previous_hash);
                current_chain.push(new_chain_entry.clone());

                let updated_node = Node::new_leaf(
                    node.is_left_sibling(),
                    hashed_id,
                    new_chain_entry.hash,
                    node.get_next(),
                );

                let index = tree.find_node_index(&node).context(format!(
                    "Node with label {} not found in the tree, but has a hashchain entry",
                    hashed_id
                ))?;

                self.db
                    .update_hashchain(operation, &current_chain)
                    .context(format!(
                        "Failed to update hashchain for operation {:?}",
                        operation
                    ))?;

                tree.update_node(index, updated_node)
                    .map(Proof::Update)
                    .context("Failed to update node in tree")
                    .map_err(|e| e.into())
            }
            Operation::CreateAccount { id, value, source } => {
                // validation of account source
                match source {
                    // TODO: use Signature, not String
                    AccountSource::SignedBySequencer { signature } => {
                        let sig = Signature::from_str(signature)
                            .context("Failed to parse sequencer's signature")?;
                        self.key
                            .verify(format!("{}{}", id, value).as_bytes(), &sig)
                            .map_err(|e| PrismError::General(GeneralError::InvalidSignature(e)))
                    }
                }?;

                let hashchain: PrismResult<Vec<HashchainEntry>> = self.db.get_hashchain(id);
                if hashchain.is_ok() {
                    return Err(DatabaseError::NotFoundError(format!(
                        "empty slot for ID {}",
                        id.clone()
                    ))
                    .into());
                }

                debug!("creating new hashchain for user id {}", id.clone());
                let new_chain = vec![HashchainEntry::new(operation.clone(), Node::HEAD)];

                self.db
                    .update_hashchain(operation, &new_chain)
                    .context(format!(
                        "Failed to create hashchain for operation {:?}",
                        operation
                    ))?;

                let mut tree = self.tree.lock().await;
                let hashed_id = sha256_mod(id.as_bytes());

                let mut node =
                    Node::new_leaf(true, hashed_id, new_chain.first().unwrap().hash, Node::TAIL);
                tree.insert_node(&mut node)
                    .map(Proof::Insert)
                    .context("Failed to insert node into tree")
                    .map_err(|e| e.into())
            }
        }
    }

    /// Adds an operation to be posted to the DA layer and applied in the next epoch.
    pub async fn validate_and_queue_update(
        self: Arc<Self>,
        incoming_operation: &OperationInput,
    ) -> PrismResult<()> {
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
        da::mock::LocalDataAvailabilityLayer,
        storage::RedisConnection,
    };
    use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
    use keystore_rs::create_signing_key;
    use serial_test::serial;

    // set up redis connection and flush database before each test
    fn setup_db() -> RedisConnection {
        let redis_connection = RedisConnection::new(&RedisConfig::default()).unwrap();
        redis_connection.flush_database().unwrap();
        redis_connection
    }

    // flush database after each test
    fn teardown_db(redis_connections: &RedisConnection) {
        redis_connections.flush_database().unwrap();
    }

    // Helper function to create a test Sequencer instance
    async fn create_test_sequencer() -> Arc<Sequencer> {
        let da_layer = Arc::new(LocalDataAvailabilityLayer::new());
        let db = Arc::new(setup_db());
        let signing_key = create_signing_key();
        Arc::new(
            Sequencer::new(db.clone(), da_layer, Config::default(), signing_key.clone()).unwrap(),
        )
    }

    fn create_new_account_operation(id: String, value: String, key: SigningKey) -> OperationInput {
        let incoming = Operation::CreateAccount {
            id: id.clone(),
            value: value.clone(),
            source: AccountSource::SignedBySequencer {
                signature: key.sign(format!("{}{}", id, value).as_bytes()).to_string(),
            },
        };
        let content = serde_json::to_string(&incoming).unwrap();
        let sig = key.sign(content.clone().as_bytes());

        OperationInput {
            operation: incoming,
            signed_operation: sig.to_string(),
            public_key: engine.encode(key.verifying_key().to_bytes()),
        }
    }

    fn create_update_operation(id: String, value: String) -> OperationInput {
        let key = create_signing_key();
        let incoming = Operation::Add { id, value };
        let content = serde_json::to_string(&incoming).unwrap();
        let sig = key.sign(content.clone().as_bytes());

        OperationInput {
            operation: incoming,
            signed_operation: sig.to_string(),
            public_key: engine.encode(key.verifying_key().to_bytes()),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_validate_and_queue_update() {
        let da_layer = Arc::new(LocalDataAvailabilityLayer::new());
        let db = Arc::new(setup_db());
        let sequencer = Arc::new(
            Sequencer::new(
                db.clone(),
                da_layer,
                Config::default(),
                create_signing_key(),
            )
            .unwrap(),
        );

        let update_entry =
            create_update_operation("test@deltadevs.xyz".to_string(), "test".to_string());

        sequencer
            .validate_and_queue_update(&update_entry)
            .await
            .unwrap();
        teardown_db(&db);
    }

    #[tokio::test]
    #[serial]
    async fn test_queued_update_gets_finalized() {
        let da_layer = Arc::new(LocalDataAvailabilityLayer::new());
        let db = Arc::new(setup_db());
        let signing_key = create_signing_key();
        let sequencer = Arc::new(
            Sequencer::new(db.clone(), da_layer, Config::default(), signing_key.clone()).unwrap(),
        );

        let id = "test@deltadevs.xyz".to_string();
        let update_entry =
            create_new_account_operation(id.clone(), "test".to_string(), signing_key.clone());

        println!("update_entry: {:?}", update_entry);

        sequencer
            .clone()
            .validate_and_queue_update(&update_entry)
            .await
            .unwrap();

        // hashchain doesn't exist yet, because operation is only queued
        let hashchain = sequencer.db.get_hashchain(id.as_str());
        assert!(hashchain.is_err());

        let pending_operations = sequencer.pending_operations.lock().await.clone();
        let prev_commitment = sequencer.get_commitment().await.unwrap();
        sequencer.finalize_epoch(pending_operations).await.unwrap();
        let new_commitment = sequencer.get_commitment().await.unwrap();
        assert_ne!(prev_commitment, new_commitment);

        let hashchain = sequencer.db.get_hashchain(id.as_str());
        let value = hashchain.unwrap().first().unwrap().operation.value();
        assert_eq!(value, "test");

        teardown_db(&db);
    }

    #[tokio::test]
    #[serial]
    async fn test_validate_invalid_update_fails() {
        let da_layer = Arc::new(LocalDataAvailabilityLayer::new());
        let db = Arc::new(setup_db());
        let sequencer = Arc::new(
            Sequencer::new(
                db.clone(),
                da_layer,
                Config::default(),
                create_signing_key(),
            )
            .unwrap(),
        );

        let mut update_entry =
            create_update_operation("test@deltadevs.xyz".to_string(), "test".to_string());
        let second_signer =
            create_update_operation("abcd".to_string(), "test".to_string()).public_key;
        update_entry.public_key = second_signer;

        let res = sequencer.validate_and_queue_update(&update_entry).await;
        assert!(res.is_err());
        teardown_db(&db);
    }

    #[tokio::test]
    #[serial]
    async fn test_finalize_epoch_first_epoch() {
        let sequencer = create_test_sequencer().await;
        let operations = vec![
            create_new_account_operation(
                "user1@example.com".to_string(),
                "value1".to_string(),
                sequencer.key.clone(),
            )
            .operation,
            create_new_account_operation(
                "user2@example.com".to_string(),
                "value2".to_string(),
                sequencer.key.clone(),
            )
            .operation,
        ];

        let prev_commitment = sequencer.get_commitment().await.unwrap();
        let epoch = sequencer.finalize_epoch(operations).await.unwrap();
        assert_eq!(epoch.height, 0);
        assert_eq!(epoch.prev_commitment, prev_commitment);
        assert_eq!(
            epoch.current_commitment,
            sequencer.get_commitment().await.unwrap()
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_finalize_epoch_multiple_epochs() {
        let sequencer = create_test_sequencer().await;

        // First epoch
        let operations1 = vec![
            create_new_account_operation(
                "user1@example.com".to_string(),
                "value1".to_string(),
                sequencer.key.clone(),
            )
            .operation,
        ];
        let epoch1 = sequencer.finalize_epoch(operations1).await.unwrap();

        // Second epoch
        let operations2 = vec![
            create_new_account_operation(
                "user2@example.com".to_string(),
                "value2".to_string(),
                sequencer.key.clone(),
            )
            .operation,
        ];
        let epoch2 = sequencer.finalize_epoch(operations2).await.unwrap();

        assert_eq!(epoch2.height, 1);
        assert_eq!(epoch2.prev_commitment, epoch1.current_commitment);
    }

    #[tokio::test]
    #[serial]
    async fn test_process_operation_add() {
        let sequencer = create_test_sequencer().await;

        // First, create an account
        let create_op = create_new_account_operation(
            "user@example.com".to_string(),
            "initial".to_string(),
            sequencer.key.clone(),
        )
        .operation;
        sequencer.process_operation(&create_op).await.unwrap();

        // Then, add a new value
        let add_op = Operation::Add {
            id: "user@example.com".to_string(),
            value: "new_value".to_string(),
        };
        let proof = sequencer.process_operation(&add_op).await.unwrap();

        assert!(matches!(proof, Proof::Update(_)));

        let hashchain = sequencer.db.get_hashchain("user@example.com").unwrap();
        assert_eq!(hashchain.len(), 2);
        assert_eq!(hashchain[1].operation.value(), "new_value");
    }

    #[tokio::test]
    #[serial]
    async fn test_process_operation_revoke() {
        let sequencer = create_test_sequencer().await;

        // First, create an account
        let create_op = create_new_account_operation(
            "user@example.com".to_string(),
            "initial".to_string(),
            sequencer.key.clone(),
        )
        .operation;
        sequencer.process_operation(&create_op).await.unwrap();

        // Then, revoke a value
        let revoke_op = Operation::Revoke {
            id: "user@example.com".to_string(),
            value: "initial".to_string(),
        };
        let proof = sequencer.process_operation(&revoke_op).await.unwrap();

        assert!(matches!(proof, Proof::Update(_)));

        let hashchain = sequencer.db.get_hashchain("user@example.com").unwrap();
        assert_eq!(hashchain.len(), 2);
        assert!(matches!(hashchain[1].operation, Operation::Revoke { .. }));
    }

    #[tokio::test]
    #[serial]
    async fn test_process_operation_create_account_duplicate() {
        let sequencer = create_test_sequencer().await;

        // Create an account
        let create_op = create_new_account_operation(
            "user@example.com".to_string(),
            "initial".to_string(),
            sequencer.key.clone(),
        )
        .operation;
        sequencer.process_operation(&create_op).await.unwrap();

        // Try to create the same account again
        let result = sequencer.process_operation(&create_op).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_receive_finalized_epochs() {
        let sequencer = create_test_sequencer().await;

        // Create some realistic operations
        let op1 = create_new_account_operation(
            "user1@example.com".to_string(),
            "value1".to_string(),
            sequencer.key.clone(),
        )
        .operation;
        let op2 = create_new_account_operation(
            "user2@example.com".to_string(),
            "value2".to_string(),
            sequencer.key.clone(),
        )
        .operation;
        let op3 = Operation::Add {
            id: "user1@example.com".to_string(),
            value: "new_value1".to_string(),
        };

        // Create FinalizedEpoch instances
        let epoch1 = sequencer.finalize_epoch(vec![op1]).await.unwrap();
        let epoch2 = sequencer.finalize_epoch(vec![op2, op3]).await.unwrap();

        // Send the epochs to the sequencer
        sequencer.send_finalized_epoch(&epoch1).await.unwrap();
        sequencer.send_finalized_epoch(&epoch2).await.unwrap();

        // Receive and verify the epochs
        let received_epochs = sequencer.receive_finalized_epochs().await.unwrap();
        assert_eq!(received_epochs.len(), 2);

        // Verify first epoch
        assert_eq!(received_epochs[0].height, epoch1.height);
        assert_eq!(received_epochs[0].prev_commitment, epoch1.prev_commitment);
        assert_eq!(
            received_epochs[0].current_commitment,
            epoch1.current_commitment
        );

        // Verify second epoch
        assert_eq!(received_epochs[1].height, epoch2.height);
        assert_eq!(received_epochs[1].prev_commitment, epoch2.prev_commitment);
        assert_eq!(
            received_epochs[1].current_commitment,
            epoch2.current_commitment
        );

        // Verify that the epochs are connected
        assert_eq!(
            received_epochs[1].prev_commitment,
            received_epochs[0].current_commitment
        );

        // Verify that the buffer is now empty
        let empty_epochs = sequencer.receive_finalized_epochs().await.unwrap();
        assert!(empty_epochs.is_empty());
    }
}
