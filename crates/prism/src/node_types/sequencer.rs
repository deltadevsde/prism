use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;

use jmt::KeyHash;
use std::{self, collections::VecDeque, sync::Arc};
use tokio::sync::{broadcast, RwLock};

use sp1_sdk::{ProverClient, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

use crate::{
    cfg::Config,
    da::{DataAvailabilityLayer, FinalizedEpoch},
    node_types::NodeType,
    storage::Database,
    webserver::WebServer,
};
use prism_common::{
    hashchain::Hashchain,
    operation::Operation,
    tree::{
        hash, Batch, Digest, Hasher, KeyDirectoryTree, NonMembershipProof, Proof, SnarkableTree,
    },
};
use prism_errors::DataAvailabilityError;

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
    pending_operations: Arc<RwLock<Vec<Operation>>>,
    tree: Arc<RwLock<KeyDirectoryTree<Box<dyn Database>>>>,
    prover_client: Arc<RwLock<ProverClient>>,

    proving_key: SP1ProvingKey,
    verifying_key: SP1VerifyingKey,
}

#[async_trait]
impl NodeType for Sequencer {
    async fn start(self: Arc<Self>) -> Result<()> {
        self.da
            .start()
            .await
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))
            .context("Failed to start DataAvailabilityLayer")?;

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

        let tree = Arc::new(RwLock::new(KeyDirectoryTree::new(db.clone())));

        #[cfg(feature = "mock_prover")]
        let prover_client = ProverClient::mock();
        #[cfg(not(feature = "mock_prover"))]
        let prover_client = ProverClient::local();

        let (pk, vk) = prover_client.setup(PRISM_ELF);

        Ok(Sequencer {
            db: db.clone(),
            da,
            ws: WebServer::new(ws),
            proving_key: pk,
            verifying_key: vk,
            key,
            start_height,
            prover_client: Arc::new(RwLock::new(prover_client)),
            tree,
            pending_operations: Arc::new(RwLock::new(Vec::new())),
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
                let mut ops = self.pending_operations.write().await;
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
        let prev_commitment = self.get_commitment().await?;

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
            self.finalize_new_epoch(*current_epoch, all_ops).await?;
        } else if let Some(epoch) = epoch_result {
            self.process_existing_epoch(
                epoch,
                current_epoch,
                buffered_operations,
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
            self.execute_block(buffered_ops).await?;
        }

        let new_commitment = self.get_commitment().await?;
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

    async fn execute_block(&self, operations: Vec<Operation>) -> Result<Vec<Proof>> {
        debug!("executing block with {} operations", operations.len());

        let mut proofs = Vec::new();

        for operation in operations {
            match self.process_operation(&operation).await {
                Ok(proof) => proofs.push(proof),
                Err(e) => {
                    // Log the error and continue with the next operation
                    warn!("Failed to process operation: {:?}. Error: {}", operation, e);
                }
            }
        }

        Ok(proofs)
    }

    async fn finalize_new_epoch(&self, height: u64, operations: Vec<Operation>) -> Result<()> {
        let prev_commitment = self.get_commitment().await?;

        let proofs = self.execute_block(operations).await?;

        let new_commitment = self.get_commitment().await?;

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
        let client = self.prover_client.read().await;

        info!("generating proof for epoch height {}", height);
        #[cfg(not(feature = "plonk"))]
        let proof = client.prove(&self.proving_key, stdin).run()?;

        #[cfg(feature = "plonk")]
        let proof = client.prove(&self.proving_key, stdin).plonk().run()?;
        info!("successfully generated proof for epoch height {}", height);

        client.verify(&proof, &self.verifying_key)?;
        info!("verified proof for epoch height {}", height);

        let mut epoch_json = FinalizedEpoch {
            height,
            prev_commitment,
            current_commitment: new_commitment,
            proof,
            signature: None,
        };

        epoch_json.insert_signature(&self.key);
        Ok(epoch_json)
    }
    pub async fn get_commitment(&self) -> Result<Digest> {
        let tree = self.tree.read().await;
        tree.get_commitment().context("Failed to get commitment")
    }
    pub async fn get_hashchain(
        &self,
        id: &String,
    ) -> Result<Result<Hashchain, NonMembershipProof>> {
        let tree = self.tree.read().await;
        let hashed_id = hash(id.as_bytes());
        let key_hash = KeyHash::with::<Hasher>(hashed_id);

        tree.get(key_hash)
    }

    /// Updates the state from an already verified pending operation.
    async fn process_operation(&self, operation: &Operation) -> Result<Proof> {
        let mut tree = self.tree.write().await;
        tree.process_operation(operation)
    }

    /// Adds an operation to be posted to the DA layer and applied in the next epoch.
    pub async fn validate_and_queue_update(
        self: Arc<Self>,
        incoming_operation: &Operation,
    ) -> Result<()> {
        // basic validation, does not include signature checks
        incoming_operation.validate()?;

        // validate operation against existing hashchain if necessary, including signature checks
        match incoming_operation {
            Operation::CreateAccount(_) => (),
            Operation::AddKey(_) | Operation::RevokeKey(_) => {
                let hc = self.get_hashchain(&incoming_operation.id()).await?;
                if let Ok(mut hc) = hc {
                    hc.perform_operation(incoming_operation.clone())?;
                } else {
                    return Err(anyhow!(
                        "Hashchain not found for id: {}",
                        incoming_operation.id()
                    ));
                }
            }
        };

        let mut pending = self.pending_operations.write().await;
        pending.push(incoming_operation.clone());
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
    use keystore_rs::create_signing_key;
    use prism_common::{
        operation::{
            CreateAccountArgs, KeyOperationArgs, PublicKey, ServiceChallengeInput, SignatureBundle,
        },
        test_utils::create_mock_signing_key,
    };
    use serial_test::serial;

    fn create_random_user(id: &str, signing_key: SigningKey) -> Operation {
        let mut op = Operation::CreateAccount(CreateAccountArgs {
            id: id.to_string(),
            value: PublicKey::Ed25519(signing_key.verifying_key().to_bytes().to_vec()),
            service_id: "test_service".to_string(),
            signature: Vec::new(),
            challenge: ServiceChallengeInput::Signed(vec![]),
        });

        op.insert_signature(&signing_key)
            .expect("Inserting signature into operation should succeed");
        op
    }

    fn add_key(id: &str, key_idx: u64, new_key: PublicKey, signing_key: SigningKey) -> Operation {
        let mut op = Operation::AddKey(KeyOperationArgs {
            id: id.to_string(),
            value: new_key.clone(),
            signature: SignatureBundle {
                key_idx,
                signature: Vec::new(),
            },
        });

        op.insert_signature(&signing_key)
            .expect("Inserting signature into operation should succeed");
        op
    }

    fn revoke_key(
        id: &str,
        key_idx: u64,
        key_to_revoke: PublicKey,
        signing_key: SigningKey,
    ) -> Operation {
        let mut op = Operation::RevokeKey(KeyOperationArgs {
            id: id.to_string(),
            value: key_to_revoke.clone(),
            signature: SignatureBundle {
                key_idx,
                signature: Vec::new(),
            },
        });
        op.insert_signature(&signing_key)
            .expect("Inserting signature into operation should succeed");
        op
    }

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
    #[tokio::test]
    #[serial]
    async fn test_validate_and_queue_update() {
        let sequencer = create_test_sequencer().await;

        let signing_key = create_mock_signing_key();
        let op = create_random_user("test@example.com", signing_key);

        sequencer
            .clone()
            .validate_and_queue_update(&op)
            .await
            .unwrap();

        let pending_ops = sequencer.pending_operations.read().await;
        assert_eq!(pending_ops.len(), 1);

        teardown_db(sequencer.db.clone());
    }
    #[tokio::test]
    #[serial]
    async fn test_process_operation() {
        let sequencer = create_test_sequencer().await;

        let signing_key = create_mock_signing_key();
        let original_pubkey = PublicKey::Ed25519(signing_key.verifying_key().to_bytes().to_vec());
        let create_account_op = create_random_user("test@example.com", signing_key.clone());

        let proof = sequencer
            .process_operation(&create_account_op)
            .await
            .unwrap();
        assert!(matches!(proof, Proof::Insert(_)));

        let new_key = create_mock_signing_key();
        let pubkey = PublicKey::Ed25519(new_key.verifying_key().to_bytes().to_vec());
        let add_key_op = add_key("test@example.com", 0, pubkey, signing_key);

        let proof = sequencer.process_operation(&add_key_op).await.unwrap();

        assert!(matches!(proof, Proof::Update(_)));

        // Revoke original key
        let revoke_op = revoke_key("test@example.com", 1, original_pubkey, new_key);
        let proof = sequencer.process_operation(&revoke_op).await.unwrap();
        assert!(matches!(proof, Proof::Update(_)));

        teardown_db(sequencer.db.clone());
    }
    #[tokio::test]
    #[serial]
    async fn test_execute_block() {
        let sequencer = create_test_sequencer().await;

        let signing_key_1 = create_mock_signing_key();
        let signing_key_2 = create_mock_signing_key();
        let new_key = PublicKey::Ed25519(
            create_mock_signing_key()
                .verifying_key()
                .to_bytes()
                .to_vec(),
        );
        let operations = vec![
            create_random_user("user1@example.com", signing_key_1.clone()),
            create_random_user("user2@example.com", signing_key_2),
            add_key("user1@example.com", 0, new_key, signing_key_1),
        ];

        let proofs = sequencer.execute_block(operations).await.unwrap();
        assert_eq!(proofs.len(), 3);

        teardown_db(sequencer.db.clone());
    }
    #[tokio::test]
    #[serial]
    async fn test_finalize_new_epoch() {
        let sequencer = create_test_sequencer().await;

        let signing_key_1 = create_mock_signing_key();
        let signing_key_2 = create_mock_signing_key();
        let new_key = PublicKey::Ed25519(
            create_mock_signing_key()
                .verifying_key()
                .to_bytes()
                .to_vec(),
        );
        let operations = vec![
            create_random_user("user1@example.com", signing_key_1.clone()),
            create_random_user("user2@example.com", signing_key_2),
            add_key("user1@example.com", 0, new_key, signing_key_1),
        ];

        let prev_commitment = sequencer.get_commitment().await.unwrap();
        sequencer.finalize_new_epoch(0, operations).await.unwrap();

        let new_commitment = sequencer.get_commitment().await.unwrap();
        assert_ne!(prev_commitment, new_commitment);

        teardown_db(sequencer.db.clone());
    }
}
