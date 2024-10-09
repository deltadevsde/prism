use anyhow::{anyhow, bail, Context, Result};
use ed25519_consensus::SigningKey;
use jmt::KeyHash;
use prism_common::tree::{
    Batch, Digest, HashchainResponse, HashchainResponse::*, Hasher, KeyDirectoryTree, Proof,
    SnarkableTree,
};
use prism_errors::DataAvailabilityError;
use std::{self, collections::VecDeque, sync::Arc};
use tokio::sync::{broadcast, RwLock};

use crate::webserver::{WebServer, WebServerConfig};
use prism_common::operation::Operation;
use prism_da::{DataAvailabilityLayer, FinalizedEpoch};
use prism_storage::Database;
use sp1_sdk::{ProverClient, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

pub const PRISM_ELF: &[u8] = include_bytes!("../../../../elf/riscv32im-succinct-zkvm-elf");

#[allow(dead_code)]
pub struct Prover {
    pub db: Arc<dyn Database>,
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub ws: WebServer,

    // [`start_height`] is the DA layer height the prover should start syncing operations from.
    pub start_height: u64,

    pub key: SigningKey,

    // [`pending_operations`] is a buffer for operations that have not yet been
    // posted to the DA layer.
    pending_operations: Arc<RwLock<Vec<Operation>>>,
    tree: Arc<RwLock<KeyDirectoryTree<Box<dyn Database>>>>,
    prover_client: Arc<RwLock<ProverClient>>,

    proving_key: SP1ProvingKey,
    verifying_key: SP1VerifyingKey,
}

#[allow(dead_code)]
impl Prover {
    pub fn new(
        db: Arc<Box<dyn Database>>,
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: WebServerConfig,
        start_height: u64,
        key: SigningKey,
    ) -> Result<Prover> {
        let tree = Arc::new(RwLock::new(KeyDirectoryTree::new(db.clone())));

        #[cfg(feature = "mock_prover")]
        let prover_client = ProverClient::mock();
        #[cfg(not(feature = "mock_prover"))]
        let prover_client = ProverClient::local();

        let (pk, vk) = prover_client.setup(PRISM_ELF);

        Ok(Prover {
            db: db.clone(),
            da,
            ws: WebServer::new(cfg),
            proving_key: pk,
            verifying_key: vk,
            key,
            start_height,
            prover_client: Arc::new(RwLock::new(prover_client)),
            tree,
            pending_operations: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
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
    async fn main_loop(self: Arc<Self>) -> Result<()> {
        let mut height_rx = self.da.subscribe_to_heights();
        let current_height = height_rx.recv().await?;
        let historical_sync_height = current_height - 1;

        self.sync_range(self.start_height, historical_sync_height)
            .await?;
        self.real_time_sync(height_rx).await
    }

    async fn sync_range(&self, start_height: u64, end_height: u64) -> Result<()> {
        let mut saved_epoch = match self.db.get_epoch() {
            Ok(epoch) => epoch,
            Err(_) => {
                debug!("no existing epoch state found, setting epoch to 0");
                self.db.set_epoch(&0)?;
                0
            }
        };
        let mut buffered_operations: VecDeque<Vec<Operation>> = VecDeque::new();
        let mut current_height = start_height;

        while current_height < end_height {
            let height = current_height + 1;
            let operations = self.da.get_operations(height).await?;
            let epoch_result = self.da.get_finalized_epoch(height).await?;

            self.sync_historical_epoch(
                height,
                operations,
                epoch_result,
                &mut saved_epoch,
                &mut buffered_operations,
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
            trace!("received height {}", height);

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

            self.process_real_time_epoch(
                height,
                operations,
                &mut current_epoch,
                &mut buffered_operations,
            )
            .await?;
        }
    }

    async fn sync_historical_epoch(
        &self,
        height: u64,
        operations: Vec<Operation>,
        epoch_result: Option<FinalizedEpoch>,
        current_epoch: &mut u64,
        buffered_operations: &mut VecDeque<Vec<Operation>>,
    ) -> Result<()> {
        let prev_commitment = self.get_commitment().await?;

        debug!(
            "processing old height {}, current_epoch: {}",
            height, current_epoch
        );

        // If there are new operations at this height, add them to the queue to
        // be included in the next finalized epoch.
        if !operations.is_empty() {
            buffered_operations.push_back(operations);
        }

        if let Some(epoch) = epoch_result {
            // run all buffered operations from the last celestia blocks and increment current_epoch
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

    async fn process_real_time_epoch(
        &self,
        height: u64,
        operations: Vec<Operation>,
        current_epoch: &mut u64,
        buffered_operations: &mut VecDeque<Vec<Operation>>,
    ) -> Result<()> {
        debug!(
            "processing new height {}, current_epoch: {}",
            height, current_epoch
        );

        // If there are new operations at this height, add them to the queue to
        // be included in the next finalized epoch.
        if !operations.is_empty() {
            buffered_operations.push_back(operations);
        }

        if !buffered_operations.is_empty() {
            let all_ops: Vec<Operation> = buffered_operations.drain(..).flatten().collect();
            self.finalize_new_epoch(*current_epoch, all_ops).await?;
            *current_epoch += 1;
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

    async fn finalize_new_epoch(
        &self,
        epoch_height: u64,
        operations: Vec<Operation>,
    ) -> Result<()> {
        let prev_commitment = self.get_commitment().await?;

        let proofs = self.execute_block(operations).await?;

        let new_commitment = self.get_commitment().await?;

        let finalized_epoch = self
            .prove_epoch(epoch_height, prev_commitment, new_commitment, proofs)
            .await?;

        self.da.submit_finalized_epoch(finalized_epoch).await?;

        self.db.set_commitment(&epoch_height, &new_commitment)?;
        self.db.set_epoch(&epoch_height)?;

        info!("Finalized new epoch at height {}", epoch_height);

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

        info!("generating proof for epoch at height {}", height);
        #[cfg(not(feature = "groth16"))]
        let proof = client.prove(&self.proving_key, stdin).run()?;

        #[cfg(feature = "groth16")]
        let proof = client.prove(&self.proving_key, stdin).groth16().run()?;
        info!(
            "successfully generated proof for epoch at height {}",
            height
        );

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

    pub async fn get_hashchain(&self, id: &String) -> Result<HashchainResponse> {
        let tree = self.tree.read().await;
        let hashed_id = Digest::hash(id);
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
            Operation::RegisterService(_) => (),
            Operation::CreateAccount(_) => (),
            Operation::AddKey(_) | Operation::RevokeKey(_) => {
                let hc_response = self.get_hashchain(&incoming_operation.id()).await?;

                let Found(mut hc, _) = hc_response else {
                    bail!("Hashchain not found for id: {}", incoming_operation.id())
                };

                hc.perform_operation(incoming_operation.clone())?;
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
    use keystore_rs::create_signing_key;
    use prism_common::test_utils::create_mock_signing_key;
    use prism_da::memory::InMemoryDataAvailabilityLayer;
    use prism_storage::inmemory::InMemoryDatabase;

    // Helper function to create a test prover instance
    async fn create_test_prover() -> Arc<Prover> {
        let (da_layer, _rx, _brx) = InMemoryDataAvailabilityLayer::new(1);
        let da_layer = Arc::new(da_layer);
        let db: Arc<Box<dyn Database>> = Arc::new(Box::new(InMemoryDatabase::new()));
        let signing_key = create_signing_key();
        let cfg = WebServerConfig::default();
        Arc::new(Prover::new(db.clone(), da_layer, cfg, 0, signing_key.clone()).unwrap())
    }

    #[tokio::test]
    async fn test_validate_and_queue_update() {
        let prover = create_test_prover().await;

        let service_key = create_mock_signing_key();
        let op =
            Operation::new_register_service("service_id".to_string(), service_key.clone().into());

        prover.clone().validate_and_queue_update(&op).await.unwrap();

        prover.clone().validate_and_queue_update(&op).await.unwrap();

        let pending_ops = prover.pending_operations.read().await;
        assert_eq!(pending_ops.len(), 2);
    }

    #[tokio::test]
    async fn test_process_operation() {
        let prover = create_test_prover().await;

        let signing_key = create_mock_signing_key();
        let original_pubkey = signing_key.verifying_key();
        let service_key = create_mock_signing_key();

        let register_service_op =
            Operation::new_register_service("service_id".to_string(), service_key.clone().into());
        let create_account_op = Operation::new_create_account(
            "test@example.com".to_string(),
            &signing_key,
            "service_id".to_string(),
            &service_key,
        )
        .unwrap();

        let proof = prover
            .process_operation(&register_service_op)
            .await
            .unwrap();
        assert!(matches!(proof, Proof::Insert(_)));

        let proof = prover.process_operation(&create_account_op).await.unwrap();
        assert!(matches!(proof, Proof::Insert(_)));

        let new_key = create_mock_signing_key();
        let pubkey = new_key.verifying_key();
        let add_key_op =
            Operation::new_add_key("test@example.com".to_string(), pubkey, &signing_key, 0)
                .unwrap();

        let proof = prover.process_operation(&add_key_op).await.unwrap();

        assert!(matches!(proof, Proof::Update(_)));

        // Revoke original key
        let revoke_op =
            Operation::new_revoke_key("test@example.com".to_string(), original_pubkey, &new_key, 1)
                .unwrap();
        let proof = prover.process_operation(&revoke_op).await.unwrap();
        assert!(matches!(proof, Proof::Update(_)));
    }

    #[tokio::test]
    async fn test_execute_block_with_invalid_tx() {
        let prover = create_test_prover().await;

        let signing_key_1 = create_mock_signing_key();
        let signing_key_2 = create_mock_signing_key();
        let signing_key_3 = create_mock_signing_key();
        let service_key = create_mock_signing_key();

        let operations = vec![
            Operation::new_register_service("service_id".to_string(), service_key.clone().into()),
            Operation::new_create_account(
                "user1@example.com".to_string(),
                &signing_key_1,
                "service_id".to_string(),
                &service_key,
            )
            .unwrap(),
            // add signing_key_2, so it will be index = 1
            Operation::new_add_key(
                "user1@example.com".to_string(),
                signing_key_2.verifying_key(),
                &signing_key_1,
                0,
            )
            .unwrap(),
            // try revoking signing_key_2
            Operation::new_revoke_key(
                "user1@example.com".to_string(),
                signing_key_2.verifying_key(),
                &signing_key_1,
                0,
            )
            .unwrap(),
            // and adding in same block.
            // both of these operations are valid individually, but when processed together it will fail.
            Operation::new_add_key(
                "user1@example.com".to_string(),
                signing_key_3.verifying_key(),
                &signing_key_2,
                1,
            )
            .unwrap(),
        ];

        let proofs = prover.execute_block(operations).await.unwrap();
        assert_eq!(proofs.len(), 4);
    }

    #[tokio::test]
    async fn test_execute_block() {
        let prover = create_test_prover().await;

        let signing_key_1 = create_mock_signing_key();
        let signing_key_2 = create_mock_signing_key();
        let new_key = create_mock_signing_key().verifying_key();
        let service_key = create_mock_signing_key();

        let operations = vec![
            Operation::new_register_service("service_id".to_string(), service_key.clone().into()),
            Operation::new_create_account(
                "user1@example.com".to_string(),
                &signing_key_1,
                "service_id".to_string(),
                &service_key,
            )
            .unwrap(),
            Operation::new_create_account(
                "user2@example.com".to_string(),
                &signing_key_2,
                "service_id".to_string(),
                &service_key,
            )
            .unwrap(),
            Operation::new_add_key("user1@example.com".to_string(), new_key, &signing_key_1, 0)
                .unwrap(),
        ];

        let proofs = prover.execute_block(operations).await.unwrap();
        assert_eq!(proofs.len(), 4);
    }

    #[tokio::test]
    async fn test_finalize_new_epoch() {
        let prover = create_test_prover().await;

        let signing_key_1 = create_mock_signing_key();
        let signing_key_2 = create_mock_signing_key();
        let new_key = create_mock_signing_key().verifying_key();
        let service_key = create_mock_signing_key();

        let operations = vec![
            Operation::new_register_service("service_id".to_string(), service_key.clone().into()),
            Operation::new_create_account(
                "user1@example.com".to_string(),
                &signing_key_1,
                "service_id".to_string(),
                &service_key,
            )
            .unwrap(),
            Operation::new_create_account(
                "user2@example.com".to_string(),
                &signing_key_2,
                "service_id".to_string(),
                &service_key,
            )
            .unwrap(),
            Operation::new_add_key("user1@example.com".to_string(), new_key, &signing_key_1, 0)
                .unwrap(),
        ];

        let prev_commitment = prover.get_commitment().await.unwrap();
        prover.finalize_new_epoch(0, operations).await.unwrap();

        let new_commitment = prover.get_commitment().await.unwrap();
        assert_ne!(prev_commitment, new_commitment);
    }
}
