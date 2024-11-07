use anyhow::{anyhow, bail, Context, Result};
use ed25519_consensus::SigningKey;
use jmt::KeyHash;
use keystore_rs::create_signing_key;
use prism_common::{
    digest::Digest,
    hashchain::Hashchain,
    hasher::Hasher,
    request::PendingRequest,
    tree::{
        Batch,
        HashchainResponse::{self, *},
        KeyDirectoryTree, Proof, SnarkableTree,
    },
};
use prism_errors::DataAvailabilityError;
use std::{self, collections::VecDeque, sync::Arc};
use tokio::{
    sync::{broadcast, RwLock},
    task::JoinSet,
};

use crate::webserver::{WebServer, WebServerConfig};
use prism_common::operation::Operation;
use prism_da::{DataAvailabilityLayer, FinalizedEpoch};
use prism_storage::Database;
use sp1_sdk::{ProverClient, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

pub const PRISM_ELF: &[u8] = include_bytes!("../../../../../elf/riscv32im-succinct-zkvm-elf");

#[derive(Clone)]
pub struct Config {
    /// Enables generating FinalizedEpochs and posting them to the DA
    /// layer. When deactivated, the node will simply sync historical and
    /// incoming FinalizedEpochs.
    pub prover: bool,

    /// Enables accepting incoming operations from the webserver and posting batches to the DA layer.
    /// When deactivated, the node will reject incoming operations.
    pub batcher: bool,

    /// Configuration for the webserver.
    pub webserver: WebServerConfig,

    /// Key used to sign new FinalizedEpochs.
    pub key: SigningKey,

    /// DA layer height the prover should start syncing operations from.
    pub start_height: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            prover: true,
            batcher: true,
            webserver: WebServerConfig::default(),
            key: create_signing_key(),
            start_height: 1,
        }
    }
}

#[allow(dead_code)]
pub struct Prover {
    pub db: Arc<dyn Database>,
    pub da: Arc<dyn DataAvailabilityLayer>,

    pub cfg: Config,

    /// [`pending_requests`] is a buffer for entries that have not yet been
    /// posted to the DA layer.
    pub pending_requests: Arc<RwLock<Vec<PendingRequest>>>,

    /// [`tree`] is the representation of the JMT, prism's state tree. It is accessed via the [`db`].
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
        cfg: &Config,
    ) -> Result<Prover> {
        let saved_epoch = match db.get_epoch() {
            Ok(epoch) => epoch,
            Err(_) => {
                debug!("no existing epoch state found, setting epoch to 0");
                db.set_epoch(&0)?;
                0
            }
        };

        let tree = Arc::new(RwLock::new(KeyDirectoryTree::load(db.clone(), saved_epoch)));

        #[cfg(feature = "mock_prover")]
        let prover_client = ProverClient::mock();
        #[cfg(not(feature = "mock_prover"))]
        let prover_client = ProverClient::local();

        let (pk, vk) = prover_client.setup(PRISM_ELF);

        Ok(Prover {
            db: db.clone(),
            da,
            cfg: cfg.clone(),
            proving_key: pk,
            verifying_key: vk,
            prover_client: Arc::new(RwLock::new(prover_client)),
            tree,
            pending_requests: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        self.da
            .start()
            .await
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))
            .context("Failed to start DataAvailabilityLayer")?;

        let main_loop = self.clone().main_loop();

        let mut futures = JoinSet::new();
        futures.spawn(main_loop);

        if self.cfg.batcher {
            let batch_poster = self.clone().post_batch_loop();
            futures.spawn(batch_poster);
        }

        let ws = WebServer::new(self.cfg.webserver.clone(), self.clone());
        if self.cfg.webserver.enabled {
            futures.spawn(async move { ws.start().await });
        }

        if let Some(result) = futures.join_next().await {
            error!("Service exited unexpectedly: {:?}", result);
            Err(anyhow!("Service exited unexpectedly"))?
        }
        error!("All services have ended unexpectedly.");
        Err(anyhow!("All services have ended unexpectedly"))?
    }

    async fn main_loop(self: Arc<Self>) -> Result<()> {
        let mut height_rx = self.da.subscribe_to_heights();
        let historical_sync_height = height_rx.recv().await?;

        let start_height = match self.db.get_last_synced_height() {
            Ok(height) => height,
            Err(_) => {
                debug!("no existing sync height found, setting sync height to start_height");
                self.db.set_last_synced_height(&self.cfg.start_height)?;
                self.cfg.start_height
            }
        };

        self.sync_loop(start_height, historical_sync_height, height_rx).await
    }

    async fn sync_loop(
        &self,
        start_height: u64,
        end_height: u64,
        mut incoming_heights: broadcast::Receiver<u64>,
    ) -> Result<()> {
        let saved_epoch = self.db.get_epoch()?;

        if saved_epoch == 0 {
            let initial_commitment = self.get_commitment().await?;
            self.db.set_commitment(&0, &initial_commitment)?;
        }

        // TODO: Should be persisted in database for crash recovery
        let mut buffered_requests: VecDeque<PendingRequest> = VecDeque::new();
        let mut current_height = start_height;

        while current_height <= end_height {
            self.process_da_height(current_height, &mut buffered_requests, false).await?;
            // TODO: Race between set_epoch and set_last_synced_height
            self.db.set_last_synced_height(&current_height)?;
            current_height += 1;
        }

        info!(
            "finished historical sync from height {} to {}",
            start_height, end_height
        );

        loop {
            let height = incoming_heights.recv().await?;
            if height != current_height {
                return Err(anyhow!(
                    "heights are not sequential: expected {}, got {}",
                    current_height,
                    height
                ));
            }
            self.process_da_height(height, &mut buffered_requests, true).await?;
            current_height += 1;
            // TODO: Race between set_epoch and set_last_synced_height - updating these should be a single atomic operation
            self.db.set_last_synced_height(&current_height)?;
        }
    }

    async fn process_da_height(
        &self,
        height: u64,
        buffered_requests: &mut VecDeque<PendingRequest>,
        is_real_time: bool,
    ) -> Result<()> {
        let current_epoch = self.db.get_epoch()?;

        let requests = self.da.get_requests(height).await?;
        let epoch_result = self.da.get_finalized_epoch(height).await?;

        debug!(
            "processing {} height {}, current_epoch: {}",
            if is_real_time { "new" } else { "old" },
            height,
            current_epoch
        );

        if let Some(epoch) = epoch_result {
            // run all buffered operations from the last celestia blocks and increment current_epoch
            self.process_epoch(epoch, buffered_requests).await?;
        } else {
            debug!("No operations to process at height {}", height);
        }

        if is_real_time && !buffered_requests.is_empty() && self.cfg.prover {
            let all_requests: Vec<PendingRequest> = buffered_requests.drain(..).collect();
            self.finalize_new_epoch(current_epoch, all_requests).await?;
        }

        // If there are new operations at this height, add them to the queue to
        // be included in the next finalized epoch.
        if !requests.is_empty() {
            buffered_requests.extend(requests);
        }

        Ok(())
    }

    async fn process_epoch(
        &self,
        epoch: FinalizedEpoch,
        buffered_requests: &mut VecDeque<PendingRequest>,
    ) -> Result<()> {
        let mut current_epoch = self.db.get_epoch()?;

        // If prover is enabled and is actively producing new epochs, it has
        // likely already ran all of the operations in the found epoch, so no
        // further processing is needed
        if epoch.height < current_epoch {
            debug!("epoch {} already processed internally", current_epoch);
            return Ok(());
        }

        let prev_commitment = self.db.get_commitment(&current_epoch)?;

        if epoch.height != current_epoch {
            return Err(anyhow!(
                "epoch height mismatch: expected {}, got {}",
                current_epoch,
                epoch.height
            ));
        }

        if epoch.prev_commitment != prev_commitment {
            return Err(anyhow!(
                "previous commitment mismatch at epoch {}",
                current_epoch
            ));
        }

        let all_requests: Vec<PendingRequest> = buffered_requests.drain(..).collect();
        if !all_requests.is_empty() {
            self.execute_block(all_requests).await?;
        }

        let new_commitment = self.get_commitment().await?;
        if epoch.current_commitment != new_commitment {
            return Err(anyhow!(
                "new commitment mismatch at epoch {}",
                current_epoch
            ));
        }

        debug!(
            "processed epoch {}. new commitment: {:?}",
            current_epoch, new_commitment
        );

        current_epoch += 1;
        self.db.set_commitment(&current_epoch, &new_commitment)?;
        self.db.set_epoch(&current_epoch)?;

        Ok(())
    }

    async fn execute_block(&self, requests: Vec<PendingRequest>) -> Result<Vec<Proof>> {
        debug!("executing block with {} requests", requests.len());

        let mut proofs = Vec::new();

        for request in requests {
            match self.process_request(request.clone()).await {
                Ok(proof) => proofs.push(proof),
                Err(e) => {
                    // Log the error and continue with the next operation
                    warn!("Failed to process operation: {:?}. Error: {}", request, e);
                }
            }
        }

        Ok(proofs)
    }

    async fn finalize_new_epoch(
        &self,
        epoch_height: u64,
        requests: Vec<PendingRequest>,
    ) -> Result<()> {
        let prev_commitment = self.get_commitment().await?;

        let proofs = self.execute_block(requests).await?;

        let new_commitment = self.get_commitment().await?;

        let finalized_epoch =
            self.prove_epoch(epoch_height, prev_commitment, new_commitment, proofs).await?;

        self.da.submit_finalized_epoch(finalized_epoch).await?;

        let new_epoch_height = epoch_height + 1;
        self.db.set_commitment(&new_epoch_height, &new_commitment)?;
        self.db.set_epoch(&new_epoch_height)?;

        info!("finalized new epoch at height {}", epoch_height);

        Ok(())
    }

    async fn prove_epoch(
        &self,
        epoch_height: u64,
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

        info!("generating proof for epoch at height {}", epoch_height);
        #[cfg(not(feature = "groth16"))]
        let proof = client.prove(&self.proving_key, stdin).run()?;

        #[cfg(feature = "groth16")]
        let proof = client.prove(&self.proving_key, stdin).groth16().run()?;
        info!("successfully generated proof for epoch {}", epoch_height);

        client.verify(&proof, &self.verifying_key)?;
        info!("verified proof for epoch {}", epoch_height);

        let mut epoch_json = FinalizedEpoch {
            height: epoch_height,
            prev_commitment,
            current_commitment: new_commitment,
            proof,
            signature: None,
        };

        epoch_json.insert_signature(&self.cfg.key);
        Ok(epoch_json)
    }

    async fn post_batch_loop(self: Arc<Self>) -> Result<()> {
        let mut height_rx = self.da.subscribe_to_heights();

        loop {
            let height = height_rx.recv().await?;
            trace!("received height {}", height);

            // Get pending operations
            let pending_requests = {
                let mut ops = self.pending_requests.write().await;
                std::mem::take(&mut *ops)
            };

            let op_count = pending_requests.len();

            // If there are pending operations, submit them
            if !pending_requests.clone().is_empty() {
                match self.da.submit_requests(pending_requests).await {
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

    /// Updates the state from an already verified pending entry.
    async fn process_request(&self, request: PendingRequest) -> Result<Proof> {
        let mut tree = self.tree.write().await;
        tree.process_entry(&request.id, request.entry)
    }

    /// Adds an operation to be posted to the DA layer and applied in the next epoch.
    pub async fn validate_and_queue_update(self: Arc<Self>, request: PendingRequest) -> Result<()> {
        if !self.cfg.batcher {
            bail!("Batcher is disabled, cannot queue operations");
        }

        // validate against existing hashchain if necessary, including signature checks
        match request.entry.operation {
            Operation::RegisterService { .. } | Operation::CreateAccount { .. } => {
                Hashchain::empty().add_entry(request.entry.clone())?
            }
            Operation::AddKey { .. } | Operation::RevokeKey { .. } | Operation::AddData { .. } => {
                let hc_response = self.get_hashchain(&request.id).await?;

                let Found(mut hc, _) = hc_response else {
                    bail!("Hashchain not found for id: {}", request.id)
                };

                hc.add_entry(request.entry.clone())?;
            }
        };

        let mut pending = self.pending_requests.write().await;
        pending.push(request);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
