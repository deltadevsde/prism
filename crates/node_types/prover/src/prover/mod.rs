mod timer;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use jmt::KeyHash;
use prism_common::{
    account::Account,
    api::{
        types::{AccountResponse, CommitmentResponse, HashedMerkleProof},
        PrismApi,
    },
    digest::Digest,
    transaction::Transaction,
};
use prism_errors::DataAvailabilityError;
use prism_keys::{CryptoAlgorithm, SigningKey, VerifyingKey};
use prism_storage::database::Database;
use prism_tree::{
    hasher::TreeHasher,
    key_directory_tree::KeyDirectoryTree,
    proofs::{Batch, Proof},
    snarkable_tree::SnarkableTree,
    AccountResponse::*,
};
use std::{self, collections::VecDeque, sync::Arc};
use timer::ProverTokioTimer;
use tokio::{
    sync::{broadcast, RwLock},
    task::JoinSet,
};

use crate::webserver::{WebServer, WebServerConfig};
use prism_common::operation::Operation;
use prism_da::{DataAvailabilityLayer, FinalizedEpoch};
use sp1_sdk::{CpuProver, Prover as _, ProverClient, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

pub const PRISM_ELF: &[u8] = include_bytes!("../../../../../elf/riscv32im-succinct-zkvm-elf");

#[derive(Clone)]
pub struct Config {
    /// Enables generating [`FinalizedEpoch`]s and posting them to the DA
    /// layer. When deactivated, the node will simply sync historical and
    /// incoming [`FinalizedEpoch`]s.
    pub prover: bool,

    /// Enables accepting incoming transactions from the webserver and posting batches to the DA layer.
    /// When deactivated, the node will reject incoming transactions.
    pub batcher: bool,

    /// Configuration for the webserver.
    pub webserver: WebServerConfig,

    /// Key used to sign new [`FinalizedEpochs`].
    pub signing_key: SigningKey,

    /// Key used to verify incoming [`FinalizedEpochs`].
    /// This is not necessarily the counterpart to signing_key, as fullnodes must use the [`verifying_key`] of the prover.
    pub verifying_key: VerifyingKey,

    /// DA layer height the prover should start syncing transactions from.
    pub start_height: u64,
}

impl Default for Config {
    fn default() -> Self {
        let signing_key = SigningKey::new_ed25519();

        Config {
            prover: true,
            batcher: true,
            webserver: WebServerConfig::default(),
            signing_key: signing_key.clone(),
            verifying_key: signing_key.verifying_key(),
            start_height: 1,
        }
    }
}

#[allow(dead_code)]
impl Config {
    /// Creates a new Config instance with the specified key algorithm.
    ///
    /// # Arguments
    /// * `algorithm` - The key algorithm to use for signing and verification
    ///
    /// # Returns
    /// A Result containing the Config or an error if key creation fails
    fn default_with_key_algorithm(algorithm: CryptoAlgorithm) -> Result<Self> {
        let signing_key =
            SigningKey::new_with_algorithm(algorithm).context("Failed to create signing key")?;

        Ok(Config {
            prover: true,
            batcher: true,
            webserver: WebServerConfig::default(),
            signing_key: signing_key.clone(),
            verifying_key: signing_key.verifying_key(),
            start_height: 1,
        })
    }
}

#[allow(dead_code)]
pub struct Prover {
    pub db: Arc<dyn Database>,
    pub da: Arc<dyn DataAvailabilityLayer>,

    pub cfg: Config,

    /// [`pending_transactions`] is a buffer for transactions that have not yet been
    /// posted to the DA layer.
    pub pending_transactions: Arc<RwLock<Vec<Transaction>>>,

    /// [`tree`] is the representation of the JMT, prism's state tree. It is accessed via the [`db`].
    tree: Arc<RwLock<KeyDirectoryTree<Box<dyn Database>>>>,

    prover_client: Arc<RwLock<CpuProver>>,
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
        let prover_client = ProverClient::builder().mock().build();
        #[cfg(not(feature = "mock_prover"))]
        let prover_client = ProverClient::builder().cpu().build();

        let (pk, vk) = prover_client.setup(PRISM_ELF);

        Ok(Prover {
            db: db.clone(),
            da,
            cfg: cfg.clone(),
            proving_key: pk,
            verifying_key: vk,
            prover_client: Arc::new(RwLock::new(prover_client)),
            tree,
            pending_transactions: Arc::new(RwLock::new(Vec::new())),
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
            let initial_commitment = self.get_commitment_from_tree().await?;
            self.db.set_commitment(&0, &initial_commitment)?;
        }

        // TODO: Should be persisted in database for crash recovery
        let mut buffered_transactions: VecDeque<Transaction> = VecDeque::new();
        let mut current_height = start_height;

        while current_height <= end_height {
            self.process_da_height(current_height, &mut buffered_transactions, false).await?;
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
            self.process_da_height(height, &mut buffered_transactions, true).await?;
            current_height += 1;
            // TODO: Race between set_epoch and set_last_synced_height - updating these should be a single atomic transaction
            self.db.set_last_synced_height(&current_height)?;
        }
    }

    async fn process_da_height(
        &self,
        height: u64,
        buffered_transactions: &mut VecDeque<Transaction>,
        is_real_time: bool,
    ) -> Result<()> {
        let current_epoch = self.db.get_epoch()?;

        let transactions = self.da.get_transactions(height).await?;
        let epoch_result = self.da.get_finalized_epoch(height).await?;

        debug!(
            "processing {} height {}, current_epoch: {}",
            if is_real_time { "new" } else { "old" },
            height,
            current_epoch
        );

        if let Some(epoch) = epoch_result {
            // run all buffered transactions from the last celestia blocks and increment current_epoch
            self.process_epoch(epoch, buffered_transactions).await?;
        } else {
            debug!("No transactions to process at height {}", height);
        }

        if is_real_time && !buffered_transactions.is_empty() && self.cfg.prover {
            let all_transactions: Vec<Transaction> = buffered_transactions.drain(..).collect();
            self.finalize_new_epoch(current_epoch, all_transactions).await?;
        }

        // If there are new transactions at this height, add them to the queue to
        // be included in the next finalized epoch.
        if !transactions.is_empty() {
            buffered_transactions.extend(transactions);
        }

        Ok(())
    }

    async fn process_epoch(
        &self,
        epoch: FinalizedEpoch,
        buffered_transactions: &mut VecDeque<Transaction>,
    ) -> Result<()> {
        let mut current_epoch = self.db.get_epoch()?;

        // If prover is enabled and is actively producing new epochs, it has
        // likely already ran all of the transactions in the found epoch, so no
        // further processing is needed
        if epoch.height < current_epoch {
            debug!("epoch {} already processed internally", current_epoch);
            return Ok(());
        }

        // TODO: Issue #144
        epoch
            .verify_signature(self.cfg.verifying_key.clone())
            .with_context(|| format!("Invalid signature in epoch {}", epoch.height))?;
        trace!("valid signature for epoch {}", epoch.height);

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

        let all_transactions: Vec<Transaction> = buffered_transactions.drain(..).collect();
        if !all_transactions.is_empty() {
            self.execute_block(all_transactions).await?;
        }

        let new_commitment = self.get_commitment_from_tree().await?;
        if epoch.current_commitment != new_commitment {
            return Err(anyhow!(
                "new commitment mismatch at epoch {}",
                current_epoch
            ));
        }

        let client = self.prover_client.read().await;
        match client.verify(&epoch.proof, &self.verifying_key) {
            Ok(_) => info!(
                "zkSNARK for epoch {} was validated successfully",
                epoch.height
            ),
            Err(err) => panic!(
                "failed to validate epoch at height {}: {:?}",
                epoch.height, err
            ),
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

    // should only be called for testing and historical sync, it does not
    // generate the Batch object for proof generation.
    async fn execute_block(&self, transactions: Vec<Transaction>) -> Result<Vec<Proof>> {
        debug!("executing block with {} transactions", transactions.len());

        let mut proofs = Vec::new();

        for transaction in transactions {
            match self.process_transaction(transaction.clone()).await {
                Ok(proof) => proofs.push(proof),
                Err(e) => {
                    // Log the error and continue with the next transaction
                    warn!(
                        "Failed to process transaction: {:?}. Error: {}",
                        transaction, e
                    );
                }
            }
        }

        Ok(proofs)
    }

    async fn finalize_new_epoch(
        &self,
        epoch_height: u64,
        transactions: Vec<Transaction>,
    ) -> Result<()> {
        let mut tree = self.tree.write().await;
        let batch = tree.process_batch(transactions)?;
        batch.verify()?;

        let finalized_epoch = self.prove_epoch(epoch_height, &batch).await?;

        self.da.submit_finalized_epoch(finalized_epoch).await?;

        let new_epoch_height = epoch_height + 1;
        self.db.set_commitment(&new_epoch_height, &batch.new_root)?;
        self.db.set_epoch(&new_epoch_height)?;

        info!("finalized new epoch at height {}", epoch_height);

        Ok(())
    }

    async fn prove_epoch(&self, epoch_height: u64, batch: &Batch) -> Result<FinalizedEpoch> {
        let mut stdin = SP1Stdin::new();
        stdin.write(&batch);
        let client = self.prover_client.read().await;

        info!("generating proof for epoch at height {}", epoch_height);
        #[cfg(not(feature = "groth16"))]
        let proof = client.prove(&self.proving_key, &stdin).run()?;

        #[cfg(feature = "groth16")]
        let proof = client.prove(&self.proving_key, &stdin).groth16().run()?;
        info!("successfully generated proof for epoch {}", epoch_height);

        client.verify(&proof, &self.verifying_key)?;
        info!("verified proof for epoch {}", epoch_height);

        let mut epoch_json = FinalizedEpoch {
            height: epoch_height,
            prev_commitment: batch.prev_root,
            current_commitment: batch.new_root,
            proof,
            signature: None,
        };

        epoch_json.insert_signature(&self.cfg.signing_key);
        Ok(epoch_json)
    }

    async fn post_batch_loop(self: Arc<Self>) -> Result<()> {
        let mut height_rx = self.da.subscribe_to_heights();

        loop {
            let height = height_rx.recv().await?;
            trace!("received height {}", height);

            // Get pending transactions
            let pending_transactions = {
                let mut ops = self.pending_transactions.write().await;
                std::mem::take(&mut *ops)
            };

            let tx_count = pending_transactions.len();

            // If there are pending transactions, submit them
            if !pending_transactions.clone().is_empty() {
                match self.da.submit_transactions(pending_transactions).await {
                    Ok(submitted_height) => {
                        info!(
                            "post_batch_loop: submitted {} transactions at height {}",
                            tx_count, submitted_height
                        );
                    }
                    Err(e) => {
                        error!("post_batch_loop: Failed to submit transactions: {}", e);
                    }
                }
            } else {
                debug!(
                    "post_batch_loop: No pending transactions to submit at height {}",
                    height
                );
            }
        }
    }

    async fn get_commitment_from_tree(&self) -> Result<Digest> {
        let tree = self.tree.read().await;
        tree.get_commitment().context("Failed to get commitment")
    }

    async fn get_account_from_tree(&self, id: &str) -> Result<prism_tree::AccountResponse> {
        let tree = self.tree.read().await;
        let key_hash = KeyHash::with::<TreeHasher>(id);

        tree.get(key_hash)
    }

    /// Updates the state from an already verified pending transaction.
    async fn process_transaction(&self, transaction: Transaction) -> Result<Proof> {
        let mut tree = self.tree.write().await;
        tree.process_transaction(transaction)
    }

    /// Adds an transaction to be posted to the DA layer and applied in the next epoch.
    pub async fn validate_and_queue_update(&self, transaction: Transaction) -> Result<()> {
        if !self.cfg.batcher {
            bail!("Batcher is disabled, cannot queue transactions");
        }

        // validate against existing account if necessary, including signature checks
        match transaction.operation {
            Operation::RegisterService { .. } | Operation::CreateAccount { .. } => {
                Account::default().process_transaction(&transaction)?;
            }
            Operation::AddKey { .. }
            | Operation::RevokeKey { .. }
            | Operation::AddData { .. }
            | Operation::SetData { .. } => {
                let account_response = self.get_account_from_tree(&transaction.id).await?;

                let Found(mut account, _) = account_response else {
                    bail!("Account not found for id: {}", transaction.id)
                };

                account.process_transaction(&transaction)?;
            }
        };

        let mut pending = self.pending_transactions.write().await;
        pending.push(transaction);
        Ok(())
    }
}

#[async_trait]
impl PrismApi for Prover {
    type Error = anyhow::Error;
    type Timer = ProverTokioTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, Self::Error> {
        let acc_response = match self.get_account_from_tree(id).await? {
            Found(account, inclusion_proof) => {
                let hashed_inclusion_proof = inclusion_proof.hashed();
                AccountResponse {
                    account: Some(*account),
                    proof: HashedMerkleProof {
                        leaf: hashed_inclusion_proof.leaf,
                        siblings: hashed_inclusion_proof.siblings,
                    },
                }
            }
            NotFound(non_inclusion_proof) => {
                let hashed_non_inclusion = non_inclusion_proof.hashed();
                AccountResponse {
                    account: None,
                    proof: HashedMerkleProof {
                        leaf: hashed_non_inclusion.leaf,
                        siblings: hashed_non_inclusion.siblings,
                    },
                }
            }
        };
        Ok(acc_response)
    }

    async fn get_commitment(&self) -> Result<CommitmentResponse, Self::Error> {
        let commitment = self.get_commitment_from_tree().await?;
        Ok(CommitmentResponse { commitment })
    }

    async fn post_transaction(&self, tx: &Transaction) -> Result<(), Self::Error> {
        self.validate_and_queue_update(tx.clone()).await
    }
}

#[cfg(test)]
mod tests;
