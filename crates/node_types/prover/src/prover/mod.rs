mod timer;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use prism_common::{
    api::{
        PendingTransaction, PendingTransactionImpl, PrismApi, PrismApiError,
        types::{AccountResponse, CommitmentResponse, HashedMerkleProof},
    },
    transaction::Transaction,
};
use prism_errors::DataAvailabilityError;
use prism_keys::{CryptoAlgorithm, SigningKey, VerifyingKey};
use prism_storage::database::Database;
use prism_tree::AccountResponse::*;
use std::sync::Arc;
use timer::ProverTokioTimer;
use tokio::{sync::RwLock, task::JoinSet};

use crate::{
    prover_engine::ProverEngine,
    sequencer::Sequencer,
    syncer::Syncer,
    webserver::{WebServer, WebServerConfig},
};
use prism_da::DataAvailabilityLayer;

/// Maximum number of DA heights the prover will wait before posting a gapfiller proof
pub const DEFAULT_MAX_EPOCHLESS_GAP: u64 = 300;

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
    ///
    /// Maximum DA height gap between two epochs; If exceeded, the prover will
    /// repost the last epoch to aid LN syncing.
    pub max_epochless_gap: u64,

    /// Whether recursive proofs should be enabled - defaults to false, unless SP1_PROVER env var is set to "mock"
    pub recursive_proofs: bool,
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
            max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
            recursive_proofs: false,
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
            signing_key: signing_key.clone(),
            verifying_key: signing_key.verifying_key(),
            recursive_proofs: false,
            ..Config::default()
        })
    }
}

#[allow(dead_code)]
pub struct Prover {
    pub cfg: Config,
    prover_engine: Arc<ProverEngine>,
    sequencer: Arc<Sequencer>,
    syncer: Arc<Syncer>,
    latest_epoch_da_height: Arc<RwLock<u64>>,
}

#[allow(dead_code)]
impl Prover {
    pub fn new(
        db: Arc<Box<dyn Database>>,
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: &Config,
    ) -> Result<Prover> {
        let latest_epoch_da_height = Arc::new(RwLock::new(0));

        let prover_engine = Arc::new(ProverEngine::new(cfg.recursive_proofs)?);

        let sequencer = Arc::new(Sequencer::new(
            db.clone(),
            da.clone(),
            cfg.signing_key.clone(),
            latest_epoch_da_height.clone(),
            cfg.batcher,
        )?);

        let syncer = Arc::new(Syncer::new(
            da,
            db,
            cfg.verifying_key.clone(),
            cfg.max_epochless_gap,
            latest_epoch_da_height.clone(),
        ));

        Ok(Prover {
            cfg: cfg.clone(),
            prover_engine,
            sequencer,
            syncer,
            latest_epoch_da_height,
        })
    }

    pub fn get_db(&self) -> Arc<Box<dyn Database>> {
        self.sequencer.get_db()
    }

    pub async fn execute_block(
        &self,
        transactions: Vec<Transaction>,
    ) -> Result<Vec<prism_tree::proofs::Proof>> {
        self.sequencer.execute_block(transactions).await
    }

    pub async fn finalize_new_epoch(
        &self,
        epoch_height: u64,
        transactions: Vec<Transaction>,
    ) -> Result<u64> {
        self.sequencer.finalize_new_epoch(epoch_height, transactions, &self.prover_engine).await
    }

    pub async fn validate_and_queue_update(&self, transaction: Transaction) -> Result<()> {
        self.sequencer.validate_and_queue_update(transaction).await
    }

    pub fn get_pending_transactions(&self) -> Arc<RwLock<Vec<Transaction>>> {
        self.sequencer.get_pending_transactions()
    }

    pub async fn process_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<prism_tree::proofs::Proof> {
        self.sequencer.process_transaction(transaction).await
    }

    pub fn get_da(&self) -> Arc<dyn DataAvailabilityLayer> {
        self.syncer.get_da()
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        self.syncer
            .start_da()
            .await
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))
            .context("Failed to start DataAvailabilityLayer")?;

        let syncer = self.syncer.clone();
        let sequencer = self.sequencer.clone();
        let prover_engine = self.prover_engine.clone();
        let start_height = self.cfg.start_height;
        let prover_enabled = self.cfg.prover;

        let main_loop = async move {
            syncer.run_main_loop(start_height, sequencer, prover_engine, prover_enabled).await
        };

        let mut futures = JoinSet::new();
        futures.spawn(main_loop);

        if self.cfg.batcher {
            let sequencer_clone = self.sequencer.clone();
            let batch_poster = async move { sequencer_clone.run_batch_poster().await };
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
}

#[async_trait]
impl PrismApi for Prover {
    type Timer = ProverTokioTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, PrismApiError> {
        let acc_response = match self.sequencer.get_account(id).await? {
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

    async fn get_commitment(&self) -> Result<CommitmentResponse, PrismApiError> {
        let commitment = self.sequencer.get_commitment().await?;
        Ok(CommitmentResponse { commitment })
    }

    async fn post_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        self.sequencer.validate_and_queue_update(transaction.clone()).await?;
        Ok(PendingTransactionImpl::new(self, transaction))
    }
}

#[cfg(test)]
mod tests;
