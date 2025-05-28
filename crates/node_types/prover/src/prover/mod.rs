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
use prism_keys::{CryptoAlgorithm, SigningKey, VerifyingKey};
use prism_storage::database::Database;
use prism_tree::AccountResponse::*;
use std::sync::Arc;
use timer::ProverTokioTimer;
use tokio::{sync::RwLock, task::JoinSet};
use tokio_util::sync::CancellationToken;

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
pub struct SyncerConfig {
    /// Key used to verify incoming [`FinalizedEpochs`].
    pub verifying_key: VerifyingKey,
    /// DA layer height the prover should start syncing transactions from.
    pub start_height: u64,
    /// Maximum DA height gap between two epochs; If exceeded, the prover will
    /// repost the last epoch to aid LN syncing.
    pub max_epochless_gap: u64,
    /// Enables generating [`FinalizedEpoch`]s and posting them to the DA layer.
    pub prover_enabled: bool,
}

#[derive(Clone)]
pub struct SequencerConfig {
    /// Key used to sign new [`FinalizedEpochs`].
    pub signing_key: SigningKey,
    /// Enables accepting incoming transactions from the webserver and posting batches to the DA layer.
    pub batcher_enabled: bool,
}

#[derive(Clone)]
pub struct ProverEngineConfig {
    /// Whether recursive proofs should be enabled
    pub recursive_proofs: bool,
}

#[derive(Clone)]
pub struct Config {
    pub syncer: SyncerConfig,
    pub sequencer: SequencerConfig,
    pub prover_engine: ProverEngineConfig,
    pub webserver: WebServerConfig,
}

impl Default for Config {
    fn default() -> Self {
        let signing_key = SigningKey::new_ed25519();

        Config {
            syncer: SyncerConfig {
                verifying_key: signing_key.verifying_key(),
                start_height: 1,
                max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
                prover_enabled: true,
            },
            sequencer: SequencerConfig {
                signing_key,
                batcher_enabled: true,
            },
            prover_engine: ProverEngineConfig {
                recursive_proofs: false,
            },
            webserver: WebServerConfig::default(),
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

        let mut config = Config::default();
        config.syncer.verifying_key = signing_key.verifying_key();
        config.sequencer.signing_key = signing_key;
        Ok(config)
    }
}

#[allow(dead_code)]
pub struct Prover {
    pub cfg: Config,
    prover_engine: Arc<ProverEngine>,
    sequencer: Arc<Sequencer>,
    syncer: Arc<Syncer>,
    latest_epoch_da_height: Arc<RwLock<u64>>,
    cancellation_token: CancellationToken,
}

#[allow(dead_code)]
impl Prover {
    pub fn new(
        db: Arc<Box<dyn Database>>,
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: &Config,
        cancellation_token: CancellationToken,
    ) -> Result<Prover> {
        let latest_epoch_da_height = Arc::new(RwLock::new(0));

        let prover_engine = Arc::new(ProverEngine::new(&cfg.prover_engine)?);

        let sequencer = Arc::new(Sequencer::new(
            db.clone(),
            da.clone(),
            &cfg.sequencer,
            latest_epoch_da_height.clone(),
        )?);

        let syncer = Arc::new(Syncer::new(
            da,
            db,
            &cfg.syncer,
            latest_epoch_da_height.clone(),
            sequencer.clone(),
            prover_engine.clone(),
        ));

        Ok(Prover {
            cfg: cfg.clone(),
            prover_engine,
            sequencer,
            syncer,
            latest_epoch_da_height,
            cancellation_token,
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
        let mut futures = JoinSet::new();

        // Start Syncer (includes DA startup and main sync loop)
        let syncer = self.syncer.clone();
        let cancel_token = self.cancellation_token.clone();
        futures.spawn(async move { syncer.start(cancel_token).await });

        // Start Sequencer (batch poster if enabled)
        let sequencer = self.sequencer.clone();
        let cancel_token = self.cancellation_token.clone();
        futures.spawn(async move { sequencer.start(cancel_token).await });

        // Start WebServer if enabled
        if self.cfg.webserver.enabled {
            let ws = WebServer::new(self.cfg.webserver.clone(), self.clone());
            futures.spawn(async move { ws.start().await });
        }

        // Wait for any service to exit
        let exit_result = if let Some(result) = futures.join_next().await {
            match result {
                Ok(service_result) => match service_result {
                    Ok(_) => {
                        info!("Service exited gracefully, shutting down other components");
                        self.cancellation_token.cancel();
                        Ok(())
                    }
                    Err(service_error) => {
                        error!(
                            "Service exited with error: {:?}, shutting down other components",
                            service_error
                        );
                        self.cancellation_token.cancel();
                        Err(service_error)
                    }
                },
                Err(join_error) => {
                    error!(
                        "Task join error: {:?}, shutting down other components",
                        join_error
                    );
                    self.cancellation_token.cancel();
                    Err(anyhow!("Task join error: {}", join_error))
                }
            }
        } else {
            error!("No futures in join set, shutting down");
            Ok(())
        };

        // Wait for all other components to finish gracefully
        while let Some(result) = futures.join_next().await {
            match result {
                Ok(Ok(_)) => debug!("Component shut down gracefully"),
                Ok(Err(e)) => warn!("Component shut down with error: {:?}", e),
                Err(e) => warn!("Component join error during shutdown: {:?}", e),
            }
        }

        info!("Prover shutdown complete");
        exit_result
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
