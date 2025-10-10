use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use prism_common::{
    api::{
        PendingTransaction, PrismApi, PrismApiError,
        types::{AccountResponse, CommitmentResponse},
    },
    transaction::Transaction,
};
use prism_keys::{CryptoAlgorithm, SigningKey, VerifyingKey};
use prism_storage::Database;
use std::sync::{Arc, Mutex};
use tokio::{sync::RwLock, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    api::ProverTokioTimer,
    prover_engine::{engine::ProverEngine, sp1_prover::SP1ProverEngine},
    sequencer::Sequencer,
    syncer::Syncer,
    webserver::{WebServer, WebServerConfig},
};
use prism_da::DataAvailabilityLayer;

/// Maximum number of DA heights the prover will wait before posting a gapfiller proof
pub const DEFAULT_MAX_EPOCHLESS_GAP: u64 = 300;

#[derive(Clone)]
pub struct SyncerOptions {
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
pub struct SequencerOptions {
    /// Key used to sign new [`FinalizedEpochs`]. This is only required when the syncer is set up
    /// to prove epochs.
    pub signing_key: Option<SigningKey>,
    /// Enables accepting incoming transactions from the webserver and posting batches to the DA
    /// layer.
    pub batcher_enabled: bool,
}

#[derive(Clone)]
pub struct ProverEngineOptions {
    /// Whether recursive proofs should be enabled
    pub recursive_proofs: bool,
}

#[derive(Clone)]
pub struct ProverOptions {
    pub syncer: SyncerOptions,
    pub sequencer: SequencerOptions,
    pub prover_engine: ProverEngineOptions,
    pub webserver: WebServerConfig,
}

impl Default for ProverOptions {
    fn default() -> Self {
        let signing_key = SigningKey::new_ed25519();

        Self {
            syncer: SyncerOptions {
                verifying_key: signing_key.verifying_key(),
                start_height: 1,
                max_epochless_gap: DEFAULT_MAX_EPOCHLESS_GAP,
                prover_enabled: true,
            },
            sequencer: SequencerOptions {
                signing_key: Some(signing_key),
                batcher_enabled: true,
            },
            prover_engine: ProverEngineOptions {
                recursive_proofs: false,
            },
            webserver: WebServerConfig::default(),
        }
    }
}

#[allow(dead_code)]
impl ProverOptions {
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

        let mut config = Self::default();
        config.syncer.verifying_key = signing_key.verifying_key();
        config.sequencer.signing_key = Some(signing_key);
        Ok(config)
    }
}

/// A Prism prover node that maintains complete network state and generates SNARK proofs.
///
/// ## Architecture
///
/// The prover consists of several key components:
/// - **Syncer**: Synchronizes with the DA layer and processes incoming epochs
/// - **Sequencer**: Batches transactions and coordinates proof generation
/// - **Prover Engine**: Generates SNARK proofs using zkVM technology
/// - **Web Server**: Provides REST API endpoints for client interactions
///
/// ## Operation Modes
///
/// Provers can operate in two modes:
/// 1. **Prover**: Generates proofs and publishes epochs (requires signing key)
/// 2. **Full Node**: Validates state without proof generation (verification only)
///
/// ## Lifecycle
///
/// 1. **Initialization**: Set up database, DA connection, and components
/// 2. **Synchronization**: Catch up with the latest network state
/// 3. **Operation**: Process transactions, generate proofs, serve clients
/// 4. **Shutdown**: Graceful cleanup via cancellation token
#[allow(dead_code)]
pub struct Prover {
    pub options: ProverOptions,
    prover_engine: Arc<dyn ProverEngine>,
    sequencer: Arc<Sequencer>,
    syncer: Arc<Syncer>,
    latest_epoch_da_height: Arc<RwLock<u64>>,
    cancellation_token: CancellationToken,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

#[allow(dead_code)]
impl Prover {
    pub fn new(
        db: Arc<Box<dyn Database>>,
        da: Arc<dyn DataAvailabilityLayer>,
        opts: &ProverOptions,
    ) -> Result<Self> {
        let prover_engine = Arc::new(SP1ProverEngine::new(&opts.prover_engine)?);
        Self::new_with_engine(db, da, prover_engine, opts)
    }

    pub fn new_with_engine(
        db: Arc<Box<dyn Database>>,
        da: Arc<dyn DataAvailabilityLayer>,
        prover_engine: Arc<dyn ProverEngine>,
        opts: &ProverOptions,
    ) -> Result<Self> {
        let latest_epoch_da_height = Arc::new(RwLock::new(0));
        let cancellation_token = CancellationToken::new();

        let sequencer = Arc::new(Sequencer::new(
            db.clone(),
            da.clone(),
            &opts.sequencer,
            latest_epoch_da_height.clone(),
            cancellation_token.child_token(),
        )?);

        let syncer = Arc::new(Syncer::new(
            da,
            db,
            &opts.syncer,
            latest_epoch_da_height.clone(),
            sequencer.clone(),
            prover_engine.clone(),
            cancellation_token.child_token(),
        )?);

        Ok(Self {
            options: opts.clone(),
            prover_engine,
            sequencer,
            syncer,
            latest_epoch_da_height,
            cancellation_token,
            task_handles: Arc::new(Mutex::new(Vec::new())),
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
        tip_da_height: u64,
    ) -> Result<u64> {
        self.sequencer
            .finalize_new_epoch(
                epoch_height,
                transactions,
                &self.prover_engine,
                tip_da_height,
            )
            .await
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

    pub async fn start(&self) -> Result<()> {
        {
            let task_handles =
                self.task_handles.lock().map_err(|e| anyhow!("Lock poisoned: {}", e))?;

            if !task_handles.is_empty() {
                info!("Prover already started");
                return Ok(());
            }
        }

        info!("Starting Prover");
        let mut handles = Vec::new();

        // Start Syncer (includes DA startup and main sync loop)
        let syncer = self.syncer.clone();
        let syncer_handle = tokio::spawn(async move {
            if let Err(e) = syncer.start().await {
                error!("Syncer error: {:?}", e);
            }
        });
        handles.push(syncer_handle);

        // Start Sequencer (batch poster if enabled)
        let sequencer = self.sequencer.clone();
        let sequencer_handle = tokio::spawn(async move {
            if let Err(e) = sequencer.start().await {
                error!("Sequencer error: {:?}", e);
            }
        });
        handles.push(sequencer_handle);

        // Start WebServer if enabled
        if self.options.webserver.enabled {
            let ws = WebServer::new(
                self.options.webserver.clone(),
                self.sequencer.clone(),
                self.cancellation_token.child_token(),
            );
            let webserver_handle = tokio::spawn(async move {
                if let Err(e) = ws.start().await {
                    error!("WebServer error: {:?}", e);
                }
            });
            handles.push(webserver_handle);
        }

        {
            let mut task_handles =
                self.task_handles.lock().map_err(|e| anyhow!("Lock poisoned: {}", e))?;
            *task_handles = handles;
        }

        info!("Prover started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Prover");
        self.cancellation_token.cancel();
        self.join().await?;
        info!("Prover stopped successfully");
        Ok(())
    }

    async fn join(&self) -> Result<()> {
        let handles = {
            let mut task_handles =
                self.task_handles.lock().map_err(|e| anyhow!("Lock poisoned: {}", e))?;
            std::mem::take(&mut *task_handles)
        };

        if handles.is_empty() {
            return Ok(());
        }

        for handle in handles {
            match handle.await {
                Ok(_) => debug!("Component shut down gracefully"),
                Err(e) => warn!("Component join error during shutdown: {:?}", e),
            }
        }

        Ok(())
    }
}

#[async_trait]
impl PrismApi for Prover {
    type Timer = ProverTokioTimer;

    async fn get_account(&self, id: &str) -> Result<AccountResponse, PrismApiError> {
        PrismApi::get_account(self.sequencer.as_ref(), id).await
    }

    async fn get_commitment(&self) -> Result<CommitmentResponse, PrismApiError> {
        PrismApi::get_commitment(self.sequencer.as_ref()).await
    }

    async fn post_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<impl PendingTransaction<Timer = Self::Timer>, PrismApiError> {
        PrismApi::post_transaction(self.sequencer.as_ref(), transaction).await
    }
}

#[cfg(test)]
mod tests;
