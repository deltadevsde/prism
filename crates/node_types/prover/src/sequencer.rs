use anyhow::{Context, Result, bail};
use jmt::KeyHash;
use prism_common::{
    account::Account, digest::Digest, operation::Operation, transaction::Transaction,
};
use prism_da::{DataAvailabilityLayer, FinalizedEpoch};
use prism_keys::SigningKey;
use prism_storage::database::Database;
use prism_tree::{
    AccountResponse::*, hasher::TreeHasher, key_directory_tree::KeyDirectoryTree, proofs::Proof,
    snarkable_tree::SnarkableTree,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::prover_engine::engine::ProverEngine;

#[derive(Clone)]
pub struct Sequencer {
    db: Arc<Box<dyn Database>>,
    da: Arc<dyn DataAvailabilityLayer>,
    tree: Arc<RwLock<KeyDirectoryTree<Box<dyn Database>>>>,
    pending_transactions: Arc<RwLock<Vec<Transaction>>>,
    signing_key: Option<SigningKey>,
    latest_epoch_da_height: Arc<RwLock<u64>>,
    batcher_enabled: bool,
}

impl Sequencer {
    pub fn new(
        db: Arc<Box<dyn Database>>,
        da: Arc<dyn DataAvailabilityLayer>,
        config: &crate::prover::SequencerOptions,
        latest_epoch_da_height: Arc<RwLock<u64>>,
    ) -> Result<Self> {
        let saved_epoch = match db.get_latest_epoch_height() {
            Ok(height) => height + 1,
            Err(_) => {
                debug!("no existing epoch state found, starting at epoch 0");
                0
            }
        };

        let tree = Arc::new(RwLock::new(KeyDirectoryTree::load(db.clone(), saved_epoch)));

        Ok(Sequencer {
            db,
            da,
            tree,
            pending_transactions: Arc::new(RwLock::new(Vec::new())),
            signing_key: config.signing_key.clone(),
            latest_epoch_da_height,
            batcher_enabled: config.batcher_enabled,
        })
    }

    pub async fn start(&self, cancellation_token: CancellationToken) -> Result<()> {
        if self.batcher_enabled {
            self.run_batch_poster(cancellation_token).await
        } else {
            // Sequencer without batcher doesn't need a running loop
            // Just wait for cancellation
            cancellation_token.cancelled().await;
            info!("Sequencer: Gracefully stopped (batcher disabled)");
            Ok(())
        }
    }

    async fn run_batch_poster(&self, cancellation_token: CancellationToken) -> Result<()> {
        let mut height_rx = self.da.subscribe_to_heights();

        loop {
            tokio::select! {
                height_result = height_rx.recv() => {
                    let height = height_result?;
                    trace!("received height {}", height);

                    let pending_transactions = {
                        let mut ops = self.pending_transactions.write().await;
                        std::mem::take(&mut *ops)
                    };

                    let tx_count = pending_transactions.len();

                    if tx_count > 0 {
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
                },
                _ = cancellation_token.cancelled() => {
                    info!("Sequencer: Gracefully stopping batch poster");
                    return Ok(());
                }
            }
        }
    }

    pub async fn finalize_new_epoch(
        &self,
        epoch_height: u64,
        transactions: Vec<Transaction>,
        prover_engine: &Arc<dyn ProverEngine>,
        tip_da_height: u64,
    ) -> Result<u64> {
        let mut tree = self.tree.write().await;
        let batch = tree.process_batch(transactions)?;
        batch.verify()?;

        let (snark, stark) = prover_engine.prove_epoch(epoch_height, &batch, &self.db).await?;

        let mut epoch_json = FinalizedEpoch {
            height: epoch_height,
            prev_commitment: batch.prev_root,
            current_commitment: batch.new_root,
            snark,
            stark,
            signature: None,
            tip_da_height,
        };

        let Some(signing_key) = &self.signing_key else {
            bail!("No signing key configured for sequencer, epoch can not be signed.");
        };

        epoch_json.insert_signature(signing_key)?;

        debug!("Submitting finalized epoch height {} to DA", epoch_height);
        let da_height = self.da.submit_finalized_epoch(epoch_json.clone()).await?;
        debug!(
            "Finalized epoch height {} submitted to DA at height {}",
            epoch_height, da_height
        );
        let mut latest_da_height = self.latest_epoch_da_height.write().await;
        *latest_da_height = da_height;

        self.db.add_epoch(&epoch_json)?;

        info!("finalized new epoch at height {}", epoch_height);

        Ok(da_height)
    }

    pub async fn execute_block(&self, transactions: Vec<Transaction>) -> Result<Vec<Proof>> {
        debug!("executing block with {} transactions", transactions.len());

        let mut proofs = Vec::new();

        for transaction in transactions {
            match self.process_transaction(transaction.clone()).await {
                Ok(proof) => proofs.push(proof),
                Err(e) => {
                    warn!(
                        "Failed to process transaction: {:?}. Error: {}",
                        transaction, e
                    );
                }
            }
        }

        Ok(proofs)
    }

    pub async fn validate_and_queue_update(&self, transaction: Transaction) -> Result<()> {
        if !self.batcher_enabled {
            bail!("Batcher is disabled, cannot queue transactions");
        }

        match transaction.operation {
            Operation::RegisterService { .. } | Operation::CreateAccount { .. } => {
                Account::default().process_transaction(&transaction)?;
            }
            Operation::AddKey { .. }
            | Operation::RevokeKey { .. }
            | Operation::AddData { .. }
            | Operation::SetData { .. } => {
                let account_response = self.get_account(&transaction.id).await?;

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

    pub async fn get_commitment(&self) -> Result<Digest> {
        let tree = self.tree.read().await;
        tree.get_commitment().context("Failed to get commitment")
    }

    pub async fn get_account(&self, id: &str) -> Result<prism_tree::AccountResponse> {
        let tree = self.tree.read().await;
        let key_hash = KeyHash::with::<TreeHasher>(id);

        tree.get(key_hash)
    }

    pub fn get_pending_transactions(&self) -> Arc<RwLock<Vec<Transaction>>> {
        self.pending_transactions.clone()
    }

    pub fn get_db(&self) -> Arc<Box<dyn Database>> {
        self.db.clone()
    }

    pub async fn process_transaction(&self, transaction: Transaction) -> Result<Proof> {
        let mut tree = self.tree.write().await;
        tree.process_transaction(transaction)
    }
}
