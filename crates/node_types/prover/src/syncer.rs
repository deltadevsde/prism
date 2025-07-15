use anyhow::{Context, Result, anyhow};
use prism_common::transaction::Transaction;
use prism_da::{DataAvailabilityLayer, VerifiableEpoch};
use prism_events::{EventPublisher, PrismEvent};
use prism_keys::VerifyingKey;
use prism_storage::database::Database;
use prism_telemetry_registry::metrics_registry::get_metrics;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tokio_util::sync::CancellationToken;

use crate::{prover_engine::ProverEngine, sequencer::Sequencer, tx_buffer::TxBuffer};

#[derive(Clone)]
pub struct Syncer {
    da: Arc<dyn DataAvailabilityLayer>,
    db: Arc<Box<dyn Database>>,
    tx_buffer: Arc<RwLock<TxBuffer>>,
    verifying_key: VerifyingKey,
    max_epochless_gap: u64,
    latest_epoch_da_height: Arc<RwLock<u64>>,
    start_height: u64,
    sequencer: Arc<Sequencer>,
    prover_engine: Arc<ProverEngine>,
    event_pub: Arc<EventPublisher>,
    is_prover_enabled: bool,
}

impl Syncer {
    pub fn new(
        da: Arc<dyn DataAvailabilityLayer>,
        db: Arc<Box<dyn Database>>,
        config: &crate::prover::SyncerConfig,
        latest_epoch_da_height: Arc<RwLock<u64>>,
        sequencer: Arc<Sequencer>,
        prover_engine: Arc<ProverEngine>,
    ) -> Self {
        let event_pub = Arc::new(da.event_channel().publisher());

        Self {
            da,
            db,
            tx_buffer: Arc::new(RwLock::new(TxBuffer::new())),
            verifying_key: config.verifying_key.clone(),
            max_epochless_gap: config.max_epochless_gap,
            latest_epoch_da_height,
            start_height: config.start_height,
            sequencer,
            prover_engine,
            event_pub,
            is_prover_enabled: config.prover_enabled,
        }
    }

    pub fn get_da(&self) -> Arc<dyn DataAvailabilityLayer> {
        self.da.clone()
    }

    pub async fn start(&self, cancellation_token: CancellationToken) -> Result<()> {
        self.da.start().await?;
        self.run_main_loop(cancellation_token).await
    }

    async fn run_main_loop(&self, cancellation_token: CancellationToken) -> Result<()> {
        let mut height_rx = self.da.subscribe_to_heights();
        let historical_sync_height = height_rx.recv().await?;

        let sync_start_height = match self.db.get_last_synced_height() {
            Ok(height) => height,
            Err(_) => {
                debug!("no existing sync height found, setting sync height to start_height");
                self.db.set_last_synced_height(&self.start_height)?;
                self.start_height
            }
        };

        self.sync_loop(
            sync_start_height,
            historical_sync_height,
            height_rx,
            cancellation_token,
        )
        .await
    }

    async fn sync_loop(
        &self,
        start_height: u64,
        end_height: u64,
        mut incoming_heights: broadcast::Receiver<u64>,
        cancellation_token: CancellationToken,
    ) -> Result<()> {
        let mut current_height = start_height;

        self.event_pub.send(PrismEvent::HistoricalSyncCompleted {
            height: (Some(current_height)),
        });

        while current_height <= end_height {
            tokio::select! {
                result = self.process_da_height(
                    current_height,
                    false,
                ) => {
                    result?;
                    self.db.set_last_synced_height(&current_height)?;
                    current_height += 1;
                },
                _ = cancellation_token.cancelled() => {
                    info!("Syncer: Gracefully stopping during historical sync at height {}", current_height);
                    return Ok(());
                }
            }
        }

        info!(
            "finished historical sync from height {} to {}",
            start_height, end_height
        );

        loop {
            tokio::select! {
                height_result = incoming_heights.recv() => {
                    let height = height_result?;
                    if height != current_height {
                        return Err(anyhow!(
                            "heights are not sequential: expected {}, got {}",
                            current_height,
                            height
                        ));
                    }
                    self.process_da_height(
                        height,
                        true,
                    ).await?;
                    self.event_pub.send(PrismEvent::UpdateDAHeight {
                        height: (current_height),
                    });
                    current_height += 1;
                    self.db.set_last_synced_height(&current_height)?;
                },
                _ = cancellation_token.cancelled() => {
                    info!("Syncer: Gracefully stopping during real-time sync at height {}", current_height);
                    return Ok(());
                }
            }
        }
    }

    async fn process_da_height(&self, height: u64, is_real_time: bool) -> Result<()> {
        let next_epoch_height = match self.db.get_latest_epoch_height() {
            Ok(height) => height + 1,
            Err(_) => 0,
        };

        let transactions = self.da.get_transactions(height).await?;
        let epoch_result = self.da.get_finalized_epochs(height).await?;

        trace!(
            "DA query at height {}: {} transactions, epoch present: {}",
            height,
            transactions.len(),
            !epoch_result.is_empty()
        );

        debug!(
            "processing {} height {}, next_epoch_height: {}",
            if is_real_time { "new" } else { "old" },
            height,
            next_epoch_height
        );

        if !epoch_result.is_empty() {
            for epoch in epoch_result {
                debug!(
                    "Found finalized epoch {} at height {}",
                    epoch.height(),
                    height
                );
                self.process_epoch(epoch).await?;
            }
        } else {
            self.event_pub.send(PrismEvent::NoEpochFound { height: (height) });
            debug!("No epoch found at height {}", height);
        }

        let mut tx_buffer = self.tx_buffer.write().await;
        if is_real_time && tx_buffer.contains_pending() && self.is_prover_enabled {
            let all_transactions: Vec<Transaction> = tx_buffer.take_to_range(height);
            debug!(
                "Starting epoch {} finalization with {} transactions at DA height {}",
                next_epoch_height,
                all_transactions.len(),
                height
            );
            self.sequencer
                .finalize_new_epoch(
                    next_epoch_height,
                    all_transactions,
                    &self.prover_engine,
                    height,
                )
                .await?;
        }

        if !transactions.is_empty() {
            tx_buffer.insert_at_height(height, transactions);
            return Ok(());
        }

        // Create a gap epoch if necessary
        let latest_epoch_height = *self.latest_epoch_da_height.read().await;
        if latest_epoch_height != 0
            && height.saturating_sub(latest_epoch_height) >= self.max_epochless_gap
        {
            self.sequencer
                .finalize_new_epoch(next_epoch_height, Vec::new(), &self.prover_engine, height)
                .await?;
        }

        if let Some(metrics) = get_metrics() {
            metrics.record_celestia_synced_height(height, vec![]);
            metrics.record_current_epoch(next_epoch_height, vec![]);
        }

        Ok(())
    }

    async fn process_epoch(&self, epoch: VerifiableEpoch) -> Result<()> {
        let current_epoch = match self.db.get_latest_epoch_height() {
            Ok(height) => height + 1,
            Err(_) => 0,
        };

        let height = epoch.height();
        let da_height = epoch.da_height();
        let finalized_epoch = epoch.try_convert().unwrap();

        if height < current_epoch {
            debug!("epoch {} already processed internally", current_epoch);
            return Ok(());
        }

        let commitments;
        // See the documentation of [`ProverEngine::verify_proof`] for an explanation of this cfg
        // enabled block.
        #[cfg(test)]
        {
            commitments = epoch.commitments();
            finalized_epoch.verify_signature(self.verifying_key.clone())?;
            self.prover_engine.verify_proof(epoch).await?;
        }
        #[cfg(not(test))]
        {
            commitments =
                epoch.verify(&self.verifying_key, &self.prover_engine.verification_keys())?;
        }

        let (proof_prev_commitment, proof_current_commitment) =
            (commitments.previous, commitments.current);

        let prev_commitment = if height == 0 {
            self.sequencer.get_commitment().await?
        } else {
            self.db
                .get_epoch(&(height - 1))
                .with_context(|| format!("previous epoch {} missing in DB", height - 1))?
                .current_commitment
        };

        if height != current_epoch {
            return Err(anyhow!(
                "epoch height mismatch: expected {}, got {}",
                current_epoch,
                height
            ));
        }

        if proof_prev_commitment != prev_commitment {
            return Err(anyhow!(
                "previous commitment mismatch at epoch {}",
                current_epoch
            ));
        }

        // Only execute transactions up to the tip DA height that the prover used
        let mut tx_buffer = self.tx_buffer.write().await;
        let transactions_to_execute = tx_buffer.take_to_range(da_height);

        if !transactions_to_execute.is_empty() {
            self.sequencer.execute_block(transactions_to_execute).await?;
        }

        let new_commitment = self.sequencer.get_commitment().await?;
        if proof_current_commitment != new_commitment {
            return Err(anyhow!(
                "new commitment mismatch at epoch {}",
                current_epoch
            ));
        }

        debug!(
            "processed epoch {}. new commitment: {:?}",
            current_epoch, new_commitment
        );

        self.db.add_epoch(&finalized_epoch)?;

        Ok(())
    }
}
