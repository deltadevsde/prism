use anyhow::{Context, Result, anyhow};
use prism_da::{DataAvailabilityLayer, FinalizedEpoch};
use prism_keys::VerifyingKey;
use prism_storage::database::Database;
use prism_telemetry_registry::metrics_registry::get_metrics;
use prism_common::transaction::Transaction;
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::{broadcast, RwLock};

use crate::{prover_engine::ProverEngine, sequencer::Sequencer};

#[derive(Clone)]
pub struct Syncer {
    da: Arc<dyn DataAvailabilityLayer>,
    db: Arc<Box<dyn Database>>,
    verifying_key: VerifyingKey,
    max_epochless_gap: u64,
    latest_epoch_da_height: Arc<RwLock<u64>>,
}

impl Syncer {
    pub fn new(
        da: Arc<dyn DataAvailabilityLayer>,
        db: Arc<Box<dyn Database>>,
        verifying_key: VerifyingKey,
        max_epochless_gap: u64,
        latest_epoch_da_height: Arc<RwLock<u64>>,
    ) -> Self {
        Self {
            da,
            db,
            verifying_key,
            max_epochless_gap,
            latest_epoch_da_height,
        }
    }

    pub async fn start_da(&self) -> Result<()> {
        self.da.start().await
    }
    
    pub fn get_da(&self) -> Arc<dyn DataAvailabilityLayer> {
        self.da.clone()
    }

    pub async fn run_main_loop(
        &self,
        start_height: u64,
        sequencer: Arc<Sequencer>,
        prover_engine: Arc<ProverEngine>,
        is_prover_enabled: bool,
    ) -> Result<()> {
        let mut height_rx = self.da.subscribe_to_heights();
        let historical_sync_height = height_rx.recv().await?;

        let sync_start_height = match self.db.get_last_synced_height() {
            Ok(height) => height,
            Err(_) => {
                debug!("no existing sync height found, setting sync height to start_height");
                self.db.set_last_synced_height(&start_height)?;
                start_height
            }
        };

        self.sync_loop(
            sync_start_height,
            historical_sync_height,
            height_rx,
            sequencer,
            prover_engine,
            is_prover_enabled,
        ).await
    }

    async fn sync_loop(
        &self,
        start_height: u64,
        end_height: u64,
        mut incoming_heights: broadcast::Receiver<u64>,
        sequencer: Arc<Sequencer>,
        prover_engine: Arc<ProverEngine>,
        is_prover_enabled: bool,
    ) -> Result<()> {
        let mut buffered_transactions: VecDeque<Transaction> = VecDeque::new();
        let mut current_height = start_height;

        while current_height <= end_height {
            self.process_da_height(
                current_height,
                &mut buffered_transactions,
                false,
                &sequencer,
                &prover_engine,
                is_prover_enabled,
            ).await?;
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
            self.process_da_height(
                height,
                &mut buffered_transactions,
                true,
                &sequencer,
                &prover_engine,
                is_prover_enabled,
            ).await?;
            current_height += 1;
            self.db.set_last_synced_height(&current_height)?;
        }
    }

    async fn process_da_height(
        &self,
        height: u64,
        buffered_transactions: &mut VecDeque<Transaction>,
        is_real_time: bool,
        sequencer: &Arc<Sequencer>,
        prover_engine: &Arc<ProverEngine>,
        is_prover_enabled: bool,
    ) -> Result<()> {
        let next_epoch_height = match self.db.get_latest_epoch_height() {
            Ok(height) => height + 1,
            Err(_) => 0,
        };

        let transactions = self.da.get_transactions(height).await?;
        let epoch_result = self.da.get_finalized_epoch(height).await?;

        debug!(
            "processing {} height {}, next_epoch_height: {}",
            if is_real_time { "new" } else { "old" },
            height,
            next_epoch_height
        );

        if let Some(epoch) = epoch_result {
            self.process_epoch(epoch, buffered_transactions, sequencer, prover_engine).await?;
        } else {
            debug!("No transactions to process at height {}", height);
        }

        if is_real_time && !buffered_transactions.is_empty() && is_prover_enabled {
            let all_transactions: Vec<Transaction> = buffered_transactions.drain(..).collect();
            sequencer.finalize_new_epoch(next_epoch_height, all_transactions, prover_engine).await?;
        }

        if !transactions.is_empty() {
            buffered_transactions.extend(transactions);
            return Ok(());
        }

        let latest_epoch_height = *self.latest_epoch_da_height.read().await;
        if latest_epoch_height != 0
            && height.saturating_sub(latest_epoch_height) >= self.max_epochless_gap
        {
            sequencer.finalize_new_epoch(next_epoch_height, Vec::new(), prover_engine).await?;
        }

        if let Some(metrics) = get_metrics() {
            metrics.record_celestia_synced_height(height, vec![]);
            metrics.record_current_epoch(next_epoch_height, vec![]);
        }

        Ok(())
    }

    async fn process_epoch(
        &self,
        epoch: FinalizedEpoch,
        buffered_transactions: &mut VecDeque<Transaction>,
        sequencer: &Arc<Sequencer>,
        prover_engine: &Arc<ProverEngine>,
    ) -> Result<()> {
        let current_epoch = match self.db.get_latest_epoch_height() {
            Ok(height) => height + 1,
            Err(_) => 0,
        };

        if epoch.height < current_epoch {
            debug!("epoch {} already processed internally", current_epoch);
            return Ok(());
        }

        epoch
            .verify_signature(self.verifying_key.clone())
            .with_context(|| format!("Invalid signature in epoch {}", epoch.height))?;
        trace!("valid signature for epoch {}", epoch.height);

        let prev_commitment = if epoch.height == 0 {
            sequencer.get_commitment().await?
        } else {
            self.db.get_epoch(&epoch.height.saturating_sub(1))?.current_commitment
        };

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
            sequencer.execute_block(all_transactions).await?;
        }

        let new_commitment = sequencer.get_commitment().await?;
        if epoch.current_commitment != new_commitment {
            return Err(anyhow!(
                "new commitment mismatch at epoch {}",
                current_epoch
            ));
        }

        match prover_engine.verify_epoch_proof(epoch.height, &epoch.proof).await {
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

        self.db.add_epoch(&epoch)?;

        Ok(())
    }
}