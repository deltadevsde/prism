#![cfg_attr(target_arch = "wasm32", allow(unused))]
#[cfg(not(target_arch = "wasm32"))]
use crate::DataAvailabilityLayer;
use crate::{
    FinalizedEpoch, LightDataAvailabilityLayer, VerifiableEpoch, error::DataAvailabilityError,
};
use anyhow::Result;
use async_trait::async_trait;
use prism_common::transaction::Transaction;
use prism_cross_target::tasks::TaskManager;
use prism_events::{EventChannel, PrismEvent};
use std::sync::Arc;
use tokio::{
    sync::{RwLock, broadcast},
    time::{Duration, interval},
};
use tracing::debug;

const IN_MEMORY_DEFAULT_BLOCK_TIME: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
pub struct Block {
    pub height: u64,
    pub transactions: Vec<Transaction>,
    pub epochs: Vec<FinalizedEpoch>,
}

pub struct InMemoryDataAvailabilityLayer {
    blocks: Arc<RwLock<Vec<Block>>>,
    pending_transactions: Arc<RwLock<Vec<Transaction>>>,
    pending_epochs: Arc<RwLock<Vec<FinalizedEpoch>>>,
    latest_height: Arc<RwLock<u64>>,
    height_update_tx: broadcast::Sender<u64>,
    block_update_tx: broadcast::Sender<Block>,
    block_time: Duration,
    event_channel: EventChannel,

    // For testing: Because mock proofs are generated very quickly, it is
    // helpful to delay the posting of the epoch to test some latency scenarios.
    epoch_posting_delay: Option<Duration>,

    /// Task manager for background tasks
    task_manager: TaskManager,
}

impl Default for InMemoryDataAvailabilityLayer {
    fn default() -> Self {
        Self::new(IN_MEMORY_DEFAULT_BLOCK_TIME, EventChannel::new()).0
    }
}

impl InMemoryDataAvailabilityLayer {
    pub fn new(
        block_time: Duration,
        event_channel: EventChannel,
    ) -> (Self, broadcast::Receiver<u64>, broadcast::Receiver<Block>) {
        let (height_tx, height_rx) = broadcast::channel(100);
        let (block_tx, block_rx) = broadcast::channel(100);
        (
            Self {
                blocks: Arc::new(RwLock::new(Vec::new())),
                pending_transactions: Arc::new(RwLock::new(Vec::new())),
                pending_epochs: Arc::new(RwLock::new(Vec::new())),
                latest_height: Arc::new(RwLock::new(0)),
                height_update_tx: height_tx,
                block_update_tx: block_tx,
                block_time,
                event_channel,
                epoch_posting_delay: None,
                task_manager: TaskManager::new(),
            },
            height_rx,
            block_rx,
        )
    }

    pub fn new_with_epoch_delay(
        block_time: Duration,
        epoch_delay: Duration,
        event_channel: EventChannel,
    ) -> (Self, broadcast::Receiver<u64>, broadcast::Receiver<Block>) {
        let (height_tx, height_rx) = broadcast::channel(100);
        let (block_tx, block_rx) = broadcast::channel(100);
        (
            Self {
                blocks: Arc::new(RwLock::new(Vec::new())),
                pending_transactions: Arc::new(RwLock::new(Vec::new())),
                pending_epochs: Arc::new(RwLock::new(Vec::new())),
                latest_height: Arc::new(RwLock::new(0)),
                height_update_tx: height_tx,
                block_update_tx: block_tx,
                block_time,
                event_channel,
                epoch_posting_delay: Some(epoch_delay),
                task_manager: TaskManager::new(),
            },
            height_rx,
            block_rx,
        )
    }

    fn produce_blocks(&self) -> Result<(), DataAvailabilityError> {
        let blocks = self.blocks.clone();
        let pending_transactions = self.pending_transactions.clone();
        let pending_epochs = self.pending_epochs.clone();
        let latest_height = self.latest_height.clone();
        let height_update_tx = self.height_update_tx.clone();
        let block_update_tx = self.block_update_tx.clone();
        let event_publisher = self.event_channel.publisher();
        let block_time = self.block_time;

        self.task_manager
            .spawn(|token| async move {
                let mut interval = interval(block_time);
                loop {
                    tokio::select! {
                        _ = token.triggered() => {
                            debug!("Memory DA block production cancelled");
                            break;
                        }
                        _ = interval.tick() => {
                            let mut blocks = blocks.write().await;
                            let mut pending_transactions = pending_transactions.write().await;
                            let mut pending_epochs = pending_epochs.write().await;
                            let mut latest_height = latest_height.write().await;

                            *latest_height += 1;
                            let new_block = Block {
                                height: *latest_height,
                                transactions: std::mem::take(&mut *pending_transactions),
                                epochs: std::mem::take(&mut *pending_epochs),
                            };
                            debug!(
                                "new block produced at height {} with {} transactions",
                                new_block.height,
                                new_block.transactions.len(),
                            );
                            blocks.push(new_block.clone());

                            // Notify subscribers of the new height and block
                            let _ = height_update_tx.send(*latest_height);
                            let _ = block_update_tx.send(new_block);

                            // Publish UpdateDAHeight event
                            event_publisher.send(PrismEvent::UpdateDAHeight {
                                height: *latest_height,
                            });
                        }
                    }
                }
            })
            .map_err(|e| {
                DataAvailabilityError::InitializationError(format!(
                    "failed to spawn block producer: {}",
                    e
                ))
            })
    }

    pub fn subscribe_blocks(&self) -> broadcast::Receiver<Block> {
        self.block_update_tx.subscribe()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl LightDataAvailabilityLayer for InMemoryDataAvailabilityLayer {
    async fn start(&self) -> Result<(), DataAvailabilityError> {
        // Check if already started
        if self.task_manager.is_running() {
            return Ok(());
        }

        self.produce_blocks()
    }

    async fn stop(&self) -> Result<(), DataAvailabilityError> {
        self.task_manager
            .stop()
            .await
            .map_err(|e| DataAvailabilityError::ShutdownError(e.to_string()))
    }

    async fn get_finalized_epochs(&self, height: u64) -> Result<Vec<VerifiableEpoch>> {
        let blocks = self.blocks.read().await;
        match blocks.get(height.saturating_sub(1) as usize) {
            Some(block) => Ok(block
                .epochs
                .clone()
                .into_iter()
                .map(|epoch| Box::new(epoch) as VerifiableEpoch)
                .collect()),
            None => Ok(vec![]),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl DataAvailabilityLayer for InMemoryDataAvailabilityLayer {
    async fn get_latest_height(&self) -> Result<u64> {
        Ok(*self.latest_height.read().await)
    }

    async fn submit_finalized_epoch(&self, epoch: FinalizedEpoch) -> Result<u64> {
        // wait for epoch posting delay
        if let Some(delay) = self.epoch_posting_delay {
            tokio::time::sleep(delay).await;
        }

        let mut pending_epochs = self.pending_epochs.write().await;
        pending_epochs.push(epoch);
        let height = self.get_latest_height().await?;
        Ok(height + 1)
    }

    async fn get_transactions(&self, height: u64) -> Result<Vec<Transaction>> {
        let blocks = self.blocks.read().await;
        match blocks.get(height.saturating_sub(1) as usize) {
            Some(block) => Ok(block.transactions.clone()),
            None => Ok(vec![]),
        }
    }

    async fn submit_transactions(&self, transactions: Vec<Transaction>) -> Result<u64> {
        let mut pending_transactions = self.pending_transactions.write().await;
        pending_transactions.extend(transactions);
        let height = self.get_latest_height().await?;
        Ok(height + 1)
    }
}
