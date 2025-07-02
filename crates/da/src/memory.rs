#![cfg(not(target_arch = "wasm32"))]
use crate::{
    DataAvailabilityLayer, FinalizedEpoch, LightDataAvailabilityLayer, VerifiableEpoch,
    events::{EventChannel, PrismEvent},
};
use anyhow::Result;
use async_trait::async_trait;
use prism_common::transaction::Transaction;
use std::sync::Arc;
use tokio::{
    sync::{RwLock, broadcast},
    time::{Duration, interval},
};
use tracing::debug;

#[derive(Clone, Debug)]
pub struct Block {
    pub height: u64,
    pub transactions: Vec<Transaction>,
    pub epochs: Vec<FinalizedEpoch>,
}

#[derive(Clone)]
pub struct InMemoryDataAvailabilityLayer {
    blocks: Arc<RwLock<Vec<Block>>>,
    pending_transactions: Arc<RwLock<Vec<Transaction>>>,
    pending_epochs: Arc<RwLock<Vec<FinalizedEpoch>>>,
    latest_height: Arc<RwLock<u64>>,
    height_update_tx: broadcast::Sender<u64>,
    block_update_tx: broadcast::Sender<Block>,
    block_time: Duration,
    event_channel: Arc<EventChannel>,

    // For testing: Because mock proofs are generated very quickly, it is
    // helpful to delay the posting of the epoch to test some latency scenarios.
    epoch_posting_delay: Option<Duration>,
}

impl InMemoryDataAvailabilityLayer {
    pub fn new(
        block_time: Duration,
    ) -> (Self, broadcast::Receiver<u64>, broadcast::Receiver<Block>) {
        let (height_tx, height_rx) = broadcast::channel(100);
        let (block_tx, block_rx) = broadcast::channel(100);
        let event_channel = Arc::new(EventChannel::new());
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
            },
            height_rx,
            block_rx,
        )
    }

    pub fn new_with_epoch_delay(
        block_time: Duration,
        epoch_delay: Duration,
    ) -> (Self, broadcast::Receiver<u64>, broadcast::Receiver<Block>) {
        let (height_tx, height_rx) = broadcast::channel(100);
        let (block_tx, block_rx) = broadcast::channel(100);
        let event_channel = Arc::new(EventChannel::new());
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
            },
            height_rx,
            block_rx,
        )
    }

    async fn produce_blocks(self: Arc<Self>) {
        let mut interval = interval(self.block_time);
        let event_publisher = self.event_channel.publisher();
        loop {
            interval.tick().await;
            let mut blocks = self.blocks.write().await;
            let mut pending_transactions = self.pending_transactions.write().await;
            let mut pending_epochs = self.pending_epochs.write().await;
            let mut latest_height = self.latest_height.write().await;

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
            let _ = self.height_update_tx.send(*latest_height);
            let _ = self.block_update_tx.send(new_block);

            // Publish UpdateDAHeight event
            event_publisher.send(PrismEvent::UpdateDAHeight {
                height: *latest_height,
            });
        }
    }

    pub fn subscribe_blocks(&self) -> broadcast::Receiver<Block> {
        self.block_update_tx.subscribe()
    }
}

#[async_trait]
impl LightDataAvailabilityLayer for InMemoryDataAvailabilityLayer {
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

    fn event_channel(&self) -> Arc<EventChannel> {
        self.event_channel.clone()
    }
}

#[async_trait]
impl DataAvailabilityLayer for InMemoryDataAvailabilityLayer {
    async fn start(&self) -> Result<()> {
        let this = Arc::new(self.clone());
        tokio::spawn(async move {
            this.produce_blocks().await;
        });
        Ok(())
    }

    fn subscribe_to_heights(&self) -> broadcast::Receiver<u64> {
        self.height_update_tx.subscribe()
    }

    async fn get_latest_height(&self) -> Result<u64> {
        Ok(*self.latest_height.read().await)
    }

    async fn initialize_sync_target(&self) -> Result<u64> {
        self.get_latest_height().await
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
