use crate::{
    common::Operation,
    da::{DataAvailabilityLayer, FinalizedEpoch},
};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, Duration};

#[derive(Clone)]
pub struct InMemoryDataAvailabilityLayer {
    blocks: Arc<RwLock<Vec<Block>>>,
    pending_operations: Arc<RwLock<Vec<Operation>>>,
    pending_epochs: Arc<RwLock<Vec<FinalizedEpoch>>>,
    latest_height: Arc<RwLock<u64>>,
    height_update_tx: broadcast::Sender<u64>,
    block_time: u64,
}

struct Block {
    height: u64,
    operations: Vec<Operation>,
    epochs: Vec<FinalizedEpoch>,
}

impl InMemoryDataAvailabilityLayer {
    pub fn new(block_time: u64) -> (Self, broadcast::Receiver<u64>) {
        let (tx, rx) = broadcast::channel(100);
        (
            Self {
                blocks: Arc::new(RwLock::new(Vec::new())),
                pending_operations: Arc::new(RwLock::new(Vec::new())),
                pending_epochs: Arc::new(RwLock::new(Vec::new())),
                latest_height: Arc::new(RwLock::new(0)),
                height_update_tx: tx,
                block_time,
            },
            rx,
        )
    }

    async fn produce_blocks(self: Arc<Self>) {
        let mut interval = interval(Duration::from_secs(self.block_time));
        loop {
            interval.tick().await;
            let mut blocks = self.blocks.write().await;
            let mut pending_operations = self.pending_operations.write().await;
            let mut pending_epochs = self.pending_epochs.write().await;
            let mut latest_height = self.latest_height.write().await;

            *latest_height += 1;
            let new_block = Block {
                height: *latest_height,
                operations: std::mem::take(&mut *pending_operations),
                epochs: std::mem::take(&mut *pending_epochs),
            };
            blocks.push(new_block);

            // Notify subscribers of the new height
            let _ = self.height_update_tx.send(*latest_height);
        }
    }
}

#[async_trait]
impl DataAvailabilityLayer for InMemoryDataAvailabilityLayer {
    async fn get_latest_height(&self) -> Result<u64> {
        Ok(*self.latest_height.read().await)
    }

    async fn initialize_sync_target(&self) -> Result<u64> {
        self.get_latest_height().await
    }

    async fn get_snarks(&self, height: u64) -> Result<Vec<FinalizedEpoch>> {
        let blocks = self.blocks.read().await;
        Ok(blocks
            .iter()
            .find(|block| block.height == height)
            .map(|block| block.epochs.clone())
            .unwrap_or_default())
    }

    async fn submit_snarks(&self, epochs: Vec<FinalizedEpoch>) -> Result<u64> {
        let mut pending_epochs = self.pending_epochs.write().await;
        pending_epochs.extend(epochs);
        self.get_latest_height().await
    }

    async fn get_operations(&self, height: u64) -> Result<Vec<Operation>> {
        let blocks = self.blocks.read().await;
        Ok(blocks
            .iter()
            .find(|block| block.height == height)
            .map(|block| block.operations.clone())
            .unwrap_or_default())
    }

    async fn submit_operations(&self, operations: Vec<Operation>) -> Result<u64> {
        let mut pending_operations = self.pending_operations.write().await;
        pending_operations.extend(operations);
        self.get_latest_height().await
    }

    async fn start(&self) -> Result<()> {
        let this = Arc::new(self.clone());
        tokio::spawn(async move {
            this.produce_blocks().await;
        });
        Ok(())
    }
}
