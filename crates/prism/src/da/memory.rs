use crate::da::{DataAvailabilityLayer, FinalizedEpoch};
use anyhow::Result;
use async_trait::async_trait;
use prism_common::operation::Operation;
use std::{collections::VecDeque, sync::Arc};
use tokio::{
    sync::{broadcast, RwLock},
    time::{interval, Duration},
};

#[derive(Clone, Debug)]
pub struct Block {
    pub height: u64,
    pub operations: Vec<Operation>,
    pub epoch: Option<FinalizedEpoch>,
}

#[derive(Clone)]
pub struct InMemoryDataAvailabilityLayer {
    blocks: Arc<RwLock<Vec<Block>>>,
    pending_operations: Arc<RwLock<Vec<Operation>>>,
    pending_epochs: Arc<RwLock<VecDeque<FinalizedEpoch>>>,
    latest_height: Arc<RwLock<u64>>,
    height_update_tx: broadcast::Sender<u64>,
    block_update_tx: broadcast::Sender<Block>,
    block_time: u64,
}

impl InMemoryDataAvailabilityLayer {
    pub fn new(block_time: u64) -> (Self, broadcast::Receiver<u64>, broadcast::Receiver<Block>) {
        let (height_tx, height_rx) = broadcast::channel(100);
        let (block_tx, block_rx) = broadcast::channel(100);
        (
            Self {
                blocks: Arc::new(RwLock::new(Vec::new())),
                pending_operations: Arc::new(RwLock::new(Vec::new())),
                pending_epochs: Arc::new(RwLock::new(VecDeque::new())),
                latest_height: Arc::new(RwLock::new(0)),
                height_update_tx: height_tx,
                block_update_tx: block_tx,
                block_time,
            },
            height_rx,
            block_rx,
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
                epoch: pending_epochs.pop_front(),
            };
            debug!(
                "new block produced at height {} with {} operations",
                new_block.height,
                new_block.operations.len(),
            );
            blocks.push(new_block.clone());

            // Notify subscribers of the new height and block
            let _ = self.height_update_tx.send(*latest_height);
            let _ = self.block_update_tx.send(new_block);
        }
    }

    pub fn subscribe_blocks(&self) -> broadcast::Receiver<Block> {
        self.block_update_tx.subscribe()
    }
}

#[async_trait]
impl DataAvailabilityLayer for InMemoryDataAvailabilityLayer {
    fn subscribe_to_heights(&self) -> broadcast::Receiver<u64> {
        self.height_update_tx.subscribe()
    }

    async fn get_latest_height(&self) -> Result<u64> {
        Ok(*self.latest_height.read().await)
    }

    async fn initialize_sync_target(&self) -> Result<u64> {
        self.get_latest_height().await
    }

    async fn get_finalized_epoch(&self, height: u64) -> Result<Option<FinalizedEpoch>> {
        let blocks = self.blocks.read().await;
        Ok(blocks
            .iter()
            .find(|block| block.height == height)
            .map(|block| block.epoch.clone())
            .unwrap_or_default())
    }

    async fn submit_finalized_epoch(&self, epoch: FinalizedEpoch) -> Result<u64> {
        let mut pending_epochs = self.pending_epochs.write().await;
        pending_epochs.push_back(epoch);
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