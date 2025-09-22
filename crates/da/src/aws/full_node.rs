#![cfg(not(target_arch = "wasm32"))]

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use prism_common::transaction::Transaction;
use prism_errors::DataAvailabilityError;
use prism_events::{EventChannel, PrismEvent};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::{
    sync::{RwLock, broadcast},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    DataAvailabilityLayer, FinalizedEpoch, LightDataAvailabilityLayer, VerifiableEpoch,
    aws::client::{AwsDaMetaInfo, AwsDataAvailabilityClient},
};

use super::config::AwsFullNodeDAConfig;

/// AWS S3-based full node data availability layer.
///
/// This implementation provides full read-write access to both finalized epochs and
/// transaction data using AWS S3 with WORM (Write Once Read Many) compliance through
/// S3 Object Lock features.
///
/// # Features
///
/// - **WORM Compliance**: Automatic Object Lock with configurable retention periods
/// - **Legal Holds**: Additional protection for critical data beyond retention periods
/// - **Cross-Region Replication**: Automatic data replication for disaster recovery
/// - **Concurrent Uploads**: Parallel transaction publishing with rate limiting
/// - **Height Broadcasting**: Real-time height updates to network participants
/// - **Automatic Retry**: Exponential backoff for transient failures
///
/// # WORM Workflow
///
/// For each published object, the system:
/// 1. **Upload**: Write data to S3 with temporary accessibility
/// 2. **Lock**: Apply Object Lock with compliance mode and retention period
/// 3. **Hold**: Optionally apply legal hold for additional protection
/// 4. **Verify**: Confirm successful upload and lock application
/// 5. **Broadcast**: Notify network of data availability
pub struct AwsFullNodeDataAvailabilityLayer {
    /// AWS S3 client for data operations
    client: Arc<AwsDataAvailabilityClient>,

    /// Current height with built-in synchronization for race condition protection
    current_height: Arc<RwLock<u64>>,

    /// Transaction offset for the current height
    transaction_offset: Arc<AtomicU64>,

    /// Block time for the network
    block_time: Duration,

    /// Height update broadcaster
    height_update_tx: broadcast::Sender<u64>,

    /// Event channel for publishing data availability events
    event_channel: Arc<EventChannel>,

    /// Flag to track if the service has been started
    started: Arc<AtomicBool>,

    /// Cancellation token for graceful shutdown
    cancellation_token: CancellationToken,
}

impl AwsFullNodeDataAvailabilityLayer {
    pub async fn new(
        config: &AwsFullNodeDAConfig,
        cancellation_token: CancellationToken,
    ) -> Result<Self, DataAvailabilityError> {
        let client = AwsDataAvailabilityClient::new_from_full_da_config(config.clone()).await?;

        let (height_update_tx, _) = broadcast::channel(100);
        let event_channel = Arc::new(EventChannel::new());

        debug!(
            "AWS full node initialized for region '{}', epochs bucket '{}', retention {} days",
            config.light_client.region, config.light_client.epochs_bucket, config.retention_days
        );

        Ok(Self {
            client: Arc::new(client),
            current_height: Arc::new(RwLock::new(1)),
            transaction_offset: Arc::new(AtomicU64::new(0)),
            block_time: config.light_client.block_time,
            height_update_tx,
            event_channel,
            started: Arc::new(AtomicBool::new(false)),
            cancellation_token,
        })
    }

    async fn produce_blocks(&self) -> Result<(), DataAvailabilityError> {
        let client = self.client.clone();
        let current_height = self.current_height.clone();
        let height_update_tx = self.height_update_tx.clone();
        let event_publisher = self.event_channel.publisher();
        let block_time = self.block_time;
        let transaction_offset = self.transaction_offset.clone();
        let cancellation_token = self.cancellation_token.clone();

        let _handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        info!("AWS full node block production cancelled");
                        break;
                    }
                    _ = tokio::time::sleep(block_time) => {

                // Take write lock to atomically increment height and prevent submissions
                let mut height_guard = current_height.write().await;
                let completed_height = *height_guard;
                *height_guard += 1;
                drop(height_guard);

                // Reset transaction offset for new height
                transaction_offset.store(0, Ordering::Relaxed);

                // Broadcast height update
                let _ = height_update_tx.send(completed_height);

                // Publish event
                event_publisher.send(PrismEvent::UpdateDAHeight {
                    height: completed_height,
                });

                // Update metadata
                let metadata = AwsDaMetaInfo {
                    current_height: completed_height,
                };

                if let Err(e) = client.submit_metadata(metadata).await {
                    warn!("Failed to submit metadata: {}", e);
                }

                        info!("Completed block {}", completed_height);
                    }
                }
            }
        });

        debug!("Started height monitoring task with race condition protection");
        Ok(())
    }
}

#[async_trait]
impl LightDataAvailabilityLayer for AwsFullNodeDataAvailabilityLayer {
    async fn start(&self) -> Result<()> {
        // Try to set started flag atomically
        if self.started.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            info!("AWS full node data availability layer already started");
            return Ok(());
        }

        info!("Starting AWS full node data availability layer");

        let current_height = *self.current_height.read().await;
        info!(
            "AWS full node data availability layer started at height {}",
            current_height
        );

        self.produce_blocks().await?;

        Ok(())
    }

    async fn get_finalized_epochs(&self, height: u64) -> Result<Vec<VerifiableEpoch>> {
        self.client
            .fetch_epochs(height)
            .await
            .map(|epochs| epochs.into_iter().map(|e| Box::new(e) as VerifiableEpoch).collect())
            .map_err(|e| anyhow!(e.to_string()))
    }

    fn event_channel(&self) -> Arc<EventChannel> {
        self.event_channel.clone()
    }
}

#[async_trait]
impl DataAvailabilityLayer for AwsFullNodeDataAvailabilityLayer {
    async fn get_latest_height(&self) -> Result<u64> {
        Ok(*self.current_height.read().await)
    }

    async fn get_transactions(&self, height: u64) -> anyhow::Result<Vec<Transaction>> {
        self.client.fetch_transactions(height).await.map_err(|e| anyhow!(e.to_string()))
    }

    async fn submit_finalized_epoch(&self, epoch: FinalizedEpoch) -> Result<u64> {
        // Take read lock to get consistent height and prevent increments during submission
        let height_guard = self.current_height.read().await;
        let current_height = *height_guard;

        self.client.submit_finalized_epoch(epoch, current_height).await?;

        info!("Finalized epoch submitted at height {}", current_height);

        // Return the height where the epoch was published
        Ok(current_height)
    }

    async fn submit_transactions(&self, transactions: Vec<Transaction>) -> Result<u64> {
        // Take read lock to get consistent height and prevent increments during submission
        let height_guard = self.current_height.read().await;
        let height = *height_guard;

        let count = transactions.len() as u64;
        let transaction_offset = self.transaction_offset.fetch_add(count, Ordering::AcqRel);

        self.client.submit_transactions(transactions, transaction_offset, height).await?;

        info!("Transactions submitted at height {}", height);

        Ok(height)
    }

    fn subscribe_to_heights(&self) -> broadcast::Receiver<u64> {
        self.height_update_tx.subscribe()
    }
}
