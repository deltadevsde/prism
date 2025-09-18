use anyhow::{Result, anyhow};
use async_trait::async_trait;
use prism_errors::DataAvailabilityError;
use prism_events::{EventChannel, EventPublisher, PrismEvent};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tracing::{debug, info, warn};

use crate::{LightDataAvailabilityLayer, VerifiableEpoch, aws::client::AwsDataAvailabilityClient};

use super::config::AwsLightClientDAConfig;

/// AWS S3-based light data availability layer.
///
/// This implementation provides read-only access to finalized epochs stored in AWS S3
/// with WORM (Write Once Read Many) compliance. Light clients can efficiently verify
/// data availability through this layer.
#[derive(Clone)]
pub struct AwsLightDataAvailabilityLayer {
    /// AWS S3 client for data operations
    client: AwsDataAvailabilityClient,

    /// Event channel for publishing data availability events
    event_channel: Arc<EventChannel>,

    block_time: Duration,

    /// Flag to track if the service has been started
    started: Arc<AtomicBool>,
}

impl AwsLightDataAvailabilityLayer {
    /// Creates a new AWS light data availability layer.
    pub async fn new(config: &AwsLightClientDAConfig) -> Result<Self, DataAvailabilityError> {
        let client = AwsDataAvailabilityClient::new_from_light_da_config(config.clone()).await?;

        Ok(Self {
            client,
            event_channel: Arc::new(EventChannel::new()),
            block_time: config.block_time,
            started: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Creates an event publisher for this layer.
    pub fn event_publisher(&self) -> EventPublisher {
        self.event_channel.publisher()
    }

    /// Starts the height monitoring background task.
    ///
    /// Since S3 doesn't have built-in height notifications like blockchain nodes,
    /// we simulate height updates by periodically checking for new data and
    /// broadcasting updates when found.
    async fn start_height_monitoring(&self) -> Result<(), DataAvailabilityError> {
        let client = Arc::new(self.client.clone());
        let event_publisher = self.event_channel.publisher();
        let poll_interval = self.block_time;

        let _handle = tokio::spawn(async move {
            let mut last_height = 0u64;

            loop {
                match client.fetch_height().await {
                    Ok(Some(max_height)) => {
                        if max_height > last_height {
                            last_height = max_height;

                            // Publish event
                            event_publisher.send(PrismEvent::UpdateDAHeight { height: max_height });

                            info!("Height updated to {}", max_height);
                        }
                    }
                    Ok(None) => {
                        debug!("No height metadata available yet");
                    }
                    Err(e) => {
                        warn!("Failed to check for height updates: {}", e);
                    }
                }

                tokio::time::sleep(poll_interval).await;
            }
        });

        debug!("Started height monitoring task");
        Ok(())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl LightDataAvailabilityLayer for AwsLightDataAvailabilityLayer {
    async fn start(&self) -> Result<()> {
        // Try to set started flag atomically
        if self.started.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            info!("AWS light data availability layer already started");
            return Ok(());
        }

        info!("Starting AWS light data availability layer");

        self.start_height_monitoring().await?;

        Ok(())
    }

    fn event_channel(&self) -> Arc<EventChannel> {
        self.event_channel.clone()
    }

    async fn get_finalized_epochs(&self, height: u64) -> Result<Vec<VerifiableEpoch>> {
        self.client
            .fetch_epochs(height)
            .await
            .map(|epochs| epochs.into_iter().map(|e| Box::new(e) as VerifiableEpoch).collect())
            .map_err(|e| anyhow!(e.to_string()))
    }
}
