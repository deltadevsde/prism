use anyhow::Result;
use prism_common::digest::Digest;
use prism_da::{LightDataAvailabilityLayer, VerifiableEpoch, VerificationKeys};
use prism_events::{EventChannel, EventPublisher, PrismEvent};
use prism_keys::VerifyingKey;
#[cfg(feature = "telemetry")]
use prism_telemetry_registry::metrics_registry::get_metrics;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

const MAX_BACKWARD_SEARCH_DEPTH: u64 = 1000;

/// Macro to handle event subscription with cancellation support
macro_rules! select_with_cancellation {
    ($cancellation_token:expr, {
        $($event_arm:tt)*
    }) => {
        tokio::select! {
            $($event_arm)*
            _ = $cancellation_token.cancelled() => {
                info!("Syncer: Gracefully stopping due to cancellation");
                return Ok(());
            }
        };
    };
}

/// Macro for generating a `tokio::select!` arm for event subscription
macro_rules! await_event {
    ($cancellation_token:expr, $event_sub:expr, |$event_var:ident| $handler:block) => {
        tokio::select! {
            event_res = $event_sub.recv() => {
                match event_res {
                    Ok(event_info) => {
                        let $event_var = event_info.event;
                        $handler
                    }
                    Err(e) => {
                        info!("Syncer: Stopping after subscriber error");
                        return Err(e.into());
                    }
                }
            }
            _ = $cancellation_token.cancelled() => {
                info!("Syncer: Gracefully stopping due to cancellation");
                return Ok(());
            }
        }
    };
}

#[derive(Default, Clone)]
pub struct SyncState {
    /// The current synced DA height of the light client.
    pub current_height: u64,
    /// The current synced epoch height of the light client.
    pub latest_finalized_epoch: Option<u64>,
}

/// Handles synchronization operations for the light client
pub struct Syncer {
    #[cfg(not(target_arch = "wasm32"))]
    da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
    #[cfg(target_arch = "wasm32")]
    da: Arc<dyn LightDataAvailabilityLayer>,
    pub prover_pubkey: VerifyingKey,
    sp1_vkeys: VerificationKeys,
    event_chan: Arc<EventChannel>,
    event_pub: Arc<EventPublisher>,
    sync_state: Arc<RwLock<SyncState>>,
    latest_commitment: Arc<RwLock<Option<Digest>>>,
    mock_proof_verification: bool,
}

impl Syncer {
    pub fn new(
        #[cfg(not(target_arch = "wasm32"))] da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
        #[cfg(target_arch = "wasm32")] da: Arc<dyn LightDataAvailabilityLayer>,
        prover_pubkey: VerifyingKey,
        sp1_vkeys: VerificationKeys,
        mock_proof_verification: bool,
    ) -> Self {
        let event_chan = da.event_channel();
        let event_pub = Arc::new(event_chan.publisher());
        let sync_state = Arc::new(RwLock::new(SyncState::default()));
        let latest_commitment = Arc::new(RwLock::new(None));

        Self {
            da,
            prover_pubkey,
            sp1_vkeys,
            event_chan,
            event_pub,
            sync_state,
            latest_commitment,
            mock_proof_verification,
        }
    }

    pub async fn get_sync_state(&self) -> SyncState {
        self.sync_state.read().await.clone()
    }

    pub async fn get_latest_commitment(&self) -> Option<Digest> {
        *self.latest_commitment.read().await
    }

    pub async fn sync_incoming_heights(&self, cancellation_token: CancellationToken) -> Result<()> {
        let mut event_sub = self.event_chan.subscribe();
        self.event_pub.send(PrismEvent::Ready);

        loop {
            await_event!(cancellation_token, event_sub, |event| {
                trace!("Event: {:?}", event);
                if let PrismEvent::UpdateDAHeight { height } = event {
                    info!("new height from headersub {}", height);
                    self.handle_new_header(height).await;
                }
            });
        }
    }

    #[cfg(feature = "telemetry")]
    async fn collect_metrics(&self, height: u64) {
        #[cfg(feature = "telemetry")]
        if let Some(metrics) = get_metrics() {
            metrics.record_celestia_synced_height(height, vec![]);
            if let Some(latest_finalized_epoch) =
                self.sync_state.read().await.latest_finalized_epoch
            {
                metrics.record_current_epoch(latest_finalized_epoch, vec![]);
            }
        }
    }

    async fn handle_new_header(&self, height: u64) {
        {
            let state_handle = self.sync_state.read().await;
            if state_handle.current_height > height {
                warn!(
                    "new height from headersub {} is lower than synced height, skipping",
                    height
                );
                return;
            }
            // if current height is not initialized yet, backwards sync has yet to be started
            else if state_handle.current_height == 0 {
                return
            }
            drop(state_handle);
        }
        #[cfg(feature = "telemetry")]
        self.collect_metrics(height).await;
        self.process_height(height).await;
    }

    /// Checks for a new finalized epoch at this height
    async fn process_height(&self, height: u64) {
        match self.da.get_finalized_epochs(height).await {
            Ok(epochs) => {
                if epochs.is_empty() {
                    info!("no data found at height {}", height);
                }

                for epoch in epochs {
                    let epoch_height = epoch.height();
                    // Found a new finalized epoch, process it immediately
                    if self.process_epoch(epoch).await.is_ok() {
                        self.event_pub.send(PrismEvent::RecursiveVerificationCompleted { height });

                        // Update our latest known finalized epoch
                        let mut state = self.sync_state.write().await;
                        state.latest_finalized_epoch = Some(epoch_height);
                        state.current_height = height;
                    }
                }
            }
            Err(e) => {
                error!("failed to fetch data at height {}: {}", height, e)
            }
        }
    }

    async fn verify_epoch(&self, da_height: u64, epoch: VerifiableEpoch) -> Result<()> {
        let epoch_height = epoch.height();
        match self.process_epoch(epoch).await {
            Ok(_) => {
                info!(
                    "found historical finalized epoch at da height {}",
                    da_height
                );
                self.event_pub
                    .send(PrismEvent::RecursiveVerificationCompleted { height: da_height });

                let mut state = self.sync_state.write().await;
                if state.latest_finalized_epoch.is_none() {
                    state.latest_finalized_epoch = Some(epoch_height);
                    state.current_height = da_height;
                }

                self.event_pub.send(PrismEvent::HistoricalSyncCompleted {
                    height: Some(da_height),
                });

                // Stop searching if a single epoch is processed successfully
                Ok(())
            }
            Err(e) => {
                self.event_pub.send(PrismEvent::EpochVerificationFailed {
                    height: da_height,
                    error: e.to_string(),
                });

                Err(e)
            }
        }
    }

    pub async fn sync_backwards(&self, cancellation_token: CancellationToken) -> Result<()> {
        info!("starting backwards sync");

        let mut event_sub = self.event_chan.subscribe();
        let network_height = loop {
            await_event!(cancellation_token, event_sub, |event| {
                if let PrismEvent::UpdateDAHeight { height } = event {
                    let mut sync_state = self.sync_state.write().await;
                    sync_state.current_height = height;
                    break height;
                }
            });
        };

        // Announce that sync has started
        self.event_pub.send(PrismEvent::HistoricalSyncStarted {
            height: network_height,
        });
        self.event_pub.send(PrismEvent::RecursiveVerificationStarted {
            height: network_height,
        });

        // Find the most recent valid epoch by searching backward
        let mut current_height = network_height;
        let min_height = if current_height > MAX_BACKWARD_SEARCH_DEPTH {
            current_height - MAX_BACKWARD_SEARCH_DEPTH
        } else {
            1
        };
        while current_height >= min_height {
            let sync_state = self.sync_state.read().await;
            // [`sync_incoming_heights`] can find the first epoch before backwards sync finishes.
            if sync_state.latest_finalized_epoch.is_some() {
                self.event_pub.send(PrismEvent::HistoricalSyncCompleted { height: None });
                return Ok(());
            }
            drop(sync_state);
            select_with_cancellation!(cancellation_token, {
                // Look backwards for the first height with epochs
                maybe_epoch = self.find_most_recent_epoch(current_height, min_height) => {
                    match maybe_epoch {
                        Some((da_height, epochs)) => {
                            // Try to find a single valid epoch
                            for epoch in epochs {
                                match self.verify_epoch(da_height, epoch).await {
                                    Ok(_) => {
                                        // Found a valid epoch, stop looking backwards
                                        self
                                            .event_pub
                                            .send(PrismEvent::HistoricalSyncCompleted { height: Some(da_height) });
                                        return Ok(());
                                    }
                                    Err(_) => {
                                        // Keep looking backwards, as long as we haven't reached min_height
                                        current_height = da_height - 1;
                                    }
                                };
                            }
                        },
                        None => {
                            // This case happens when the incoming sync finds an epoch
                            // before the backwards sync does, or we have exhausted
                            // minimum height
                            self
                                .event_pub
                                .send(PrismEvent::HistoricalSyncCompleted { height: None });
                            return Ok(());
                        }
                    };
                }
            });
        }
        Ok(())
    }

    async fn find_most_recent_epoch(
        &self,
        start_height: u64,
        min_height: u64,
    ) -> Option<(u64, Vec<VerifiableEpoch>)> {
        let mut height = start_height;
        while height >= min_height {
            // We yield here because this operation is quite blocking
            #[cfg(not(target_arch = "wasm32"))]
            tokio::task::yield_now().await;

            // if an epoch has been found, we no longer need to sync historically
            if self.sync_state.read().await.latest_finalized_epoch.is_some() {
                info!(
                    "abandoning historical sync after finding recursive proof at incoming height"
                );
                return None;
            }

            match self.da.get_finalized_epochs(height).await {
                Ok(epochs) => {
                    if epochs.is_empty() {
                        info!("no data found at height {}", height);
                        let mut state = self.sync_state.write().await;
                        state.current_height = height;
                    } else {
                        return Some((height, epochs));
                    }
                }
                Err(e) => {
                    error!("failed to fetch data at height {}: {}", height, e)
                }
            }

            self.event_pub.send(PrismEvent::NoEpochFound { height });
            height -= 1;
        }

        info!(
            "abandoning historical sync after exhausting last {} heights",
            MAX_BACKWARD_SEARCH_DEPTH
        );
        None
    }

    async fn process_epoch(&self, epoch: VerifiableEpoch) -> Result<()> {
        let commitments = match epoch.verify(&self.prover_pubkey, &self.sp1_vkeys) {
            Ok(commitments) => commitments,
            Err(e) => {
                error!("failed to verify epoch at height {}: {}", epoch.height(), e);
                self.event_pub.send(PrismEvent::EpochVerificationFailed {
                    height: epoch.height(),
                    error: e.to_string(),
                });
                if !self.mock_proof_verification {
                    return Err(anyhow::anyhow!(e));
                }
                epoch.commitments()
            }
        };
        let curr_commitment = commitments.current;

        // Update latest commitment
        self.latest_commitment.write().await.replace(curr_commitment);

        self.event_pub.send(PrismEvent::EpochVerified {
            height: epoch.height(),
        });

        Ok(())
    }
}
