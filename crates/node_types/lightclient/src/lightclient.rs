use anyhow::Result;
use prism_common::digest::Digest;
use prism_da::{LightDataAvailabilityLayer, VerifiableEpoch, VerificationKeys};
use prism_events::{EventChannel, EventPublisher, PrismEvent};
use prism_keys::VerifyingKey;
#[cfg(feature = "telemetry")]
use prism_telemetry_registry::metrics_registry::get_metrics;
use std::{self, sync::Arc};
use tokio::sync::RwLock;
#[cfg(not(target_arch = "wasm32"))]
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

#[allow(unused_imports)]
use sp1_verifier::Groth16Verifier;
// Embed the JSON content directly in the binary at compile time because we can't read files in
// WASM.
const EMBEDDED_KEYS_JSON: &str = include_str!("../../../../verification_keys/keys.json");
const MAX_BACKWARD_SEARCH_DEPTH: u64 = 1000;

pub fn load_sp1_verifying_keys() -> Result<VerificationKeys> {
    let keys: VerificationKeys = serde_json::from_str(EMBEDDED_KEYS_JSON)?;
    Ok(keys)
}

/// Macro to handle event subscription with cancellation support
macro_rules! select_with_cancellation {
    ($cancellation_token:expr, {
        $($event_arm:tt)*
    }) => {
        tokio::select! {
            $($event_arm)*
            _ = $cancellation_token.cancelled() => {
                info!("Light Client: Gracefully stopping due to cancellation");
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
                        info!("Light Client: Stopping after subscriber error");
                        return Err(e.into());
                    }
                }
            }
            _ = $cancellation_token.cancelled() => {
                info!("Light Client: Gracefully stopping due to cancellation");
                return Ok(());
            }
        }
    };
}

/// A Prism light client for efficient network participation with minimal resource requirements.
///
/// ## Lifecycle
///
/// 1. **Initialization**: Created via factory methods with DA layer and verifying key
/// 2. **Backward Sync**: Searches for the most recent valid epoch on startup
/// 3. **Forward Sync**: Processes new epochs as they arrive from the DA layer
/// 4. **Event Processing**: Publishes verification results and sync status updates
///
/// Light clients are designed to be long-running and will continue processing
/// new epochs until cancelled via the provided cancellation token.
pub struct LightClient {
    #[cfg(not(target_arch = "wasm32"))]
    pub da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
    #[cfg(target_arch = "wasm32")]
    pub da: Arc<dyn LightDataAvailabilityLayer>,
    /// The public key of the prover, used for verifying the signature of the epochs.
    pub prover_pubkey: VerifyingKey,
    /// The verification key for both (base and recursive) SP1 programs, generated within the build
    /// process (with just build).
    pub sp1_vkeys: VerificationKeys,
    /// The event channel, used to spawn new subscribers and publishers.
    event_chan: Arc<EventChannel>,
    event_pub: Arc<EventPublisher>,
    sync_state: Arc<RwLock<SyncState>>,
    cancellation_token: CancellationToken,

    // The latest commitment.
    latest_commitment: Arc<RwLock<Option<Digest>>>,

    mock_proof_verification: bool,
}

#[derive(Default, Clone)]
pub struct SyncState {
    /// The current synced DA height of the light client.
    pub current_height: u64,
    /// The current synced epoch height of the light client.
    pub latest_finalized_epoch: Option<u64>,
}

#[allow(dead_code)]
impl LightClient {
    pub fn new(
        #[cfg(not(target_arch = "wasm32"))] da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
        #[cfg(target_arch = "wasm32")] da: Arc<dyn LightDataAvailabilityLayer>,
        prover_pubkey: VerifyingKey,
        cancellation_token: CancellationToken,
    ) -> Self {
        let sp1_vkeys = load_sp1_verifying_keys().expect("Failed to load SP1 verifying keys");

        let event_chan = da.event_channel();
        let event_pub = Arc::new(event_chan.publisher());

        let sync_state = Arc::new(RwLock::new(SyncState::default()));

        Self {
            da,
            sp1_vkeys,
            prover_pubkey,
            event_chan,
            event_pub,
            latest_commitment: Arc::new(RwLock::new(None)),
            sync_state,
            cancellation_token,
            mock_proof_verification: false,
        }
    }

    pub fn enable_mock_proof_verification(&mut self) {
        error!("PROOF VERIFICATION IS DISABLED");
        self.mock_proof_verification = true;
    }

    pub async fn get_sync_state(&self) -> SyncState {
        self.sync_state.read().await.clone()
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let (_, _) =
            std::future::join!(self.clone().sync_incoming_heights(), self.sync_backwards()).await;

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let mut futures = JoinSet::new();

        let lc = Arc::clone(&self);
        futures.spawn(async move { lc.sync_incoming_heights().await });

        let lc = Arc::clone(&self);
        futures.spawn(async move { lc.sync_backwards().await });

        futures.join_all().await;

        Ok(())
    }

    async fn sync_incoming_heights(self: Arc<Self>) -> Result<()> {
        let mut event_sub = self.event_chan.subscribe();
        self.event_pub.send(PrismEvent::Ready);

        loop {
            await_event!(self.cancellation_token, event_sub, |event| {
                trace!("Event: {:?}", event);
                if let PrismEvent::UpdateDAHeight { height } = event {
                    info!("new height from headersub {}", height);
                    self.clone().handle_new_header(height).await;
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

    async fn handle_new_header(self: Arc<Self>, height: u64) {
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
    async fn process_height(self: Arc<Self>, height: u64) {
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
                error!("failed to fetch data at height {}", e)
            }
        }
    }

    async fn verify_epoch(self: Arc<Self>, da_height: u64, epoch: VerifiableEpoch) -> Result<()> {
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

    async fn sync_backwards(self: Arc<Self>) -> Result<()> {
        info!("starting backwards sync");

        let mut event_sub = self.event_chan.subscribe();
        let network_height = loop {
            await_event!(self.cancellation_token, event_sub, |event| {
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
            select_with_cancellation!(self.cancellation_token, {
                // Look backwards for the first height with epochs
                maybe_epoch = self.find_most_recent_epoch(current_height, min_height) => {
                    match maybe_epoch {
                        Some((da_height, epochs)) => {
                            // Try to find a single valid epoch
                            for epoch in epochs {
                                match self.clone().verify_epoch(da_height, epoch).await {
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

    pub async fn get_latest_commitment(&self) -> Option<Digest> {
        *self.latest_commitment.read().await
    }
}
