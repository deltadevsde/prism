use anyhow::Result;
use prism_common::digest::Digest;
use prism_da::{LightDataAvailabilityLayer, VerifiableEpoch, VerificationKeys};
use prism_events::{EventChannel, EventPublisher, PrismEvent, utils::spawn_task};
use prism_keys::VerifyingKey;
#[cfg(feature = "telemetry")]
use prism_telemetry_registry::metrics_registry::get_metrics;
use std::{self, sync::Arc};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[allow(unused_imports)]
use sp1_verifier::Groth16Verifier;

<<<<<<< HEAD
use prism_da::{
    events::{EventPublisher, PrismEvent},
    utils::spawn_task,
};

// Embed the JSON content directly in the binary at compile time because we can't read files in
// WASM.
=======
// Embed the JSON content directly in the binary at compile time because we can't read files in WASM.
>>>>>>> 6f0d040 (Added events crate)
const EMBEDDED_KEYS_JSON: &str = include_str!("../../../../verification_keys/keys.json");
const MAX_BACKWARD_SEARCH_DEPTH: u64 = 1000;

pub fn load_sp1_verifying_keys() -> Result<VerificationKeys> {
    let keys: VerificationKeys = serde_json::from_str(EMBEDDED_KEYS_JSON)?;
    Ok(keys)
}

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
    ) -> LightClient {
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
        }
    }

    pub async fn get_sync_state(&self) -> SyncState {
        self.sync_state.read().await.clone()
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        // start listening for new headers to update sync target

        let mut event_sub = self.event_chan.subscribe();
        self.event_pub.send(PrismEvent::Ready);

        let mut backwards_sync_started = false;

        loop {
            tokio::select! {
                info = event_sub.recv() => {
                    match info {
                        Ok(event_info) => {
                            if let PrismEvent::UpdateDAHeight { height } = event_info.event {
                                info!("new height from headersub {}", height);

                                #[cfg(feature = "telemetry")]
                                if let Some(metrics) = get_metrics() {
                                    metrics.record_celestia_synced_height(height, vec![]);
                                    if let Some(latest_finalized_epoch) =
                                        self.sync_state.read().await.latest_finalized_epoch
                                    {
                                        metrics.record_current_epoch(latest_finalized_epoch, vec![]);
                                    }
                                }

                                // start initial historical backward sync if not already in progress
                                if backwards_sync_started {
                                    self.clone().handle_new_header(height).await;
                                } else {
                                    backwards_sync_started = true;
                                    self.clone().start_backward_sync(height, self.cancellation_token.clone()).await;
                                }
                            }
                        },
                        Err(e) => {
                            info!("Light Client: Stopping after subscriber error");
                            return Err(e.into());
                        }
                    };
                },
                _ = self.cancellation_token.cancelled() => {
                    info!("Light Client: Gracefully stopping after cancellation");
                    return Ok(());
                }
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
                drop(state_handle);
                return;
            }
        }

        // Check for a new finalized epoch at this height
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

                self.event_pub.send(PrismEvent::BackwardsSyncCompleted {
                    height: Some(da_height),
                });

                // Stop searching if a single epoch is processed successfully
                Ok(())
            }
            // This is the only branch that should trigger the
            // while loop to continue, the other branches all
            // return
            Err(e) => {
                error!("Failed to process epoch at height {}: {}", da_height, e);
                self.event_pub.send(PrismEvent::EpochVerificationFailed {
                    height: da_height,
                    error: e.to_string(),
                });

                let mut state = self.sync_state.write().await;
                state.current_height = da_height;

                Err(e)
            }
        }
    }

    async fn start_backward_sync(
        self: Arc<Self>,
        network_height: u64,
        cancellation_token: CancellationToken,
    ) {
        info!("starting historical sync");
        // Announce that sync has started
        self.event_pub.send(PrismEvent::BackwardsSyncStarted {
            height: network_height,
        });
        self.event_pub.send(PrismEvent::RecursiveVerificationStarted {
            height: network_height,
        });

        // Start a task to find a finalized epoch by searching backward
        let light_client = Arc::clone(&self);

        spawn_task(async move {
            // Find the most recent valid epoch by searching backward
            let mut current_height = network_height;
            let min_height = if current_height > MAX_BACKWARD_SEARCH_DEPTH {
                current_height - MAX_BACKWARD_SEARCH_DEPTH
            } else {
                1
            };
            while current_height >= min_height {
                tokio::select! {
                    // Look backwards for the first height with epochs
                    maybe_epoch = light_client.find_most_recent_epoch(current_height, min_height) => {
                        match maybe_epoch {
                            Some((da_height, epochs)) => {
                                // Try to find a single valid epoch
                                for epoch in epochs {
                                    if light_client.clone().verify_epoch(da_height, epoch).await.is_err() {
                                        // Keep looking backwards, as long as we haven't reached min_height
                                        current_height = da_height - 1;
                                    }
                                }
                            },
                            None => {
                                // This case happens when the incoming sync finds an epoch
                                // before the backwards sync does, or we have exhausted
                                // minimum height
                                light_client
                                    .event_pub
                                    .send(PrismEvent::BackwardsSyncCompleted { height: None });
                                return;
                            }
                        }
                    },
                    _ = cancellation_token.cancelled() => {
                        info!("Light Client: Gracefully stopping backward sync");
                        return;
                    }
                }
            }
        });
    }

    async fn find_most_recent_epoch(
        &self,
        start_height: u64,
        min_height: u64,
    ) -> Option<(u64, Vec<VerifiableEpoch>)> {
        let mut height = start_height;
        while height >= min_height {
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
                return Err(anyhow::anyhow!(e));
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
