use anyhow::Result;
use prism_common::digest::Digest;
use prism_da::{
    FinalizedEpoch, LightDataAvailabilityLayer, VerifiableEpoch, VerificationKeys,
    events::EventChannel,
};
use prism_keys::VerifyingKey;
#[cfg(feature = "telemetry")]
use prism_telemetry_registry::metrics_registry::get_metrics;
use std::{self, sync::Arc};
use tokio::sync::RwLock;
use tracing::{error, info};

#[allow(unused_imports)]
use sp1_verifier::Groth16Verifier;

use prism_da::{
    events::{EventPublisher, PrismEvent},
    utils::spawn_task,
};

// Embed the JSON content directly in the binary at compile time because we can't read files in WASM.
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
    /// The verification key for both (base and recursive) SP1 programs, generated within the build process (with just build).
    pub sp1_vkeys: VerificationKeys,
    /// The event channel, used to spawn new subscribers and publishers.
    event_chan: Arc<EventChannel>,
    event_pub: Arc<EventPublisher>,
    sync_state: Arc<RwLock<SyncState>>,

    // The latest commitment.
    latest_commitment: Arc<RwLock<Option<Digest>>>,
}

#[derive(Default, Clone)]
pub struct SyncState {
    pub current_height: u64,
    pub initial_sync_completed: bool,
    pub initial_sync_in_progress: bool,
    pub latest_finalized_epoch: Option<u64>,
}

#[allow(dead_code)]
impl LightClient {
    pub fn new(
        #[cfg(not(target_arch = "wasm32"))] da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
        #[cfg(target_arch = "wasm32")] da: Arc<dyn LightDataAvailabilityLayer>,
        prover_pubkey: VerifyingKey,
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
        }
    }

    pub async fn get_sync_state(&self) -> SyncState {
        self.sync_state.read().await.clone()
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        // start listening for new headers to update sync target

        let mut event_sub = self.event_chan.subscribe();
        self.event_pub.send(PrismEvent::Ready);
        while let Ok(event_info) = event_sub.recv().await {
            if let PrismEvent::UpdateDAHeight { height } = event_info.event {
                #[cfg(feature = "telemetry")]
                if let Some(metrics) = get_metrics() {
                    metrics.record_celestia_synced_height(height, vec![]);
                    if let Some(latest_finalized_epoch) =
                        self.sync_state.read().await.latest_finalized_epoch
                    {
                        metrics.record_current_epoch(latest_finalized_epoch, vec![]);
                    }
                }
                info!("new height from headersub {}", height);
                self.clone().handle_new_header(height).await;
            }
        }

        Ok(())
    }

    async fn handle_new_header(self: Arc<Self>, height: u64) {
        // start initial historical backward sync if needed and not already in progress
        {
            let mut state_handle = self.sync_state.write().await;
            if !state_handle.initial_sync_completed && !state_handle.initial_sync_in_progress {
                state_handle.initial_sync_in_progress = true;
                drop(state_handle);
                self.start_backward_sync(height).await;
                return;
            }
        }

        // Check for a new finalized epoch at this height
        match self.da.get_finalized_epoch(height).await {
            Ok(epochs) => {
                if epochs.is_empty() {
                    info!("no data found at height {}", height);
                }

                for epoch in epochs {
                    // Found a new finalized epoch, process it immediately
                    if self.process_epoch(epoch).await.is_ok() {
                        self.event_pub.send(PrismEvent::RecursiveVerificationCompleted { height });

                        // Update our latest known finalized epoch
                        let mut state = self.sync_state.write().await;
                        state.latest_finalized_epoch = Some(height);

                        // If we're waiting for initial sync, this completes it
                        if state.initial_sync_in_progress && !state.initial_sync_completed {
                            info!("finished initial sync");
                            state.initial_sync_completed = true;
                            state.initial_sync_in_progress = false;
                        }

                        // Update current height to the epoch height + 1
                        state.current_height = height + 1;
                    }
                }
            }
            Err(e) => {
                error!("failed to fetch data at height {}", e)
            }
        }
    }

    async fn start_backward_sync(self: Arc<Self>, network_height: u64) {
        info!("starting historical sync");
        // Announce that sync has started
        self.event_pub.send(PrismEvent::SyncStarted {
            height: network_height,
        });
        self.event_pub.send(PrismEvent::RecursiveVerificationStarted {
            height: network_height,
        });

        // Start a task to find a finalized epoch by searching backward
        let light_client = Arc::clone(&self);

        let state = self.sync_state.clone();
        spawn_task(async move {
            // Find the most recent valid epoch by searching backward
            let mut current_height = network_height;
            let min_height = if current_height > MAX_BACKWARD_SEARCH_DEPTH {
                current_height - MAX_BACKWARD_SEARCH_DEPTH
            } else {
                1
            };
            while current_height >= min_height {
                // Look backwards for the first height with epochs
                if let Some((da_height, epochs)) = light_client
                    .find_most_recent_epoch(current_height, min_height, state.clone())
                    .await
                {
                    // Try to find a single valid epoch
                    for epoch in epochs {
                        let epoch_height = epoch.height();
                        match light_client.process_epoch(epoch).await {
                            Ok(_) => {
                                info!(
                                    "found historical finalized epoch at da height {}",
                                    da_height
                                );
                                light_client.event_pub.send(
                                    PrismEvent::RecursiveVerificationCompleted {
                                        height: da_height,
                                    },
                                );

                                let mut state = state.write().await;
                                state.initial_sync_completed = true;
                                state.initial_sync_in_progress = false;
                                state.latest_finalized_epoch = Some(epoch_height);
                                state.current_height = da_height + 1;

                                // Break out of the loop if a single epoch is processed successfully
                                return;
                            }
                            Err(e) => {
                                error!("Failed to process epoch at height {}: {}", da_height, e);
                                light_client.event_pub.send(PrismEvent::EpochVerificationFailed {
                                    height: da_height,
                                    error: e.to_string(),
                                });

                                // Keep looking backwards, as long as we haven't reached min_height
                                current_height = da_height - 1;
                            }
                        }
                    }
                }

                // No epoch found in backward search, mark initial sync as complete
                // but don't update current height - we'll wait for new epochs
                let mut state = state.write().await;
                state.initial_sync_completed = true;
                state.initial_sync_in_progress = false;
            }
        })
    }

    async fn find_most_recent_epoch(
        &self,
        start_height: u64,
        min_height: u64,
        state: Arc<RwLock<SyncState>>,
    ) -> Option<(u64, Vec<VerifiableEpoch>)> {
        let mut height = start_height;
        while height >= min_height {
            // if an epoch has been found, we no longer need to sync historically
            if state.read().await.latest_finalized_epoch.is_some() {
                info!(
                    "abandoning historical sync after finding recursive proof at incoming height"
                );
                return None;
            }

            match self.da.get_finalized_epoch(height).await {
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
        let commitments = epoch.verify(&self.prover_pubkey, &self.sp1_vkeys)?;
        let curr_commitment = commitments.current;

        // Update latest commitment
        self.latest_commitment.write().await.replace(curr_commitment);

        self.event_pub.send(PrismEvent::EpochVerified {
            height: epoch.height(),
        });

        Ok(())
    }

    /// Returns the count of successfully processed epochs
    async fn process_height(&self, height: u64) -> Result<u64> {
        info!("processing at DA height {}", height);
        self.event_pub.send(PrismEvent::EpochVerificationStarted { height });

        match self.da.get_finalized_epoch(height).await {
            Ok(finalized_epochs) => {
                if finalized_epochs.is_empty() {
                    self.event_pub.send(PrismEvent::NoEpochFound { height });
                }

                // Process each finalized epoch
                let mut count = 0;
                for epoch in finalized_epochs {
                    if let Err(e) = self.process_epoch(epoch).await {
                        let error = format!("Failed to process epoch: {}", e);
                        self.event_pub.send(PrismEvent::EpochVerificationFailed {
                            height,
                            error: error.clone(),
                        });
                    } else {
                        count += 1;
                    }
                }
                Ok(count)
            }
            Err(e) => {
                let error = format!("Failed to get epoch: {}", e);
                self.event_pub.send(PrismEvent::EpochVerificationFailed {
                    height,
                    error: error.clone(),
                });
                Err(anyhow::anyhow!(error))
            }
        }
    }

    fn extract_commitments(&self, public_values: &[u8]) -> Result<(Digest, Digest)> {
        let mut slice = [0u8; 32];
        slice.copy_from_slice(&public_values[..32]);
        let proof_prev_commitment = Digest::from(slice);

        let mut slice = [0u8; 32];
        slice.copy_from_slice(&public_values[32..64]);
        let proof_current_commitment = Digest::from(slice);

        Ok((proof_prev_commitment, proof_current_commitment))
    }

    fn verify_commitments(
        &self,
        finalized_epoch: &FinalizedEpoch,
        proof_prev_commitment: Digest,
        proof_current_commitment: Digest,
    ) -> Result<()> {
        if finalized_epoch.prev_commitment != proof_prev_commitment
            || finalized_epoch.current_commitment != proof_current_commitment
        {
            // maybe we should forwards events for these kind of errors as well.
            return Err(anyhow::anyhow!(
                "Commitment mismatch: prev={:?}/{:?}, current={:?}/{:?}",
                finalized_epoch.prev_commitment,
                proof_prev_commitment,
                finalized_epoch.current_commitment,
                proof_current_commitment
            ));
        }
        Ok(())
    }

    fn verify_snark_proof(
        &self,
        finalized_epoch: &FinalizedEpoch,
        public_values: &[u8],
    ) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        let finalized_epoch_proof = &finalized_epoch.proof;

        #[cfg(not(target_arch = "wasm32"))]
        let finalized_epoch_proof = &finalized_epoch.proof.bytes();

        let vkey = if finalized_epoch.height == 0 {
            &self.sp1_vkeys.base_vk
        } else {
            &self.sp1_vkeys.recursive_vk
        };

        Groth16Verifier::verify(
            finalized_epoch_proof,
            public_values,
            vkey,
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .map_err(|e| anyhow::anyhow!("SNARK verification failed: {:?}", e))
    }
    pub async fn get_latest_commitment(&self) -> Option<Digest> {
        *self.latest_commitment.read().await
    }
}
