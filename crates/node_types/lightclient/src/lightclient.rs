use anyhow::Result;
use lumina_node::events::NodeEvent;
use prism_common::digest::Digest;
use prism_da::{FinalizedEpoch, LightDataAvailabilityLayer, VerifiableEpoch, VerificationKeys};
use prism_keys::VerifyingKey;
#[cfg(feature = "telemetry")]
use prism_telemetry_registry::metrics_registry::get_metrics;
use serde::Deserialize;
use std::{self, future::Future, sync::Arc};
use tokio::sync::RwLock;
use tracing::{error, info};

#[allow(unused_imports)]
use sp1_verifier::Groth16Verifier;

use crate::events::{EventPublisher, LightClientEvent};

#[cfg(target_arch = "wasm32")]
fn spawn_task<F>(future: F)
where
    F: Future<Output = ()> + 'static,
{
    wasm_bindgen_futures::spawn_local(future);
}

#[cfg(not(target_arch = "wasm32"))]
fn spawn_task<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(future);
}

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
    /// The event publisher.
    pub event_publisher: EventPublisher,
    // The latest commitment.
    latest_commitment: Arc<RwLock<Option<Digest>>>,
}

struct SyncState {
    current_height: u64,
    initial_sync_completed: bool,
    initial_sync_in_progress: bool,
    latest_finalized_epoch: Option<u64>,
}

#[allow(dead_code)]
impl LightClient {
    pub fn new(
        #[cfg(not(target_arch = "wasm32"))] da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
        #[cfg(target_arch = "wasm32")] da: Arc<dyn LightDataAvailabilityLayer>,
        prover_pubkey: VerifyingKey,
        event_publisher: EventPublisher,
    ) -> LightClient {
        let sp1_vkeys = load_sp1_verifying_keys().expect("Failed to load SP1 verifying keys");
        LightClient {
            da,
            sp1_vkeys,
            prover_pubkey,
            event_publisher,
            latest_commitment: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        // start listening for new headers to update sync target
        if let Some(lumina_event_subscriber) = self.da.event_subscriber() {
            let mut subscriber = lumina_event_subscriber.lock().await;
            let sync_state = Arc::new(RwLock::new(SyncState {
                current_height: 0,
                initial_sync_completed: false,
                initial_sync_in_progress: false,
                latest_finalized_epoch: None,
            }));
            while let Ok(event_info) = subscriber.recv().await {
                // forward all events to the event publisher
                self.clone().event_publisher.send(LightClientEvent::LuminaEvent {
                    event: event_info.event.clone(),
                });

                if let NodeEvent::AddedHeaderFromHeaderSub { height } = event_info.event {
                    #[cfg(feature = "telemetry")]
                    if let Some(metrics) = get_metrics() {
                        metrics.record_celestia_synced_height(height, vec![]);
                        if let Some(latest_finalized_epoch) =
                            sync_state.read().await.latest_finalized_epoch
                        {
                            metrics.record_current_epoch(latest_finalized_epoch, vec![]);
                        }
                    }
                    info!("new height from headersub {}", height);
                    self.clone().handle_new_header(height, sync_state.clone()).await;
                }
            }
        }

        Ok(())
    }

    async fn handle_new_header(self: Arc<Self>, height: u64, state: Arc<RwLock<SyncState>>) {
        self.event_publisher.send(LightClientEvent::UpdateDAHeight { height });

        // start initial historical backward sync if needed and not already in progress
        {
            let mut state_handle = state.write().await;
            if !state_handle.initial_sync_completed && !state_handle.initial_sync_in_progress {
                state_handle.initial_sync_in_progress = true;
                drop(state_handle);
                self.start_backward_sync(height, state.clone()).await;
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
                        self.event_publisher
                            .send(LightClientEvent::RecursiveVerificationCompleted { height });

                        // Update our latest known finalized epoch
                        let mut state = state.write().await;
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

    async fn start_backward_sync(
        self: Arc<Self>,
        network_height: u64,
        state: Arc<RwLock<SyncState>>,
    ) {
        info!("starting historical sync");
        // Announce that sync has started
        self.event_publisher.send(LightClientEvent::SyncStarted {
            height: network_height,
        });
        self.event_publisher.send(LightClientEvent::RecursiveVerificationStarted {
            height: network_height,
        });

        // Start a task to find a finalized epoch by searching backward
        let light_client = Arc::clone(&self);

        let state = state.clone();
        spawn_task(async move {
            // Find the most recent valid epoch by searching backward
            if let Some(epoch_height) =
                light_client.find_most_recent_epoch(network_height, state.clone()).await
            {
                // Process the found epoch
                match light_client.process_height(epoch_height).await {
                    Ok(_) => {
                        info!(
                            "found historical finalized epoch at height {}",
                            epoch_height
                        );
                        light_client.event_publisher.send(
                            LightClientEvent::RecursiveVerificationCompleted {
                                height: epoch_height,
                            },
                        );

                        let mut state = state.write().await;
                        state.initial_sync_completed = true;
                        state.initial_sync_in_progress = false;
                        state.latest_finalized_epoch = Some(epoch_height);
                        state.current_height = epoch_height + 1;
                    }
                    Err(e) => {
                        error!("Failed to process epoch at height {}: {}", epoch_height, e);
                        light_client.event_publisher.send(
                            LightClientEvent::EpochVerificationFailed {
                                height: epoch_height,
                                error: e.to_string(),
                            },
                        );

                        // Mark initial sync as complete but don't update current height
                        let mut state = state.write().await;
                        state.initial_sync_completed = true;
                        state.initial_sync_in_progress = false;
                    }
                }
            } else {
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
        state: Arc<RwLock<SyncState>>,
    ) -> Option<u64> {
        let mut height = start_height;
        let min_height = if start_height > MAX_BACKWARD_SEARCH_DEPTH {
            start_height - MAX_BACKWARD_SEARCH_DEPTH
        } else {
            1
        };

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
                        return Some(height);
                    }
                }
                Err(e) => {
                    error!("failed to fetch data at height {}: {}", height, e)
                }
            }

            self.event_publisher.send(LightClientEvent::NoEpochFound { height });
            height -= 1;
        }

        info!(
            "abandoning historical sync after exhausting last {} heights",
            MAX_BACKWARD_SEARCH_DEPTH
        );
        None
    }

    async fn process_epoch(&self, epoch: VerifiableEpoch) -> Result<()> {
        let (prev_commitment, curr_commitment) =
            epoch.verify(&self.prover_pubkey, &self.sp1_vkeys)?;

        // Update latest commitment
        self.latest_commitment.write().await.replace(curr_commitment);

        self.event_publisher.send(LightClientEvent::EpochVerified {
            height: epoch.height(),
        });

        Ok(())
    }

    async fn process_height(&self, height: u64) -> Result<()> {
        info!("processing at DA height {}", height);
        self.event_publisher.send(LightClientEvent::EpochVerificationStarted { height });

        match self.da.get_finalized_epoch(height).await {
            Ok(finalized_epochs) => {
                if finalized_epochs.is_empty() {
                    self.event_publisher.send(LightClientEvent::NoEpochFound { height });
                }

                // Process each finalized epoch
                for epoch in finalized_epochs {
                    if let Err(e) = self.process_epoch(epoch).await {
                        let error = format!("Failed to process epoch: {}", e);
                        self.event_publisher.send(LightClientEvent::EpochVerificationFailed {
                            height,
                            error: error.clone(),
                        });
                    }
                }
                Ok(())
            }
            Err(e) => {
                let error = format!("Failed to get epoch: {}", e);
                self.event_publisher.send(LightClientEvent::EpochVerificationFailed {
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
