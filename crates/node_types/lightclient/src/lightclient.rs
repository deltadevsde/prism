use anyhow::Result;
use lumina_node::events::NodeEvent;
use prism_common::digest::Digest;
use prism_da::{FinalizedEpoch, LightDataAvailabilityLayer};
use prism_keys::VerifyingKey;
use serde::Deserialize;
use std::{
    self,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::RwLock;

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

#[derive(Deserialize)]
pub struct VerificationKeys {
    pub base_vk: String,
    pub recursive_vk: String,
}

// Embed the JSON content directly in the binary at compile time because we can't read files in WASM.
const EMBEDDED_KEYS_JSON: &str = include_str!("../../../../verification_keys/keys.json");

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
    pub prover_pubkey: Option<VerifyingKey>,
    /// The verification key for both (base and recursive) SP1 programs, generated within the build process (with just build).
    pub sp1_vkeys: VerificationKeys,
    /// The event publisher.
    pub event_publisher: EventPublisher,
    // The latest commitment.
    latest_commitment: Arc<RwLock<Option<Digest>>>,
    sync_target: Arc<AtomicU64>,
}

#[allow(dead_code)]
impl LightClient {
    pub fn new(
        #[cfg(not(target_arch = "wasm32"))] da: Arc<dyn LightDataAvailabilityLayer + Send + Sync>,
        #[cfg(target_arch = "wasm32")] da: Arc<dyn LightDataAvailabilityLayer>,
        start_height: u64,
        prover_pubkey: Option<VerifyingKey>,
        event_publisher: EventPublisher,
    ) -> LightClient {
        let sp1_vkeys = load_sp1_verifying_keys().expect("Failed to load SP1 verifying keys");
        LightClient {
            da,
            sp1_vkeys,
            prover_pubkey,
            event_publisher,
            latest_commitment: Arc::new(RwLock::new(None)),
            sync_target: Arc::new(AtomicU64::new(start_height)),
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        // start listening for new headers to update sync target
        if let Some(lumina_event_subscriber) = self.da.event_subscriber() {
            let light_client = self.clone();

            spawn_task({
                let lumina_event_subscriber = lumina_event_subscriber.clone();
                async move {
                    let mut current_height = 0; // Will be set when we do our first sync
                    let mut subscriber = lumina_event_subscriber.lock().await;
                    let mut performed_initial_search = false;

                    while let Ok(event_info) = subscriber.recv().await {
                        light_client.event_publisher.send(LightClientEvent::LuminaEvent {
                            event: event_info.event.clone(),
                        });

                        if let NodeEvent::AddedHeaderFromHeaderSub { height } = event_info.event {
                            light_client.sync_target.store(height, Ordering::Relaxed);
                            light_client
                                .event_publisher
                                .send(LightClientEvent::UpdateDAHeight { height });

                            // If we haven't done our initial backward search yet
                            if !performed_initial_search {
                                performed_initial_search = true;

                                // First height we've received, so announce starting sync
                                light_client
                                    .event_publisher
                                    .send(LightClientEvent::SyncStarted { height });

                                light_client.event_publisher.send(
                                    LightClientEvent::RecursiveVerificationStarted { height },
                                );

                                // Search backward from the network height
                                let mut latest_epoch_height = height;

                                // Continue searching until we find an epoch or reach height 0
                                loop {
                                    if let Ok(Some(_)) = light_client
                                        .da
                                        .get_finalized_epoch(latest_epoch_height)
                                        .await
                                    {
                                        if let Err(e) =
                                            light_client.process_epoch(latest_epoch_height).await
                                        {
                                            error!(
                                                "Failed to process epoch at height {}: {}",
                                                latest_epoch_height, e
                                            );
                                        } else {
                                            light_client.event_publisher.send(
                                                LightClientEvent::RecursiveVerificationCompleted {
                                                    height: latest_epoch_height,
                                                },
                                            );
                                            current_height = latest_epoch_height + 1;
                                        }
                                        break;
                                    }

                                    // If we've reached height 0 and found no epoch, break out
                                    if latest_epoch_height == 0 {
                                        // If no epoch found, just start from the current network height, there was no previous prism epoch
                                        if current_height == 0 {
                                            current_height = height;
                                        }
                                        break;
                                    }

                                    latest_epoch_height -= 1;
                                }
                            }

                            // Process any new heights
                            if height > current_height {
                                for h in current_height..height {
                                    if let Err(e) = light_client.process_epoch(h + 1).await {
                                        error!(
                                            "Failed to process epoch at height {}: {}",
                                            h + 1,
                                            e
                                        );
                                    }
                                }
                                current_height = height;
                            }
                        }
                    }
                }
            });
        }

        Ok(())
    }

    async fn process_epoch(&self, height: u64) -> Result<()> {
        self.event_publisher.send(LightClientEvent::EpochVerificationStarted { height });

        match self.da.get_finalized_epoch(height).await {
            Ok(Some(finalized_epoch)) => {
                if let Some(pubkey) = &self.prover_pubkey {
                    finalized_epoch
                        .verify_signature(pubkey.clone())
                        .map_err(|e| anyhow::anyhow!("Invalid signature: {:?}", e))?;
                }

                if finalized_epoch.public_values.len() < 64 {
                    return Err(anyhow::anyhow!(
                        "Public values length is less than 64 bytes"
                    ));
                }

                // Extract and verify commitments
                let (proof_prev_commitment, proof_current_commitment) =
                    self.extract_commitments(&finalized_epoch.public_values)?;

                self.verify_commitments(
                    &finalized_epoch,
                    proof_prev_commitment,
                    proof_current_commitment,
                )?;

                // Update latest commitment
                self.latest_commitment.write().await.replace(proof_current_commitment);

                // Verify SNARK proof
                #[cfg(not(feature = "mock_prover"))]
                self.verify_snark_proof(
                    &finalized_epoch,
                    finalized_epoch.public_values.as_slice(),
                )?;

                #[cfg(feature = "mock_prover")]
                info!("mock_prover is activated, skipping proof verification");
                // lets say the mocked proof is valid
                self.event_publisher.send(LightClientEvent::EpochVerified {
                    height: finalized_epoch.height,
                });

                Ok(())
            }
            Ok(None) => {
                self.event_publisher.send(LightClientEvent::NoEpochFound { height });
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

    #[cfg(not(feature = "mock_prover"))]
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
