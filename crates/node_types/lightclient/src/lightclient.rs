use anyhow::{Context, Result};
use prism_common::digest::Digest;
use prism_da::{celestia::CelestiaConfig, DataAvailabilityLayer};
use prism_errors::{DataAvailabilityError, GeneralError};
use prism_keys::VerifyingKey;
use std::{self, sync::Arc};
use tokio::{sync::broadcast, task::spawn};

pub const PRISM_ELF: &[u8] = include_bytes!("../../../../elf/riscv32im-succinct-zkvm-elf");

#[allow(dead_code)]
pub struct LightClient {
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub prover_pubkey: Option<VerifyingKey>,
    pub vkey_bytes: String,
    pub start_height: u64,
}

#[allow(dead_code)]
impl LightClient {
    pub fn new(
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: CelestiaConfig,
        prover_pubkey: Option<VerifyingKey>,
        vkey_bytes: String,
    ) -> LightClient {
        LightClient {
            da,
            vkey_bytes,
            prover_pubkey,
            start_height: cfg.start_height,
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        // start listening for new headers to update sync target
        self.da
            .start()
            .await
            .map_err(|e| DataAvailabilityError::InitializationError(e.to_string()))
            .context("Failed to start DataAvailabilityLayer")?;

        self.sync_loop()
            .await
            .map_err(|e| GeneralError::InitializationError(e.to_string()))
            .context("Sync loop failed")
    }

    async fn sync_loop(self: Arc<Self>) -> Result<(), tokio::task::JoinError> {
        info!("starting SNARK sync loop");
        let start_height = self.start_height;
        spawn(async move {
            let mut current_position = start_height;
            let mut height_rx = self.da.subscribe_to_heights();

            loop {
                match height_rx.recv().await {
                    Ok(target) => {
                        for i in current_position..target {
                            trace!("processing height: {}", i);
                            match self.da.get_finalized_epoch(i + 1).await {
                                Ok(Some(finalized_epoch)) => {
                                    debug!("light client: got epochs at height {}", i + 1);

                                    // TODO: Issue #144
                                    if let Some(pubkey) = &self.prover_pubkey {
                                        match finalized_epoch.verify_signature(*pubkey) {
                                            Ok(_) => trace!(
                                                "valid signature for epoch {}",
                                                finalized_epoch.height
                                            ),
                                            Err(e) => {
                                                panic!("invalid signature in epoch {}: {:?}", i, e)
                                            }
                                        }
                                    }

                                    // Commitment verification
                                    let prev_commitment = &finalized_epoch.prev_commitment;
                                    let current_commitment = &finalized_epoch.current_commitment;
                                    let public_values = finalized_epoch.proof.public_values.clone();

                                    let mut slice = [0u8; 32];
                                    slice.copy_from_slice(&public_values.as_slice()[..32]);
                                    let proof_prev_commitment: Digest = Digest::from(slice);
                                    let mut slice = [0u8; 32];
                                    slice.copy_from_slice(&public_values.to_vec()[32..64]);
                                    let proof_current_commitment: Digest = Digest::from(slice);
                                    if prev_commitment != &proof_prev_commitment
                                        || current_commitment != &proof_current_commitment
                                    {
                                        error!(
                                            "Commitment mismatch:
                                            prev_commitment: {:?}, proof_prev_commitment: {:?},
                                            current_commitment: {:?}, proof_current_commitment: {:?}",
                                            prev_commitment, proof_prev_commitment,
                                            current_commitment, proof_current_commitment
                                        );
                                        panic!("Commitment mismatch in epoch {}", finalized_epoch.height);
                                    }

                                    // SNARK verification
                                    #[cfg(feature = "mock_prover")]
                                    info!("mock_prover is activated, skipping proof verification");
                                    #[cfg(not(feature = "mock_prover"))]
                                    match sp1_verifier::Groth16Verifier::verify(
                                        &finalized_epoch.proof.bytes(),
                                        public_values.as_slice(),
                                        &self.vkey_bytes,
                                        &sp1_verifier::GROTH16_VK_BYTES,
                                    ) {
                                        Ok(_) => info!(
                                            "zkSNARK for epoch {} was validated successfully",
                                            finalized_epoch.height
                                        ),
                                        Err(err) => panic!(
                                            "failed to validate epoch at height {}: {:?}",
                                            finalized_epoch.height, err
                                        ),
                                    }
                                }
                                Ok(None) => {
                                    debug!("no finalized epoch found at height: {}", i + 1);
                                }
                                Err(e) => debug!("light client: getting epoch: {}", e),
                            };
                        }
                        current_position = target;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        error!("Height channel closed unexpectedly");
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!("Lagged behind by {} messages", skipped);
                    }
                }
            }
        })
        .await
    }
}
