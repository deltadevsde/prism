use anyhow::{Context, Result};
use ed25519_consensus::VerificationKey as VerifyingKey;
use prism_common::digest::Digest;
use prism_da::{celestia::CelestiaConfig, DataAvailabilityLayer};
use prism_errors::{DataAvailabilityError, GeneralError};
use sp1_sdk::{ProverClient, SP1VerifyingKey};
use std::{self, sync::{Arc, Mutex}};
use tokio::{sync::broadcast, task::spawn};

pub const PRISM_ELF: &[u8] = include_bytes!("../../../../elf/riscv32im-succinct-zkvm-elf");

#[allow(dead_code)]
pub struct LightClient {
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub prover_pubkey: Option<VerifyingKey>,
    pub client: ProverClient,
    pub verifying_key: SP1VerifyingKey,
    pub start_height: u64,
    current_epoch: Arc<Mutex<u64>>,
}

#[allow(dead_code)]
impl LightClient {
    pub fn new(
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: CelestiaConfig,
        prover_pubkey: Option<VerifyingKey>,
    ) -> LightClient {
        #[cfg(feature = "mock_prover")]
        let client = ProverClient::mock();
        #[cfg(not(feature = "mock_prover"))]
        let client = ProverClient::local();
        let (_, verifying_key) = client.setup(PRISM_ELF);

        LightClient {
            da,
            verifying_key,
            client,
            prover_pubkey,
            start_height: cfg.start_height,
            current_epoch: Arc::new(Mutex::new(0)),
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
        // let current_epoch = Arc::clone(&self.current_epoch);
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
                                            Ok(_) => trace!("valid signature for epoch {}", finalized_epoch.height),
                                            Err(e) => panic!("invalid signature in epoch {}: {:?}", i, e),
                                        }
                                    }

                                    debug!("verifying commitment for epoch {}", finalized_epoch.height);

                                    // Commitment verification
                                    let prev_commitment = &finalized_epoch.prev_commitment;
                                    debug!("prev_commitment: {:?}", prev_commitment);
                                    let current_commitment = &finalized_epoch.current_commitment;
                                    debug!("current_commitment: {:?}", current_commitment);
                                    let public_values = finalized_epoch.proof.public_values.clone();
                                    debug!("public_values: {:?}", public_values);
                                    let mut slice = [0u8; 32];
                                    slice.copy_from_slice(&public_values.as_slice()[..32]);
                                    let proof_prev_commitment: Digest = Digest::from(slice);
                                    debug!("proof_prev_commitment: {:?}", proof_prev_commitment);
                                    let mut slice = [0u8; 32];
                                    slice.copy_from_slice(&public_values.to_vec()[32..64]);
                                    let proof_current_commitment: Digest = Digest::from(slice);
                                    debug!("proof_current_commitment: {:?}", proof_current_commitment);

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
                                        continue;
                                    }

                                    debug!("verifying zkSNARK for epoch {}", finalized_epoch.height);

                                    // SNARK verification with timeout
                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(5),
                                        async {
                                            self.client.verify(&finalized_epoch.proof, &self.verifying_key)
                                        }
                                    ).await {
                                        Ok(Ok(_)) => {
                                            info!("zkSNARK for epoch {} was validated successfully", finalized_epoch.height);
                                            // let mut epoch_guard = current_epoch.lock().unwrap();
                                            // *epoch_guard = finalized_epoch.height;
                                        },
                                        Ok(Err(err)) => {
                                            info!("failed to validate epoch at height {}: {:?}", finalized_epoch.height, err);
                                            error!("failed to validate epoch at height {}: {:?}", finalized_epoch.height, err);
                                            continue;
                                        },
                                        Err(_) => {
                                            info!("timeout while validating epoch at height {}", finalized_epoch.height);
                                            error!("timeout while validating epoch at height {}", finalized_epoch.height);
                                            continue;
                                        },
                                    }

                                    debug!("verified zkSNARK for epoch {}", finalized_epoch.height);
                                },
                                Ok(None) => {
                                    debug!("no finalized epoch found at height: {}", i + 1);
                                },
                                Err(e) => {
                                    error!("light client: error getting epoch at height {}: {:?}", i + 1, e);
                                    continue;
                                },
                            };
                        }
                        current_position = target;
                    },
                    Err(broadcast::error::RecvError::Closed) => {
                        warn!("Height channel closed unexpectedly");
                        break;
                    },
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!("Lagged behind by {} messages", skipped);
                    },
                }
            }
        })
        .await
    }

    // pub fn get_current_epoch(&self) -> Result<u64> {
    //     let epoch_guard = self.current_epoch.lock().unwrap();
    //     Ok(*epoch_guard)
    // }
}
