use crate::cfg::CelestiaConfig;
use anyhow::{Context, Result};
use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use prism_common::tree::Digest;
use prism_errors::{DataAvailabilityError, GeneralError};
use sp1_sdk::{ProverClient, SP1VerifyingKey};
use std::{self, sync::Arc};
use tokio::{sync::broadcast, task::spawn};

use crate::{da::DataAvailabilityLayer, node_types::NodeType};

pub const PRISM_ELF: &[u8] = include_bytes!("../../../../elf/riscv32im-succinct-zkvm-elf");

pub struct LightClient {
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub sequencer_pubkey: Option<VerifyingKey>,
    pub client: ProverClient,
    pub verifying_key: SP1VerifyingKey,
    pub start_height: u64,
}

#[async_trait]
impl NodeType for LightClient {
    async fn start(self: Arc<Self>) -> Result<()> {
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
}

impl LightClient {
    pub fn new(
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: CelestiaConfig,
        sequencer_pubkey: Option<VerifyingKey>,
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
            sequencer_pubkey,
            start_height: cfg.start_height,
        }
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
                        debug!("updated sync target to height {}", target);
                        for i in current_position..target {
                            trace!("processing height: {}", i);
                            match self.da.get_finalized_epoch(i + 1).await {
                                Ok(Some(finalized_epoch)) => {
                                    debug!("light client: got epochs at height {}", i + 1);

                                    // Signature verification
                                    if let Some(pubkey) = &self.sequencer_pubkey {
                                        match finalized_epoch.verify_signature(*pubkey) {
                                            Ok(_) => trace!("valid signature for epoch {}", finalized_epoch.height),
                                            Err(e) => panic!("invalid signature in epoch {}: {:?}", i, e),
                                        }
                                    }

                                    // Commitment verification
                                    let prev_commitment = &finalized_epoch.prev_commitment;
                                    let current_commitment = &finalized_epoch.current_commitment;
                                    let mut public_values = finalized_epoch.proof.public_values.clone();
                                    let proof_prev_commitment: Digest = public_values.read();
                                    let proof_current_commitment: Digest = public_values.read();

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
                                    match self.client.verify(&finalized_epoch.proof, &self.verifying_key) {
                                        Ok(_) => info!("zkSNARK for epoch {} was validated successfully", finalized_epoch.height),
                                        Err(err) => panic!("failed to validate epoch at height {}: {:?}", finalized_epoch.height, err),
                                    }
                                },
                                Ok(None) => {
                                    debug!("no finalized epoch found at height: {}", i + 1);
                                },
                                Err(e) => debug!("light client: getting epoch: {}", e),
                            };
                        }
                        current_position = target;
                    },
                    Err(broadcast::error::RecvError::Closed) => {
                        error!("Height channel closed unexpectedly");
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
}
