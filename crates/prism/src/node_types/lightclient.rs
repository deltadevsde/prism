use anyhow::{Context, Result};
use async_trait::async_trait;
use prism_common::tree::Digest;
use prism_da::{celestia::CelestiaConfig, DataAvailabilityLayer};
use prism_errors::{DataAvailabilityError, GeneralError};
use sp1_sdk::{ProverClient, SP1VerifyingKey};
use std::{self, sync::Arc, time::Duration};
use tokio::{task::spawn, time::interval};

use crate::{node_types::NodeType, utils::verify_signature};

pub const PRISM_ELF: &[u8] = include_bytes!("../../../../elf/riscv32im-succinct-zkvm-elf");

pub struct LightClient {
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub sequencer_pubkey: Option<String>,
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
        sequencer_pubkey: Option<String>,
    ) -> LightClient {
        let client = ProverClient::new();
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
            let mut ticker = interval(Duration::from_secs(1));
            loop {
                // target is updated when a new header is received
                let target = match self.da.get_latest_height().await {
                    Ok(target) => target,
                    Err(e) => {
                        error!("failed to update sync target, retrying: {:?}", e);
                        continue;
                    }
                };

                debug!("updated sync target to height {}", target);
                for i in current_position..target {
                    trace!("processing height: {}", i);
                    match self.da.get_snarks(i + 1).await {
                        Ok(epoch_json_vec) => {
                            if !epoch_json_vec.is_empty() {
                                debug!("light client: got epochs at height {}", i + 1);
                            }

                            // todo: verify adjacency to last heights, <- for this we need some sort of storage of epochs
                            for epoch_json in epoch_json_vec {
                                let _prev_commitment = &epoch_json.prev_commitment;
                                let _current_commitment = &epoch_json.current_commitment;

                                // if the user does not add a verifying key, we will not verify the signature,
                                // but only log a warning on startup
                                if self.sequencer_pubkey.is_some() {
                                    match verify_signature(
                                        &epoch_json.clone(),
                                        self.sequencer_pubkey.clone(),
                                    ) {
                                        Ok(_) => trace!(
                                            "valid signature for epoch {}",
                                            epoch_json.height
                                        ),
                                        Err(e) => {
                                            panic!("invalid signature in epoch {}: {:?}", i, e)
                                        }
                                    }
                                }

                                let prev_commitment = &epoch_json.prev_commitment;
                                let current_commitment = &epoch_json.current_commitment;

                                let mut public_values = epoch_json.proof.public_values.clone();
                                let proof_prev_commitment: Digest = public_values.read();
                                let proof_current_commitment: Digest = public_values.read();

                                if prev_commitment != &proof_prev_commitment
                                    || current_commitment != &proof_current_commitment
                                {
                                    error!(
                                        "Commitment mismatch: 
                                        prev_commitment: {:?}, proof_prev_commitment: {:?},
                                        current_commitment: {:?}, proof_current_commitment: {:?}",
                                        prev_commitment,
                                        proof_prev_commitment,
                                        current_commitment,
                                        proof_current_commitment
                                    );
                                    panic!("Commitment mismatch in epoch {}", epoch_json.height);
                                }

                                match self.client.verify(&epoch_json.proof, &self.verifying_key) {
                                    Ok(_) => {
                                        info!(
                                            "zkSNARK for epoch {} was validated successfully",
                                            epoch_json.height
                                        )
                                    }
                                    Err(err) => panic!(
                                        "failed to validate epoch at height {}: {:?}",
                                        epoch_json.height, err
                                    ),
                                }
                            }
                        }
                        Err(e) => {
                            debug!("light client: getting epoch: {}", e)
                        }
                    };
                }
                ticker.tick().await; // only for testing purposes
                current_position = target; // Update the current position to the latest target
            }
        })
        .await
    }
}
