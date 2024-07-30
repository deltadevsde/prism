use crate::{
    cfg::CelestiaConfig,
    error::{DataAvailabilityError, GeneralError, PrismResult},
};
use async_trait::async_trait;
use std::{self, sync::Arc, time::Duration};
use tokio::{task::spawn, time::interval};

use crate::{
    da::DataAvailabilityLayer,
    node_types::NodeType,
    utils::{validate_epoch, verify_signature},
};

pub struct LightClient {
    pub da: Arc<dyn DataAvailabilityLayer>,
    // verifying_key is the [`VerifyingKey`] used to verify epochs from the prover/sequencer
    pub verifying_key: Option<String>,
    start_height: u64,
}

#[async_trait]
impl NodeType for LightClient {
    async fn start(self: Arc<Self>) -> PrismResult<()> {
        // start listening for new headers to update sync target
        match self.da.start().await {
            Ok(_) => (),
            Err(e) => return Err(DataAvailabilityError::InitializationError(e.to_string()).into()),
        };

        self.sync_loop()
            .await
            .map_err(|e| GeneralError::InitializationError(e.to_string()).into())
    }
}

impl LightClient {
    pub fn new(
        da: Arc<dyn DataAvailabilityLayer>,
        cfg: CelestiaConfig,
        sequencer_pub_key: Option<String>,
    ) -> LightClient {
        LightClient {
            da,
            verifying_key: sequencer_pub_key,
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
                                let prev_commitment = &epoch_json.prev_commitment;
                                let current_commitment = &epoch_json.current_commitment;

                                let proof = match epoch_json.proof.clone().try_into() {
                                    Ok(proof) => proof,
                                    Err(e) => {
                                        error!("failed to deserialize proof, skipping a blob at height {}: {:?}", i, e);
                                        continue;
                                    }
                                };

                                // TODO(@distractedm1nd): i don't know rust yet but this seems like non-idiomatic rust -
                                // is there not a Trait that can satisfy these properties for us?
                                let verifying_key = match epoch_json.verifying_key.clone().try_into() {
                                    Ok(vk) => vk,
                                    Err(e) => {
                                        error!("failed to deserialize verifying key, skipping a blob at height {}: {:?}", i, e);
                                        continue;
                                    }
                                };

                                // if the user does not add a verifying key, we will not verify the signature,
                                // but only log a warning on startup
                                if self.verifying_key.is_some() {
                                    match verify_signature(
                                        &epoch_json.clone(),
                                        self.verifying_key.clone(),
                                    ) {
                                        Ok(_) => trace!("valid signature for epoch {}", epoch_json.height),
                                        Err(e) => {
                                            panic!("invalid signature in epoch {}: {:?}", i, e)
                                        }
                                    }
                                }

                                match validate_epoch(
                                    prev_commitment,
                                    current_commitment,
                                    proof,
                                    verifying_key,
                                ) {
                                    Ok(_) => {
                                        info!(
                                            "zkSNARK for epoch {} was validated successfully",
                                            epoch_json.height
                                        )
                                    }
                                    Err(err) => panic!("failed to validate epoch: {:?}", err),
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
        }).await
    }
}
