use crate::{
    consts::{CHANNEL_BUFFER_SIZE, DA_RETRY_COUNT, DA_RETRY_INTERVAL},
    error::{DataAvailabilityError, DeimosResult},
};
use async_trait::async_trait;
use crypto_hash::{hex_digest, Algorithm};
use ed25519_dalek::{Signer, SigningKey};
use indexed_merkle_tree::{node::Node, tree::IndexedMerkleTree};
use std::{self, sync::Arc, time::Duration};
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::spawn,
    time::interval,
};

use crate::{
    cfg::Config,
    da::{DataAvailabilityLayer, EpochJson},
    error::{DeimosError, GeneralError},
    storage::{ChainEntry, Database, IncomingEntry, Operation, UpdateEntryJson},
    utils::{validate_epoch, verify_signature},
    webserver::WebServer,
    zk_snark::{
        deserialize_custom_to_verifying_key, deserialize_proof, serialize_proof,
        serialize_verifying_key_to_custom, BatchMerkleProofCircuit,
    },
};

pub struct LightClient {
    pub da: Arc<dyn DataAvailabilityLayer>,
    pub sequencer_public_key: Option<String>,
}

#[async_trait]
impl NodeType for LightClient {
    async fn start(self: Arc<Self>) -> DeimosResult<()> {
        // start listening for new headers to update sync target
        self.da.start().await.unwrap();

        info!("starting main light client loop");
        // todo: persist current_position in datastore
        // also: have initial starting position be configurable

        let handle = spawn(async move {
            let mut current_position = 0;
            let mut ticker = interval(Duration::from_secs(1));
            loop {
                // target is updated when a new header is received
                let target = self.da.get_message().await.unwrap();
                debug!("updated sync target to height {}", target);
                for i in current_position..target {
                    trace!("processing height: {}", i);
                    match self.da.get(i + 1).await {
                        Ok(epoch_json_vec) => {
                            // Verify adjacency to last heights, <- for this we need some sort of storage of epochs
                            // Verify zk proofs,
                            for epoch_json in epoch_json_vec {
                                let prev_commitment = &epoch_json.prev_commitment;
                                let current_commitment = &epoch_json.current_commitment;
                                let proof = deserialize_proof(&epoch_json.proof).unwrap();
                                let verifying_key =
                                    deserialize_custom_to_verifying_key(&epoch_json.verifying_key)
                                        .unwrap();
                                if self.sequencer_public_key.is_some() {
                                    if verify_signature(
                                        &epoch_json.clone(),
                                        self.sequencer_public_key.clone(),
                                    )
                                    .is_ok()
                                    {
                                        trace!("valid signature for height {}", i);
                                    } else {
                                        panic!(
                                            "invalid signature in retrieved epoch on height {}",
                                            i
                                        );
                                    }
                                } else {
                                    error!("epoch on height {} was not signed", i);
                                }

                                match validate_epoch(
                                    &prev_commitment,
                                    &current_commitment,
                                    proof,
                                    verifying_key,
                                ) {
                                    Ok(_) => (),
                                    Err(err) => panic!("Failed to validate epoch: {:?}", err),
                                }
                            }

                            info!("light client: got epochs at height {}", i + 1);
                        }
                        Err(e) => debug!("light client: getting epoch: {}", e),
                    };
                }
                ticker.tick().await; // only for testing purposes
                current_position = target; // Update the current position to the latest target
            }
        });

        handle
            .await
            .map_err(|_| GeneralError::WebserverError.into())
    }
}

impl LightClient {
    pub fn new(
        da: Arc<dyn DataAvailabilityLayer>,
        sequencer_pub_key: Option<String>,
    ) -> LightClient {
        LightClient {
            da,
            sequencer_public_key: sequencer_pub_key,
        }
    }
}
