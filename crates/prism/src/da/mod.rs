use crate::utils::SignedContent;
use anyhow::Result;
use async_trait::async_trait;
use bincode;
use ed25519::Signature;
use prism_common::{operation::Operation, tree::Digest};
use prism_errors::GeneralError;
use serde::{Deserialize, Serialize};
use sp1_sdk::SP1ProofWithPublicValues;
use std::{self, str::FromStr};
use tokio::sync::broadcast;

pub mod celestia;
pub mod memory;

// FinalizedEpoch is the data structure that represents the finalized epoch data, and is posted to the DA layer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FinalizedEpoch {
    pub height: u64,
    pub prev_commitment: Digest,
    pub current_commitment: Digest,
    pub proof: SP1ProofWithPublicValues,
    pub signature: Option<String>,
}

impl SignedContent for FinalizedEpoch {
    fn get_signature(&self) -> Result<Signature> {
        match &self.signature {
            Some(signature) => Signature::from_str(signature)
                .map_err(|e| GeneralError::ParsingError(format!("signature: {}", e)).into()),
            None => Err(GeneralError::MissingArgumentError("signature".to_string()).into()),
        }
    }

    fn get_plaintext(&self) -> Result<Vec<u8>> {
        let mut copy = self.clone();
        copy.signature = None;
        bincode::serialize(&copy).map_err(|e| GeneralError::EncodingError(e.to_string()).into())
    }

    fn get_public_key(&self) -> Result<String> {
        //TODO(@distractedm1nd): the below comment isn't good enough of an argument to not return the public key, it should be fixed

        // for epoch json the public key to verify is the one from the sequencer which should be already be public and known from every light client
        // so if we use this function there should be an error
        Err(GeneralError::MissingArgumentError("public key".to_string()).into())
    }
}

#[async_trait]
pub trait DataAvailabilityLayer: Send + Sync {
    async fn get_latest_height(&self) -> Result<u64>;
    async fn initialize_sync_target(&self) -> Result<u64>;
    async fn get_finalized_epoch(&self, height: u64) -> Result<Option<FinalizedEpoch>>;
    async fn submit_finalized_epoch(&self, epoch: FinalizedEpoch) -> Result<u64>;
    async fn get_operations(&self, height: u64) -> Result<Vec<Operation>>;
    async fn submit_operations(&self, operations: Vec<Operation>) -> Result<u64>;
    async fn start(&self) -> Result<()>;
    fn subscribe_to_heights(&self) -> broadcast::Receiver<u64>;
}
