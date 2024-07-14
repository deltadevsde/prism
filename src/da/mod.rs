use crate::{
    error::{DAResult, DeimosResult, GeneralError},
    utils::Signable,
    zk_snark::{Bls12Proof, VerifyingKey},
};
use async_trait::async_trait;
use ed25519::Signature;
use serde::{Deserialize, Serialize};
use std::{self, str::FromStr};

pub mod celestia;
pub mod mock;

#[derive(Serialize, Deserialize, Clone)]
pub struct EpochJson {
    pub height: u64,
    pub prev_commitment: String,
    pub current_commitment: String,
    pub proof: Bls12Proof,
    pub verifying_key: VerifyingKey,
    pub signature: Option<String>,
}

impl Signable for EpochJson {
    fn get_signature(&self) -> DeimosResult<Signature> {
        match &self.signature {
            Some(signature) => Signature::from_str(signature)
                .map_err(|e| GeneralError::ParsingError(format!("signature: {}", e)).into()),
            None => Err(GeneralError::MissingArgumentError("signature".to_string()).into()),
        }
    }

    fn get_content_to_sign(&self) -> DeimosResult<String> {
        let mut copy = self.clone();
        copy.signature = None;
        serde_json::to_string(&copy).map_err(|e| GeneralError::EncodingError(e.to_string()).into())
    }

    fn get_public_key(&self) -> DeimosResult<String> {
        //TODO(@distractedm1nd): the below comment isn't good enough of an argument to not return the public key, it should be fixed

        // for epoch json the public key to verify is the one from the sequencer which should be already be public and known from every light client
        // so if we use this function there should be an error
        Err(GeneralError::MissingArgumentError("public key".to_string()).into())
    }
}

#[async_trait]
pub trait DataAvailabilityLayer: Send + Sync {
    async fn get_latest_height(&self) -> DAResult<u64>;
    async fn initialize_sync_target(&self) -> DAResult<u64>;
    async fn get(&self, height: u64) -> DAResult<Vec<EpochJson>>;
    async fn submit(&self, epoch: &EpochJson) -> DAResult<u64>;
    async fn start(&self) -> DAResult<()>;
}
