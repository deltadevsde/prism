use crate::{
    circuits::{Bls12Proof, VerifyingKey},
    common::Operation,
    error::GeneralError,
    utils::SignedContent,
};
use anyhow::Result;
use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519::Signature;
use indexed_merkle_tree::Hash;
use std::{self, str::FromStr};

pub mod celestia;
pub mod mock;

// FinalizedEpoch is the data structure that represents the finalized epoch data, and is posted to the DA layer.
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct FinalizedEpoch {
    pub height: u64,
    pub prev_commitment: Hash,
    pub current_commitment: Hash,
    pub proof: Bls12Proof,
    pub verifying_key: VerifyingKey,
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
        borsh::to_vec(&copy).map_err(|e| GeneralError::EncodingError(e.to_string()).into())
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
    async fn get_snarks(&self, height: u64) -> Result<Vec<FinalizedEpoch>>;
    async fn submit_snarks(&self, epoch: Vec<FinalizedEpoch>) -> Result<u64>;
    async fn get_operations(&self, height: u64) -> Result<Vec<Operation>>;
    async fn submit_operations(&self, operations: Vec<Operation>) -> Result<u64>;
    async fn start(&self) -> Result<()>;
}
