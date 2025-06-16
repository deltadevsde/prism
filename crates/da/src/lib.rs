use std::sync::Arc;

use async_trait::async_trait;
use celestia_types::Blob;
use mockall::automock;
use prism_common::digest::Digest;
use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::{
    binary::{FromBinary, ToBinary},
    hex::{FromHex, ToHex},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

#[allow(unused_imports)]
use sp1_verifier::Groth16Verifier;

use crate::events::{EventChannel, EventSubscriber};

#[cfg(not(target_arch = "wasm32"))]
use {prism_common::transaction::Transaction, sp1_sdk::SP1ProofWithPublicValues};

pub mod celestia;
pub mod consts;
pub mod events;
pub mod memory;
pub mod utils;

#[cfg(target_arch = "wasm32")]
type Groth16Proof = Vec<u8>;

#[cfg(not(target_arch = "wasm32"))]
type Groth16Proof = SP1ProofWithPublicValues;

#[cfg(target_arch = "wasm32")]
type CompressedProof = Vec<u8>;

#[cfg(not(target_arch = "wasm32"))]
type CompressedProof = SP1ProofWithPublicValues;

pub type VerifiableEpoch = Box<dyn VerifiableStateTransition>;

/// `VerifiableStateTransition` is a trait wrapper around `FinalizedEpoch` that allows for mocking.
/// The only concrete implementation of this trait is by `FinalizedEpoch`.
pub trait VerifiableStateTransition: Send {
    fn verify(
        &self,
        vk: &VerifyingKey,
        sp1_vkeys: &VerificationKeys,
    ) -> Result<(Digest, Digest), EpochVerificationError>;
    fn height(&self) -> u64;
    fn da_height(&self) -> u64;
    fn commitments(&self) -> (Digest, Digest);
    fn try_convert(&self) -> Result<FinalizedEpoch, EpochVerificationError>;
}

// FinalizedEpoch is the data structure that represents the finalized epoch data, and is posted to the DA layer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FinalizedEpoch {
    /// The epoch height.
    pub height: u64,

    /// Commitment of the last epoch.
    pub prev_commitment: Digest,

    /// Commitment after the state transition to the current epoch.
    pub current_commitment: Digest,

    /// Groth16 proof of the state transition.
    pub proof: Groth16Proof,
    /// Auxillary data for WASM arch to read the public values of the proof.
    pub public_values: Vec<u8>,

    /// Compressed proof of the state transition, stored for cheaper recursive proving.
    pub compressed_proof: CompressedProof,

    /// The signature of this struct by the prover, with the signature field set to `None`.
    pub signature: Option<String>,

    /// The tip of the DA layer at the time of the epoch; All transactions in
    /// this epoch are from the DA blocks [previous_epoch.tip_da_height,
    /// current_epoch.tip_da_height).
    pub tip_da_height: u64,
}

#[derive(Deserialize, Clone)]
pub struct VerificationKeys {
    pub base_vk: String,
    pub recursive_vk: String,
}

impl VerifiableStateTransition for FinalizedEpoch {
    fn height(&self) -> u64 {
        self.height
    }

    fn da_height(&self) -> u64 {
        self.tip_da_height
    }

    fn try_convert(&self) -> Result<FinalizedEpoch, EpochVerificationError> {
        Ok(self.clone())
    }

    fn commitments(&self) -> (Digest, Digest) {
        (self.prev_commitment, self.current_commitment)
    }

    fn verify(
        &self,
        vk: &VerifyingKey,
        sp1_vkeys: &VerificationKeys,
    ) -> Result<(Digest, Digest), EpochVerificationError> {
        &self.verify_signature(vk.clone())?;

        if self.public_values.len() < 64 {
            return Err(EpochVerificationError::InvalidPublicValues(
                self.public_values.len(),
            ));
        }

        self.verify_commitments()?;

        #[cfg(target_arch = "wasm32")]
        let finalized_epoch_proof = self.proof;

        #[cfg(not(target_arch = "wasm32"))]
        let finalized_epoch_proof = self.proof.bytes();

        let vkey = if self.height == 0 {
            &sp1_vkeys.base_vk
        } else {
            &sp1_vkeys.recursive_vk
        };

        Groth16Verifier::verify(
            &finalized_epoch_proof,
            &self.public_values,
            vkey,
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .map_err(|e| EpochVerificationError::ProofVerificationError(e.to_string()))?;

        Ok((self.prev_commitment, self.current_commitment))
    }
}

impl FinalizedEpoch {
    pub fn insert_signature(&mut self, key: &SigningKey) -> Result<(), EpochVerificationError> {
        let plaintext = self.encode_to_bytes().unwrap();
        let signature =
            key.sign(&plaintext).map_err(|e| SignatureError::SignatureError(e.to_string()))?;
        self.signature = Some(signature.to_bytes().to_hex());
        Ok(())
    }

    fn extract_commitments(&self) -> Result<(Digest, Digest), EpochVerificationError> {
        let mut slice = [0u8; 32];
        slice.copy_from_slice(&self.public_values[..32]);
        let proof_prev_commitment = Digest::from(slice);

        let mut slice = [0u8; 32];
        slice.copy_from_slice(&self.public_values[32..64]);
        let proof_current_commitment = Digest::from(slice);

        Ok((proof_prev_commitment, proof_current_commitment))
    }

    fn verify_commitments(&self) -> Result<(), EpochVerificationError> {
        let (proof_prev_commitment, proof_current_commitment) = self.extract_commitments()?;

        if self.prev_commitment != proof_prev_commitment {
            return Err(CommitmentError::PreviousCommitmentMismatch.into());
        }

        if self.current_commitment != proof_current_commitment {
            return Err(CommitmentError::CurrentCommitmentMismatch.into());
        }

        Ok(())
    }

    pub fn verify_signature(&self, vk: VerifyingKey) -> Result<(), EpochVerificationError> {
        let epoch_without_signature = FinalizedEpoch {
            height: self.height,
            prev_commitment: self.prev_commitment,
            current_commitment: self.current_commitment,
            proof: self.proof.clone(),
            compressed_proof: self.compressed_proof.clone(),
            public_values: self.public_values.clone(),
            signature: None,
            tip_da_height: self.tip_da_height,
        };

        let message = epoch_without_signature
            .encode_to_bytes()
            .map_err(|e| EpochVerificationError::SerializationError(e.to_string()))?;

        let signature = self.signature.as_ref().ok_or_else(|| SignatureError::MissingSignature)?;

        let signature_bytes = Vec::<u8>::from_hex(signature)
            .map_err(|e| SignatureError::DecodingError(e.to_string()))?;

        let signature: Signature =
            Signature::from_algorithm_and_bytes(vk.algorithm(), signature_bytes.as_slice())
                .map_err(|_| SignatureError::InvalidLength)?;

        vk.verify_signature(&message, &signature)
            .map_err(|e| SignatureError::VerificationError(e.to_string()))?;
        Ok(())
    }
}

impl TryFrom<&Blob> for FinalizedEpoch {
    type Error = EpochVerificationError;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        FinalizedEpoch::decode_from_bytes(&value.data)
            .map_err(|_| EpochVerificationError::DecodingError(value.clone()))
    }
}

#[derive(Error, Debug)]
pub enum EpochVerificationError {
    #[error("public values too short, has length {0}")]
    InvalidPublicValues(usize),
    #[error("commitment error: {0}")]
    CommitmentError(#[from] CommitmentError),
    #[error("signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("failed to decode finalized epoch from blob: {0:?}")]
    DecodingError(Blob),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("epoch proo verification error: {0}")]
    ProofVerificationError(String),
}

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("invalid length")]
    InvalidLength,
    #[error("missing signature")]
    MissingSignature,
    #[error("decoding error: {0}")]
    DecodingError(String),
    // TODO: This error should be replaced once we have sensible errors in the keys crate
    #[error("verification error")]
    VerificationError(String),
    #[error("signature error: {0}")]
    SignatureError(String),
}

#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("previous commitment mismatch")]
    PreviousCommitmentMismatch,
    #[error("current commitment mismatch")]
    CurrentCommitmentMismatch,
}

#[automock]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait LightDataAvailabilityLayer {
    async fn get_finalized_epoch(&self, height: u64) -> anyhow::Result<Vec<VerifiableEpoch>>;

    fn event_channel(&self) -> Arc<EventChannel>;
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait DataAvailabilityLayer: LightDataAvailabilityLayer + Send + Sync {
    async fn start(&self) -> anyhow::Result<()>;
    async fn get_latest_height(&self) -> anyhow::Result<u64>;
    async fn initialize_sync_target(&self) -> anyhow::Result<u64>;
    async fn submit_finalized_epoch(&self, epoch: FinalizedEpoch) -> anyhow::Result<u64>;
    async fn get_transactions(&self, height: u64) -> anyhow::Result<Vec<Transaction>>;
    async fn submit_transactions(&self, transactions: Vec<Transaction>) -> anyhow::Result<u64>;
    fn subscribe_to_heights(&self) -> tokio::sync::broadcast::Receiver<u64>;
}
