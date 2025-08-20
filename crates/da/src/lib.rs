//! # Prism Data Availability Layer
//!
//! This crate provides abstracted access to data availability layers for the Prism network.
//! It supports multiple backends and provides both light client and full node capabilities.
//!
//! ## Overview
//!
//! The DA layer is responsible for:
//! - Storing and retrieving finalized epochs (SNARK proofs)
//! - Publishing and reading transaction batches
//! - Providing data availability guarantees for network participants
//! - Supporting light client protocols for efficient data access
//!
//! ## Architecture
//!
//! The crate provides two main trait abstractions:
//! - [`LightDataAvailabilityLayer`]: Read-only access to finalized epochs/proofs
//! - [`DataAvailabilityLayer`]: Full read-write access to finalized epochs/proofs and transactions
//!
//! ## Supported Backends
//!
//! ### Celestia
//! - Production-ready modular data availability network
//! - Supports both light client and full node protocols
//! - Configurable through [`CelestiaLightClientDAConfig`] and [`CelestiaFullNodeDAConfig`]
//!
//! ### InMemory
//! - Local storage for testing and development
//! - No persistence across restarts
//! - Suitable for CI/CD and local development
//!
//! ## Example
//!
//! ### Light Client Example
//!
//! ```rust
//! use prism_da::{LightClientDAConfig, create_light_client_da_layer};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // In-memory for development
//!     let config = LightClientDAConfig::InMemory;
//!     let da = create_light_client_da_layer(&config).await?;
//!
//!     let epochs = da.get_finalized_epochs(100).await?;
//!     for epoch in epochs {
//!         println!("Epoch height: {}", epoch.height());
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Full Node Example
//!
//! ```rust,no_run
//! use prism_common::transaction::Transaction;
//! use prism_da::{
//!     FullNodeDAConfig, create_full_node_da_layer,
//!     celestia::{CelestiaFullNodeDAConfig, CelestiaNetwork}
//! };
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = FullNodeDAConfig::Celestia(CelestiaFullNodeDAConfig {
//!         url: "ws://localhost:26658".to_string(),
//!         celestia_network: CelestiaNetwork::Arabica,
//!         snark_namespace_id: "00000000000000de1008".to_string(),
//!         operation_namespace_id: "00000000000000de1009".to_string(),
//!         fetch_timeout: Duration::from_secs(90),
//!         fetch_max_retries: 3,
//!     });
//!     let da = create_full_node_da_layer(&config).await?;
//!     da.start().await?;
//!
//!     let transactions = vec![/* your transactions */];
//!     let height = da.submit_transactions(transactions).await?;
//!     println!("Submitted at height: {}", height);
//!
//!     let mut height_rx = da.subscribe_to_heights();
//!     while let Ok(new_height) = height_rx.recv().await {
//!         let txs = da.get_transactions(new_height).await?;
//!         println!("Height {}: {} transactions", new_height, txs.len());
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod celestia;
pub mod consts;
mod factory;
pub mod memory;

use async_trait::async_trait;
use celestia_types::Blob;
pub use factory::*;
use mockall::automock;
use prism_common::digest::Digest;
use prism_errors::{CommitmentError, EpochVerificationError, SignatureError};
use prism_events::EventChannel;
use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::{
    binary::{FromBinary, ToBinary},
    hex::{FromHex, ToHex},
};
use serde::{Deserialize, Serialize};
use sp1_verifier::Groth16Verifier;
use std::{fmt::Display, sync::Arc};
#[cfg(not(target_arch = "wasm32"))]
use {prism_common::transaction::Transaction, sp1_sdk::SP1ProofWithPublicValues};

pub type VerifiableEpoch = Box<dyn VerifiableStateTransition>;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
/// Represents an [`SP1ProofWithPublicValues`] that can be used in wasm32
/// environments.
///
/// This is necessary because wasm32 cannot decode the [`proof_bytes`] back into
/// an [`SP1ProofWithPublicValues`], but provers will still need something
/// deserializable back into the original type (for STARK recursion)
pub struct SuccinctProof {
    /// Represents the bincode serialization of a [`SP1ProofWithPublicValues`].
    ///
    /// Can be used by `sp1_verifier::groth16::Groth16Verifier::verify` as the
    /// `proof` field.
    pub proof_bytes: Vec<u8>,

    /// Represents the output of [`SP1ProofWithPublicValues::public_values()`]
    ///
    /// Can be used by `sp1_verifier::groth16::Groth16Verifier::verify` as the
    /// `public_values` field.
    pub public_values: Vec<u8>,
}

impl Display for SuccinctProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(proof: {}, public_values: {})",
            self.proof_bytes.to_hex(),
            self.public_values.to_hex()
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TryInto<SP1ProofWithPublicValues> for SuccinctProof {
    type Error = Box<bincode::ErrorKind>;

    fn try_into(self) -> Result<SP1ProofWithPublicValues, Self::Error> {
        bincode::deserialize::<SP1ProofWithPublicValues>(&self.proof_bytes)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TryFrom<SP1ProofWithPublicValues> for SuccinctProof {
    type Error = Box<bincode::ErrorKind>;

    fn try_from(proof: SP1ProofWithPublicValues) -> Result<Self, Self::Error> {
        let proof_bytes = bincode::serialize(&proof)?;
        Ok(SuccinctProof {
            proof_bytes,
            public_values: proof.public_values.to_vec(),
        })
    }
}

/// Represents the commitments from epoch verification (previous and current)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCommitments {
    pub previous: Digest,
    pub current: Digest,
}

impl EpochCommitments {
    pub fn new(previous: Digest, current: Digest) -> Self {
        Self { previous, current }
    }
}

impl From<(Digest, Digest)> for EpochCommitments {
    fn from((previous, current): (Digest, Digest)) -> Self {
        Self::new(previous, current)
    }
}

impl From<EpochCommitments> for (Digest, Digest) {
    fn from(commitments: EpochCommitments) -> Self {
        (commitments.previous, commitments.current)
    }
}

/// `VerifiableStateTransition` is a trait wrapper around `FinalizedEpoch` that allows for mocking.
/// The only concrete implementation of this trait is by `FinalizedEpoch`.
#[automock]
pub trait VerifiableStateTransition: Send {
    fn verify(
        &self,
        vk: &VerifyingKey,
        sp1_vkeys: &VerificationKeys,
    ) -> Result<EpochCommitments, EpochVerificationError>;
    fn height(&self) -> u64;
    fn da_height(&self) -> u64;
    fn commitments(&self) -> EpochCommitments;
    fn try_convert(&self) -> Result<FinalizedEpoch, EpochVerificationError>;
}

// FinalizedEpoch is the data structure that represents the finalized epoch data, and is posted to
// the DA layer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FinalizedEpoch {
    /// The epoch height.
    pub height: u64,

    /// Commitment of the last epoch.
    pub prev_commitment: Digest,

    /// Commitment after the state transition to the current epoch.
    pub current_commitment: Digest,

    /// Groth16 proof of the state transition.
    pub snark: SuccinctProof,

    /// Compressed proof of the state transition, stored for the next recursion step.
    pub stark: SuccinctProof,

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

    fn commitments(&self) -> EpochCommitments {
        EpochCommitments::new(self.prev_commitment, self.current_commitment)
    }

    fn verify(
        &self,
        vk: &VerifyingKey,
        sp1_vkeys: &VerificationKeys,
    ) -> Result<EpochCommitments, EpochVerificationError> {
        self.verify_signature(vk.clone())?;

        if self.snark.public_values.len() < 64 {
            return Err(EpochVerificationError::InvalidPublicValues(
                self.snark.public_values.len(),
            ));
        }

        self.verify_commitments()?;

        let finalized_epoch_proof = &self.snark.proof_bytes;

        let vkey = if self.height == 0 {
            &sp1_vkeys.base_vk
        } else {
            &sp1_vkeys.recursive_vk
        };

        Groth16Verifier::verify(
            finalized_epoch_proof,
            &self.snark.public_values,
            vkey,
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .map_err(|e| EpochVerificationError::ProofVerificationError(e.to_string()))?;

        Ok(EpochCommitments::new(
            self.prev_commitment,
            self.current_commitment,
        ))
    }
}

impl FinalizedEpoch {
    pub fn insert_signature(&mut self, key: &SigningKey) -> Result<(), EpochVerificationError> {
        let plaintext = self.encode_to_bytes().unwrap();
        let signature =
            key.sign(&plaintext).map_err(|e| SignatureError::SigningError(e.to_string()))?;
        self.signature = Some(signature.to_bytes().to_hex());
        Ok(())
    }

    fn extract_commitments(&self) -> Result<(Digest, Digest), EpochVerificationError> {
        let mut slice = [0u8; 32];
        slice.copy_from_slice(&self.snark.public_values[..32]);
        let proof_prev_commitment = Digest::from(slice);

        let mut slice = [0u8; 32];
        slice.copy_from_slice(&self.snark.public_values[32..64]);
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
            snark: self.snark.clone(),
            stark: self.stark.clone(),
            signature: None,
            tip_da_height: self.tip_da_height,
        };

        let message = epoch_without_signature
            .encode_to_bytes()
            .map_err(|e| EpochVerificationError::SerializationError(e.to_string()))?;

        let signature = self.signature.as_ref().ok_or(SignatureError::MissingSignature)?;

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
        FinalizedEpoch::decode_from_bytes(&value.data).map_err(|_| {
            EpochVerificationError::DecodingError(format!("Failed to decode blob: {value:?}"))
        })
    }
}

#[automock]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait LightDataAvailabilityLayer {
    async fn get_finalized_epochs(&self, height: u64) -> anyhow::Result<Vec<VerifiableEpoch>>;

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
