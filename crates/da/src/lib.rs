use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use celestia_types::Blob;
use lumina_node::events::EventSubscriber;
use prism_common::digest::Digest;
use prism_keys::{Signature, SigningKey, VerifyingKey};
use prism_serde::{
    binary::{FromBinary, ToBinary},
    hex::{FromHex, ToHex},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[cfg(not(target_arch = "wasm32"))]
use {prism_common::transaction::Transaction, sp1_sdk::SP1ProofWithPublicValues};

pub mod celestia;
pub mod consts;
pub mod memory;

#[cfg(target_arch = "wasm32")]
type Groth16Proof = Vec<u8>;

#[cfg(not(target_arch = "wasm32"))]
type Groth16Proof = SP1ProofWithPublicValues;

#[cfg(target_arch = "wasm32")]
type CompressedProof = Vec<u8>;

#[cfg(not(target_arch = "wasm32"))]
type CompressedProof = SP1ProofWithPublicValues;

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

impl FinalizedEpoch {
    pub fn insert_signature(&mut self, key: &SigningKey) -> Result<()> {
        let plaintext = self.encode_to_bytes().unwrap();
        let signature = key.sign(&plaintext)?;
        self.signature = Some(signature.to_bytes().to_hex());
        Ok(())
    }

    pub fn verify_signature(&self, vk: VerifyingKey) -> Result<()> {
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
            .map_err(|e| anyhow::anyhow!("Failed to serialize epoch: {}", e))?;

        let signature =
            self.signature.as_ref().ok_or_else(|| anyhow::anyhow!("No signature present"))?;

        let signature_bytes = Vec::<u8>::from_hex(signature)
            .map_err(|e| anyhow::anyhow!("Failed to decode signature: {}", e))?;

        let signature: Signature =
            Signature::from_algorithm_and_bytes(vk.algorithm(), signature_bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;

        vk.verify_signature(&message, &signature)
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;
        Ok(())
    }
}

impl TryFrom<&Blob> for FinalizedEpoch {
    type Error = anyhow::Error;

    fn try_from(value: &Blob) -> Result<Self, Self::Error> {
        FinalizedEpoch::decode_from_bytes(&value.data).map_err(|_| {
            anyhow!(format!(
                "Failed to decode blob into FinalizedEpoch: {value:?}"
            ))
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait LightDataAvailabilityLayer {
    async fn get_finalized_epoch(&self, height: u64) -> Result<Vec<FinalizedEpoch>>;

    // starts the event subscriber, optional because inmemory and rpc based fullnode still need the start function
    fn event_subscriber(&self) -> Option<Arc<Mutex<EventSubscriber>>>;
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait DataAvailabilityLayer: LightDataAvailabilityLayer + Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn get_latest_height(&self) -> Result<u64>;
    async fn initialize_sync_target(&self) -> Result<u64>;
    async fn submit_finalized_epoch(&self, epoch: FinalizedEpoch) -> Result<u64>;
    async fn get_transactions(&self, height: u64) -> Result<Vec<Transaction>>;
    async fn submit_transactions(&self, transactions: Vec<Transaction>) -> Result<u64>;
    fn subscribe_to_heights(&self) -> tokio::sync::broadcast::Receiver<u64>;
}
