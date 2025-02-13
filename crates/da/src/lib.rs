use std::sync::{atomic::AtomicU64, Arc};

use anyhow::{anyhow, Result};
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
use tokio::sync::{broadcast, Mutex};

#[cfg(not(target_arch = "wasm32"))]
use {prism_common::transaction::Transaction, sp1_sdk::SP1ProofWithPublicValues};

pub mod celestia;
pub mod consts;
pub mod memory;

#[cfg(target_arch = "wasm32")]
type Groth16Proof = Vec<u8>;

#[cfg(not(target_arch = "wasm32"))]
type Groth16Proof = SP1ProofWithPublicValues;

// FinalizedEpoch is the data structure that represents the finalized epoch data, and is posted to the DA layer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FinalizedEpoch {
    pub height: u64,
    pub prev_commitment: Digest,
    pub current_commitment: Digest,
    pub proof: Groth16Proof,
    pub signature: Option<String>,
}

impl FinalizedEpoch {
    pub fn insert_signature(&mut self, key: &SigningKey) {
        let plaintext = self.encode_to_bytes().unwrap();
        let signature = key.sign(&plaintext);
        self.signature = Some(signature.to_bytes().to_hex());
    }

    pub fn verify_signature(&self, vk: VerifyingKey) -> Result<()> {
        let epoch_without_signature = FinalizedEpoch {
            height: self.height,
            prev_commitment: self.prev_commitment,
            current_commitment: self.current_commitment,
            proof: self.proof.clone(),
            signature: None,
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
    fn subscribe_to_heights(&self) -> broadcast::Receiver<u64>;
    async fn get_finalized_epoch(&self, height: u64) -> Result<Option<FinalizedEpoch>>;
    fn event_subscriber(&self) -> Option<Arc<Mutex<EventSubscriber>>>; // the start of the event subscriber, optional because inmemoory and rpc based fullnode still need the start function and won't need this event subscriber
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
}
