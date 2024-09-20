use anyhow::Result;
use async_trait::async_trait;
use bincode;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prism_common::{operation::Operation, tree::Digest};
use serde::{Deserialize, Serialize};
use sp1_sdk::SP1ProofWithPublicValues;
use tokio::sync::broadcast; // Added import for hex

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

impl FinalizedEpoch {
    pub fn insert_signature(&mut self, key: &SigningKey) {
        let plaintext = bincode::serialize(&self).unwrap();
        let signature = key.sign(&plaintext);
        self.signature = Some(hex::encode(signature.to_bytes()));
    }

    pub fn verify_signature(&self, vk: VerifyingKey) -> Result<()> {
        let epoch_without_signature = FinalizedEpoch {
            height: self.height,
            prev_commitment: self.prev_commitment,
            current_commitment: self.current_commitment,
            proof: self.proof.clone(),
            signature: None,
        };

        let message = bincode::serialize(&epoch_without_signature).unwrap();

        if self.signature.is_none() {
            return Err(anyhow::anyhow!("No signature present"));
        }

        let signature_bytes = hex::decode(self.signature.as_ref().unwrap()).unwrap();
        if signature_bytes.len() != 64 {
            return Err(anyhow::anyhow!("Invalid signature length"));
        }

        let signature: Signature = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;

        vk.verify_strict(&message, &signature).unwrap();
        Ok(())
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
