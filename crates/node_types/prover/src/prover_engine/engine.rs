use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use mockall::automock;
use prism_da::{SuccinctProof, VerificationKeys};
use prism_storage::Database;
use prism_tree::proofs::Batch;

#[cfg(test)]
use prism_da::VerifiableEpoch;

#[automock]
#[async_trait]
pub trait ProverEngine: Send + Sync {
    /// Returns the ZK verifying keys for SNARK and STARK verification.
    fn verification_keys(&self) -> VerificationKeys;

    /// Generates a (SNARK, STARK) pair proving the validation of [`batch`].
    /// The STARK validates the SNARK for cheaper recursion within the zkVM.
    async fn prove_epoch(
        &self,
        epoch_height: u64,
        batch: &Batch,
        db: &Arc<Box<dyn Database>>,
    ) -> Result<(SuccinctProof, SuccinctProof)>;

    #[cfg(test)]
    /// This method is only used for testing purposes, as
    /// VerifiableEpoch::verify cannot verify mock proofs unless they themselves
    /// are mocked.
    async fn verify_proof(&self, proof: VerifiableEpoch) -> Result<()>;
}
