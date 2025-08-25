use anyhow::{Result, anyhow};
use async_trait::async_trait;
#[cfg(test)]
use prism_da::VerifiableEpoch;
use prism_da::{SuccinctProof, VerificationKeys};
use prism_storage::Database;
use prism_tree::proofs::Batch;
use sp1_sdk::{
    EnvProver, HashableKey as _, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1ProvingKey,
    SP1Stdin, SP1VerifyingKey,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::prover_engine::engine::ProverEngine;

pub const BASE_PRISM_ELF: &[u8] =
    include_bytes!("../../../../../elf/base-riscv32im-succinct-zkvm-elf");
pub const RECURSIVE_PRISM_ELF: &[u8] =
    include_bytes!("../../../../../elf/recursive-riscv32im-succinct-zkvm-elf");

#[derive(Clone)]
pub struct SP1ProverEngine {
    base_prover_client: Arc<RwLock<EnvProver>>,
    base_proving_key: SP1ProvingKey,
    base_verifying_key: SP1VerifyingKey,

    recursive_prover_client: Arc<RwLock<EnvProver>>,
    recursive_proving_key: SP1ProvingKey,
    recursive_verifying_key: SP1VerifyingKey,

    recursive_proofs_enabled: bool,
}

#[async_trait]
impl ProverEngine for SP1ProverEngine {
    fn verification_keys(&self) -> VerificationKeys {
        // If recursive proofs are disabled, we just tell the verifier to verify using the base
        // proving key
        let recursive_vk = match self.recursive_proofs_enabled {
            true => self.recursive_verifying_key.bytes32(),
            false => self.base_verifying_key.bytes32(),
        };

        VerificationKeys {
            base_vk: self.base_verifying_key.bytes32(),
            recursive_vk,
        }
    }

    async fn prove_epoch(
        &self,
        epoch_height: u64,
        batch: &Batch,
        db: &Arc<Box<dyn Database>>,
    ) -> Result<(SuccinctProof, SuccinctProof)> {
        let (snark, stark) = if epoch_height == 0 || !self.recursive_proofs_enabled {
            self.prove_with_base_prover(epoch_height, batch).await?
        } else {
            self.prove_with_recursive_prover(epoch_height, batch, db).await?
        };

        return Ok((snark, stark));
    }

    #[cfg(test)]
    async fn verify_proof(&self, proof: VerifiableEpoch) -> Result<()> {
        let succinct_proof = proof.try_convert().unwrap().stark;
        let sp1_proof: SP1ProofWithPublicValues = succinct_proof.try_into()?;
        self.base_prover_client
            .read()
            .await
            .verify(&sp1_proof, &self.base_verifying_key)
            .map_err(|e| anyhow!(e))
    }
}

impl SP1ProverEngine {
    pub fn new(config: &crate::prover::ProverEngineOptions) -> Result<Self> {
        let base_prover_client = ProverClient::from_env();
        let recursive_prover_client = ProverClient::from_env();

        let (base_pk, base_vk) = base_prover_client.setup(BASE_PRISM_ELF);
        let (recursive_pk, recursive_vk) = recursive_prover_client.setup(RECURSIVE_PRISM_ELF);

        Ok(Self {
            base_proving_key: base_pk,
            base_verifying_key: base_vk,
            recursive_proving_key: recursive_pk,
            recursive_verifying_key: recursive_vk,
            base_prover_client: Arc::new(RwLock::new(base_prover_client)),
            recursive_prover_client: Arc::new(RwLock::new(recursive_prover_client)),
            recursive_proofs_enabled: config.recursive_proofs,
        })
    }

    async fn prove_with_base_prover(
        &self,
        epoch_height: u64,
        batch: &Batch,
    ) -> Result<(SuccinctProof, SuccinctProof)> {
        let mut stdin = SP1Stdin::new();
        stdin.write(batch);

        let client = self.base_prover_client.read().await;
        info!("generating proof for epoch {}", epoch_height);

        let snark = client.prove(&self.base_proving_key, &stdin).groth16().run()?;
        info!(
            "successfully generated base proof for epoch {}",
            epoch_height
        );

        let stark = client.prove(&self.base_proving_key, &stdin).compressed().run()?;
        info!(
            "successfully generated compressed proof for epoch {}",
            epoch_height
        );

        Ok((snark.try_into()?, stark.try_into()?))
    }

    async fn prove_with_recursive_prover(
        &self,
        epoch_height: u64,
        batch: &Batch,
        db: &Arc<Box<dyn Database>>,
    ) -> Result<(SuccinctProof, SuccinctProof)> {
        let prev_epoch = match db.get_latest_epoch() {
            Ok(epoch) => epoch,
            Err(_) => {
                return Err(anyhow!(
                    "Previous epoch not found for recursive verification at height {}",
                    epoch_height - 1
                ));
            }
        };

        let vk_to_use = if prev_epoch.height == 0 {
            self.base_verifying_key.clone()
        } else {
            self.recursive_verifying_key.clone()
        };

        let mut stdin = SP1Stdin::new();
        let sp1_stark: SP1ProofWithPublicValues = prev_epoch.stark.try_into()?;
        let compressed_proof = match sp1_stark.proof {
            SP1Proof::Compressed(proof) => proof,
            _ => return Err(anyhow!("Invalid proof type: expected compressed proof")),
        };
        stdin.write_proof(*compressed_proof, vk_to_use.clone().vk);
        stdin.write_vec(prev_epoch.snark.public_values.clone());
        stdin.write(&vk_to_use.hash_u32());
        stdin.write(batch);

        let client = self.recursive_prover_client.read().await;
        info!(
            "generating recursive proof for epoch at height {}",
            epoch_height
        );

        let snark = client.prove(&self.recursive_proving_key, &stdin).groth16().run()?;
        info!(
            "successfully generated recursive proof for epoch {}",
            epoch_height
        );
        let stark = client.prove(&self.recursive_proving_key, &stdin).compressed().run()?;
        info!(
            "successfully generated recursive compressed proof for epoch {}",
            epoch_height
        );

        Ok((snark.try_into()?, stark.try_into()?))
    }
}
