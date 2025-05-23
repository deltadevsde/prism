use anyhow::{Result, anyhow};
use prism_storage::database::Database;
use prism_tree::proofs::Batch;
use sp1_sdk::{
    EnvProver, HashableKey as _, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1ProvingKey,
    SP1Stdin, SP1VerifyingKey,
};
use std::sync::Arc;
use tokio::sync::RwLock;

pub const BASE_PRISM_ELF: &[u8] =
    include_bytes!("../../../../elf/base-riscv32im-succinct-zkvm-elf");
pub const RECURSIVE_PRISM_ELF: &[u8] =
    include_bytes!("../../../../elf/recursive-riscv32im-succinct-zkvm-elf");

#[derive(Clone)]
pub struct ProverEngine {
    base_prover_client: Arc<RwLock<EnvProver>>,
    base_proving_key: SP1ProvingKey,
    base_verifying_key: SP1VerifyingKey,

    recursive_prover_client: Arc<RwLock<EnvProver>>,
    recursive_proving_key: SP1ProvingKey,
    recursive_verifying_key: SP1VerifyingKey,

    recursive_proofs_enabled: bool,
}

impl ProverEngine {
    pub fn new(recursive_proofs_enabled: bool) -> Result<Self> {
        let base_prover_client = ProverClient::from_env();
        let recursive_prover_client = ProverClient::from_env();

        let (base_pk, base_vk) = base_prover_client.setup(BASE_PRISM_ELF);
        let (recursive_pk, recursive_vk) = recursive_prover_client.setup(RECURSIVE_PRISM_ELF);

        Ok(ProverEngine {
            base_proving_key: base_pk,
            base_verifying_key: base_vk,
            recursive_proving_key: recursive_pk,
            recursive_verifying_key: recursive_vk,
            base_prover_client: Arc::new(RwLock::new(base_prover_client)),
            recursive_prover_client: Arc::new(RwLock::new(recursive_prover_client)),
            recursive_proofs_enabled,
        })
    }

    pub async fn prove_epoch(
        &self,
        epoch_height: u64,
        batch: &Batch,
        db: &Arc<Box<dyn Database>>,
    ) -> Result<(SP1ProofWithPublicValues, SP1ProofWithPublicValues)> {
        let (proof, compressed_proof, client, verifying_key) =
            if epoch_height == 0 || !self.recursive_proofs_enabled {
                self.prove_with_base_prover(epoch_height, batch).await?
            } else {
                self.prove_with_recursive_prover(epoch_height, batch, db).await?
            };

        client.verify(&proof, verifying_key)?;
        info!("verified proof for epoch {}", epoch_height);

        Ok((proof, compressed_proof))
    }

    async fn prove_with_base_prover(
        &self,
        epoch_height: u64,
        batch: &Batch,
    ) -> Result<(
        SP1ProofWithPublicValues,
        SP1ProofWithPublicValues,
        tokio::sync::RwLockReadGuard<'_, EnvProver>,
        &SP1VerifyingKey,
    )> {
        let mut stdin = SP1Stdin::new();
        stdin.write(batch);

        let client = self.base_prover_client.read().await;
        info!("generating proof for epoch {}", epoch_height);

        let proof = client.prove(&self.base_proving_key, &stdin).groth16().run()?;
        info!(
            "successfully generated base proof for epoch {}",
            epoch_height
        );

        let compressed_proof = client.prove(&self.base_proving_key, &stdin).compressed().run()?;
        info!(
            "successfully generated compressed proof for epoch {}",
            epoch_height
        );

        Ok((proof, compressed_proof, client, &self.base_verifying_key))
    }

    async fn prove_with_recursive_prover(
        &self,
        epoch_height: u64,
        batch: &Batch,
        db: &Arc<Box<dyn Database>>,
    ) -> Result<(
        SP1ProofWithPublicValues,
        SP1ProofWithPublicValues,
        tokio::sync::RwLockReadGuard<'_, EnvProver>,
        &SP1VerifyingKey,
    )> {
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
        let compressed_proof = match prev_epoch.compressed_proof.proof {
            SP1Proof::Compressed(proof) => proof,
            _ => return Err(anyhow!("Invalid proof type: expected compressed proof")),
        };
        stdin.write_proof(*compressed_proof, vk_to_use.clone().vk);
        stdin.write_vec(prev_epoch.public_values.to_vec());
        stdin.write(&vk_to_use.hash_u32());
        stdin.write(batch);

        let client = self.recursive_prover_client.read().await;
        info!(
            "generating recursive proof for epoch at height {}",
            epoch_height
        );

        let proof = client.prove(&self.recursive_proving_key, &stdin).groth16().run()?;
        info!(
            "successfully generated recursive proof for epoch {}",
            epoch_height
        );
        let compressed_proof =
            client.prove(&self.recursive_proving_key, &stdin).compressed().run()?;
        info!(
            "successfully generated recursive compressed proof for epoch {}",
            epoch_height
        );

        Ok((
            proof,
            compressed_proof,
            client,
            &self.recursive_verifying_key,
        ))
    }

    pub fn get_verifying_key(&self, epoch_height: u64) -> &SP1VerifyingKey {
        if epoch_height == 0 || !self.recursive_proofs_enabled {
            &self.base_verifying_key
        } else {
            &self.recursive_verifying_key
        }
    }

    pub async fn verify_epoch_proof(
        &self,
        epoch_height: u64,
        proof: &SP1ProofWithPublicValues,
    ) -> Result<()> {
        let client = if epoch_height == 0 || !self.recursive_proofs_enabled {
            self.base_prover_client.read().await
        } else {
            self.recursive_prover_client.read().await
        };

        let verifying_key = self.get_verifying_key(epoch_height);

        client.verify(proof, verifying_key)?;
        Ok(())
    }
}
