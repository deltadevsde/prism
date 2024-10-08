use crate::{
    merkle_insertion::prove_insertion, merkle_update::prove_update, utils::create_and_verify_snark,
    InsertMerkleProofCircuit, ProofVariantCircuit, UpdateMerkleProofCircuit,
};
use anyhow::Result;
use bellman::{groth16, Circuit, ConstraintSystem, SynthesisError};
use bls12_381::{Bls12, Scalar};
use indexed_merkle_tree::{tree::Proof, Hash};

/// BatchMerkleProofCircuit represents a circuit for proving a batch of merkle proof circuits.
#[derive(Clone)]
pub struct BatchMerkleProofCircuit {
    pub old_commitment: Scalar,
    pub new_commitment: Scalar,
    pub proofs: Vec<ProofVariantCircuit>,
}

impl BatchMerkleProofCircuit {
    pub fn new(
        old_commitment: &Hash,
        new_commitment: &Hash,
        proofs: Vec<Proof>,
    ) -> Result<BatchMerkleProofCircuit> {
        let parsed_old_commitment: Scalar = (*old_commitment).try_into()?;
        let parsed_new_commitment: Scalar = (*new_commitment).try_into()?;
        let mut proof_circuit_array: Vec<ProofVariantCircuit> = vec![];
        for proof in proofs {
            match proof {
                Proof::Update(update_proof) => {
                    proof_circuit_array.push(ProofVariantCircuit::Update(Box::new(
                        UpdateMerkleProofCircuit::new(&update_proof)?,
                    )));
                }
                Proof::Insert(insertion_proof) => {
                    proof_circuit_array.push(ProofVariantCircuit::Insert(Box::new(
                        InsertMerkleProofCircuit::new(&insertion_proof)?,
                    )));
                }
            }
        }
        Ok(BatchMerkleProofCircuit {
            old_commitment: parsed_old_commitment,
            new_commitment: parsed_new_commitment,
            proofs: proof_circuit_array,
        })
    }

    pub fn create_and_verify_snark(
        &self,
    ) -> Result<(groth16::Proof<Bls12>, groth16::VerifyingKey<Bls12>)> {
        let scalars: Vec<Scalar> = vec![self.old_commitment, self.new_commitment];

        create_and_verify_snark(ProofVariantCircuit::Batch(self.clone()), scalars)
    }
}

impl Circuit<Scalar> for BatchMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // If the proofs are empty, we just verify that the commitments are equal
        if self.proofs.is_empty() {
            let provided_old_commitment =
                cs.alloc_input(|| "provided old commitment", || Ok(self.old_commitment))?;
            let provided_new_commitment =
                cs.alloc_input(|| "provided new commitment", || Ok(self.new_commitment))?;

            // provided_old_commitment * (1) = provided_new_commitment
            cs.enforce(
                || "old commitment check",
                |lc| lc + provided_old_commitment,
                |lc| lc + CS::one(),
                |lc| lc + provided_new_commitment,
            );

            return Ok(());
        }

        // before the calculations make sure that the old root is that of the first proof
        let old_root = match &self.proofs[0] {
            ProofVariantCircuit::Update(update_proof_circuit) => update_proof_circuit.old_root,
            ProofVariantCircuit::Insert(insert_proof_circuit) => {
                insert_proof_circuit.pre_insertion_root
            }
            ProofVariantCircuit::Batch(batch_proof_circuit) => batch_proof_circuit.old_commitment,
        };

        let provided_old_commitment =
            cs.alloc_input(|| "provided old commitment", || Ok(self.old_commitment))?;
        let old_commitment_from_proofs =
            cs.alloc(|| "old commitment from proofs", || Ok(old_root))?;

        // old_commitment_from_proofs * (1) = provided_old_commitment
        cs.enforce(
            || "old commitment check",
            |lc| lc + old_commitment_from_proofs,
            |lc| lc + CS::one(),
            |lc| lc + provided_old_commitment,
        );

        let mut new_commitment: Scalar = Scalar::zero();
        for proof in self.proofs {
            // update the new_commitment for every proof, applying the constraints of the circuit each time
            match proof {
                ProofVariantCircuit::Update(update_proof_circuit) => {
                    new_commitment = prove_update(
                        cs,
                        update_proof_circuit.old_root,
                        &update_proof_circuit.old_path,
                        update_proof_circuit.updated_root,
                        &update_proof_circuit.updated_path,
                    )?;
                }
                ProofVariantCircuit::Insert(insert_proof_circuit) => {
                    new_commitment = prove_insertion(
                        cs,
                        insert_proof_circuit.pre_insertion_root,
                        &insert_proof_circuit.insertion_path,
                        insert_proof_circuit.new_leaf_node,
                        insert_proof_circuit.existing_leaf_update,
                        insert_proof_circuit.new_leaf_activation,
                    )?;
                }
                ProofVariantCircuit::Batch(_) => {
                    // Batches cannot be recursively constructed
                    // TODO: Should they be able to?
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
        }

        let provided_new_commitment =
            cs.alloc_input(|| "provided commitment", || Ok(self.new_commitment))?;
        let recalculated_new_commitment =
            cs.alloc(|| "recalculated commitment", || Ok(new_commitment))?;

        // recalculated_commitment * (1) = provided_commitment
        cs.enforce(
            || "new commitment check",
            |lc| lc + recalculated_new_commitment,
            |lc| lc + CS::one(),
            |lc| lc + provided_new_commitment,
        );

        Ok(())
    }
}
