use crate::{
    circuits::{
        merkle_insertion::prove_non_membership, merkle_update::prove_update,
        InsertMerkleProofCircuit, ProofVariantCircuit, UpdateMerkleProofCircuit,
    },
    utils::create_and_verify_snark,
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
                    proof_circuit_array.push(ProofVariantCircuit::Update(
                        UpdateMerkleProofCircuit::new(&update_proof)?,
                    ));
                }
                Proof::Insert(insertion_proof) => {
                    proof_circuit_array.push(ProofVariantCircuit::Insert(
                        InsertMerkleProofCircuit::new(&insertion_proof)?,
                    ));
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
        if self.proofs.is_empty() {
            let provided_old_commitment =
                cs.alloc_input(|| "provided old commitment", || Ok(self.old_commitment))?;
            let provided_new_commitment =
                cs.alloc_input(|| "provided new commitment", || Ok(self.new_commitment))?;
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

        cs.enforce(
            || "old commitment check",
            |lc| lc + old_commitment_from_proofs,
            |lc| lc + CS::one(),
            |lc| lc + provided_old_commitment,
        );

        let mut new_commitment: Option<Scalar> = None;
        for proof_variant in self.proofs {
            match proof_variant {
                ProofVariantCircuit::Update(update_proof_circuit) => {
                    new_commitment = Some(prove_update(
                        cs,
                        update_proof_circuit.old_root,
                        &update_proof_circuit.old_path,
                        update_proof_circuit.updated_root,
                        &update_proof_circuit.updated_path,
                    )?);
                }
                ProofVariantCircuit::Insert(insert_proof_circuit) => {
                    // Proof of Non-Membership
                    match prove_non_membership(
                        cs,
                        insert_proof_circuit.pre_insertion_root,
                        &insert_proof_circuit.insertion_path,
                        insert_proof_circuit.new_leaf_node,
                    ) {
                        Ok(_) => (),
                        Err(_) => return Err(SynthesisError::AssignmentMissing),
                    }

                    // Proof of Update for the old and new node
                    let calculated_root_from_first_proof = prove_update(
                        cs,
                        insert_proof_circuit.existing_leaf_update.old_root,
                        &insert_proof_circuit.existing_leaf_update.old_path,
                        insert_proof_circuit.existing_leaf_update.updated_root,
                        &insert_proof_circuit.existing_leaf_update.updated_path,
                    );
                    new_commitment = Some(prove_update(
                        cs,
                        calculated_root_from_first_proof?,
                        &insert_proof_circuit.new_leaf_activation.old_path,
                        insert_proof_circuit.new_leaf_activation.updated_root,
                        &insert_proof_circuit.new_leaf_activation.updated_path,
                    )?);
                }
                ProofVariantCircuit::Batch(_) => {
                    // Batches cannot be recursively constructed
                    // TODO: Should they be able to?
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
        }

        if let Some(new_commitment) = new_commitment {
            let provided_new_commitment =
                cs.alloc_input(|| "provided commitment", || Ok(self.new_commitment))?;
            let recalculated_new_commitment =
                cs.alloc(|| "recalculated commitment", || Ok(new_commitment))?;

            cs.enforce(
                || "new commitment check",
                |lc| lc + recalculated_new_commitment,
                |lc| lc + CS::one(),
                |lc| lc + provided_new_commitment,
            );

            Ok(())
        } else {
            Err(SynthesisError::Unsatisfiable)
        }
    }
}
