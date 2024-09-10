use crate::{
    circuits::{
        merkle_insertion::prove_insertion, InsertMerkleProofCircuit, ProofVariantCircuit,
        UpdateCircuit,
    },
    tree::{Digest, Proof},
    utils::verify_proof,
};
use anyhow::Result;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use blstrs::Scalar;

use super::utils::digest_to_scalar;

/// BatchMerkleProofCircuit represents a circuit for proving a batch of merkle proof circuits.
#[derive(Clone)]
pub struct BatchMerkleProofCircuit {
    pub old_commitment: Scalar,
    pub new_commitment: Scalar,
    pub proofs: Vec<ProofVariantCircuit>,
}

impl BatchMerkleProofCircuit {
    pub fn new(
        old_commitment: Scalar,
        new_commitment: Scalar,
        proofs: Vec<Proof>,
    ) -> Result<BatchMerkleProofCircuit> {
        let mut proof_circuit_array: Vec<ProofVariantCircuit> = vec![];
        for proof in proofs {
            match proof {
                Proof::Update(update_proof) => {
                    proof_circuit_array.push(ProofVariantCircuit::Update(UpdateCircuit::new(
                        update_proof,
                    )));
                }
                Proof::Insert(insertion_proof) => {
                    proof_circuit_array.push(ProofVariantCircuit::Insert(
                        InsertMerkleProofCircuit::new(insertion_proof),
                    ));
                }
            }
        }
        Ok(BatchMerkleProofCircuit {
            old_commitment,
            new_commitment,
            proofs: proof_circuit_array,
        })
    }

    /* pub fn create_and_verify_snark(&self) -> Result<bool> {
        let scalars: Vec<Scalar> = vec![self.old_commitment, self.new_commitment];

        let circuit = BatchMerkleProofCircuit::new(
            self.old_commitment,
            self.new_commitment,
            self.proofs.clone(),
        )?;

        let params = load_params_from_storage()?;

        let rng = &mut OsRng;
        let proof = groth16::create_random_proof(circuit, &params, rng)?;

        let proof = create_proof(self);
        verify_proof(proof, &scalars)
    } */
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
            ProofVariantCircuit::Update(update_proof_circuit) => {
                update_proof_circuit.update_proof.old_root
            }
            ProofVariantCircuit::Insert(insert_proof_circuit) => insert_proof_circuit
                .insertion_proof
                .non_membership_proof
                .root
                .into(),
            /* ProofVariantCircuit::Batch(batch_proof_circuit) => batch_proof_circuit.old_commitment, */
        };

        let old_root_scalar =
            digest_to_scalar(&old_root.into()).map_err(|_| SynthesisError::Unsatisfiable)?;

        let provided_old_commitment =
            cs.alloc_input(|| "provided old commitment", || Ok(self.old_commitment))?;
        let old_commitment_from_proofs =
            cs.alloc(|| "old commitment from proofs", || Ok(old_root_scalar))?;

        // old_commitment_from_proofs * (1) = provided_old_commitment
        cs.enforce(
            || "old commitment check",
            |lc| lc + old_commitment_from_proofs,
            |lc| lc + CS::one(),
            |lc| lc + provided_old_commitment,
        );

        let mut new_commitment: Scalar = Scalar::from(0);
        for proof in self.proofs {
            // update the new_commitment for every proof, applying the constraints of the circuit each time
            match proof {
                ProofVariantCircuit::Update(update_proof_circuit) => {
                    new_commitment = prove_update(cs, update_proof_circuit)?;
                }
                ProofVariantCircuit::Insert(insert_proof_circuit) => {
                    new_commitment = prove_insertion(cs, insert_proof_circuit)?;
                } /* ProofVariantCircuit::Batch(_) => {
                      // Batches cannot be recursively constructed
                      // TODO: Should they be able to?
                      return Err(SynthesisError::Unsatisfiable);
                  } */
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
