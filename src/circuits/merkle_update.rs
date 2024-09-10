use crate::tree::{Digest, UpdateProof};
use crate::utils::{load_params_from_storage, verify_proof};
use anyhow::Result;
use bellperson::groth16;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use blstrs::Scalar;
use rand::rngs::OsRng;

use super::utils::{allocate_bits_to_binary_number, verify_membership_proof};

#[derive(Clone)]
pub struct UpdateCircuit {
    pub update_proof: UpdateProof,
}

impl UpdateCircuit {
    pub fn new(proof: UpdateProof) -> Self {
        Self {
            update_proof: proof,
        }
    }

    pub fn create_and_verify_snark(&self) -> Result<bool> {
        let old_root: Scalar = Digest::from(self.update_proof.old_root.into()).try_into()?;
        let new_root: Scalar = Digest::from(self.update_proof.new_root.into()).try_into()?;
        let scalars: Vec<Scalar> = vec![old_root, new_root];

        let circuit = UpdateCircuit::new(self.update_proof.clone());

        let params = load_params_from_storage()?;

        let rng = &mut OsRng;
        let proof = groth16::create_random_proof(circuit, &params, rng)?;

        verify_proof(&proof, &scalars)
    }
}

impl Circuit<Scalar> for UpdateCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let old_root_bits =
            allocate_bits_to_binary_number(cs, self.update_proof.old_root.0.to_vec())?;

        let update_proof = &self.update_proof.proof.proofs()[0];

        let leaf = update_proof.leaf().ok_or(SynthesisError::Unsatisfiable)?;

        verify_membership_proof(cs, update_proof, &old_root_bits, leaf)
    }
}

// heuking zusammenarbeit
