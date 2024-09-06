use crate::tree::UpdateProof;
use crate::utils::{create_proof, verify_proof};
use anyhow::Result;
use bellpepper_core::{Circuit, ConstraintSystem, SynthesisError};
use blstrs::Scalar;

use super::utils::hash_to_scalar;

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
        let old_root = Scalar::from_bytes(&self.update_proof.old_root.0).unwrap();
        let new_root = Scalar::from_bytes(&self.update_proof.new_root.0).unwrap();
        let scalars: Vec<Scalar> = vec![old_root, new_root];

        let proof = create_proof(self)?;
        verify_proof(&proof, &scalars)
    }
}

impl Circuit<Scalar> for UpdateCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        match prove_update(cs, self.update_proof) {
            Ok(_) => Ok(()),
            Err(_) => Err(SynthesisError::Unsatisfiable),
        }
    }
}

pub(crate) fn prove_update<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    update_proof: UpdateProof,
) -> Result<Scalar, SynthesisError> {
    let old_root_sc = hash_to_scalar(&update_proof.old_root);
    let new_root = hash_to_scalar(&update_proof.new_root);
    let path = &update_proof.proof;

    let root_with_old_pointer =
        cs.alloc(|| "first update root with old pointer", || Ok(old_root_sc))?;
    let root_with_new_pointer =
        cs.alloc(|| "first update root with new pointer", || Ok(new_root))?;

    // update the root hash for old and new path+

    // TODO: merkle proof gadget
    update_proof
        .verify()
        .map_err(|_| SynthesisError::Unsatisfiable)?;

    /* let recalculated_root_with_old_pointer =
        recalculate_hash_as_scalar(old_path).map_err(|_| SynthesisError::Unsatisfiable)?;
    let recalculated_root_with_new_pointer =
        recalculate_hash_as_scalar(new_path).map_err(|_| SynthesisError::Unsatisfiable)?;

    let allocated_recalculated_root_with_old_pointer = cs.alloc(
        || "recalculated first update proof old root",
        || Ok(recalculated_root_with_old_pointer),
    )?;
    let allocated_recalculated_root_with_new_pointer = cs.alloc(
        || "recalculated first update proof new root",
        || Ok(recalculated_root_with_new_pointer),
    )?;*/

    // Check if the resulting hash is the root hash of the old tree
    // allocated_recalculated_root_with_old_pointer * (1) = root_with_old_pointer
    cs.enforce(
        || "first update old root equality",
        |lc| lc + root_with_old_pointer,
        |lc| lc + CS::one(),
        |lc| lc + root_with_old_pointer,
    );

    // Check that the resulting hash is the root hash of the new tree.
    // allocated_recalculated_root_with_new_pointer * (1) = root_with_new_pointer
    cs.enforce(
        || "first update new root equality",
        |lc| lc + root_with_new_pointer,
        |lc| lc + CS::one(),
        |lc| lc + root_with_new_pointer,
    );

    Ok(root_with_new_pointer)
}
