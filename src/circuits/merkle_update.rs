use crate::circuits::{
    utils::{recalculate_hash_as_scalar, unpack_and_process},
    ProofVariantCircuit,
};
use crate::{error::PrismError, utils::create_and_verify_snark};
use anyhow::Result;
use bellman::{groth16, Circuit, ConstraintSystem, SynthesisError};
use bls12_381::{Bls12, Scalar};
use indexed_merkle_tree::{node::Node, tree::UpdateProof};

#[derive(Clone)]
pub struct UpdateMerkleProofCircuit {
    pub old_root: Scalar,
    pub old_path: Vec<Node>,
    pub updated_root: Scalar,
    pub updated_path: Vec<Node>,
}

impl UpdateMerkleProofCircuit {
    pub fn new(proof: &UpdateProof) -> Result<UpdateMerkleProofCircuit, PrismError> {
        let (old_root, old_path) = unpack_and_process(&proof.old_proof)?;
        let (updated_root, updated_path) = unpack_and_process(&proof.new_proof)?;

        // if old_root.is_none()
        //     || old_path.is_none()
        //     || updated_root.is_none()
        //     || updated_path.is_none()
        // {
        //     return Err(GeneralError::MissingArgumentError);
        // }

        // // TODO: are there cases where MissingArgumentError isnt the right type?

        // let old_root =
        //     hash_to_scalar(&old_root.ok_or(GeneralError::MissingArgumentError)?.as_str())?;
        // let updated_root = hash_to_scalar(
        //     &updated_root
        //         .ok_or(GeneralError::MissingArgumentError)?
        //         .as_str(),
        // )?;

        // let old_path = old_path.ok_or(GeneralError::MissingArgumentError)?;
        // let updated_path = updated_path.ok_or(GeneralError::MissingArgumentError)?;

        Ok(UpdateMerkleProofCircuit {
            old_root,
            old_path: old_path.clone(),
            updated_root,
            updated_path: updated_path.clone(),
        })
    }

    pub fn create_and_verify_snark(
        &self,
    ) -> Result<(groth16::Proof<Bls12>, groth16::VerifyingKey<Bls12>)> {
        let scalars: Vec<Scalar> = vec![self.old_root, self.updated_root];

        create_and_verify_snark(ProofVariantCircuit::Update(self.clone()), scalars)
    }
}

impl Circuit<Scalar> for UpdateMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        match prove_update(
            cs,
            self.old_root,
            &self.old_path,
            self.updated_root,
            &self.updated_path,
        ) {
            Ok(_) => Ok(()),
            Err(_) => Err(SynthesisError::Unsatisfiable),
        }
    }
}

pub(crate) fn prove_update<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    old_root: Scalar,
    old_path: &[Node],
    new_root: Scalar,
    new_path: &[Node],
) -> Result<Scalar, SynthesisError> {
    let root_with_old_pointer =
        cs.alloc(|| "first update root with old pointer", || Ok(old_root))?;
    let root_with_new_pointer =
        cs.alloc(|| "first update root with new pointer", || Ok(new_root))?;

    // update the root hash for old and new path
    let recalculated_root_with_old_pointer =
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
    )?;

    // Check if the resulting hash is the root hash of the old tree
    // allocated_recalculated_root_with_old_pointer * (1) = root_with_old_pointer
    cs.enforce(
        || "first update old root equality",
        |lc| lc + allocated_recalculated_root_with_old_pointer,
        |lc| lc + CS::one(),
        |lc| lc + root_with_old_pointer,
    );

    // Check that the resulting hash is the root hash of the new tree.
    // allocated_recalculated_root_with_new_pointer * (1) = root_with_new_pointer
    cs.enforce(
        || "first update new root equality",
        |lc| lc + allocated_recalculated_root_with_new_pointer,
        |lc| lc + CS::one(),
        |lc| lc + root_with_new_pointer,
    );

    Ok(recalculated_root_with_new_pointer)
}
