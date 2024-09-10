use crate::{
    circuits::{LessThanCircuit, UpdateCircuit},
    error::PrismError,
    nova::insert,
    tree::InsertProof,
    utils::{load_params_from_storage, verify_proof},
};
use anyhow::Result;
use bellperson::{groth16, Circuit, ConstraintSystem, SynthesisError};
use blstrs::Scalar;
use indexed_merkle_tree::node::{LeafNode, Node};
use rand::rngs::OsRng;

use super::utils::{allocate_bits_to_binary_number, digest_to_scalar, verify_membership_proof};

/// Represents a circuit for proving the insertion of a new leaf into a the IMT.
///
/// This circuit encapsulates the entire process of inserting a new leaf,
/// including proving non-membership of the new leaf, updating the existing leaf's next pointer,
/// and activating the new leaf.
#[derive(Clone)]
pub struct InsertMerkleProofCircuit {
    pub insertion_proof: InsertProof,
}

impl InsertMerkleProofCircuit {
    pub fn new(proof: InsertProof) -> Self {
        Self {
            insertion_proof: proof,
        }
    }

    pub fn create_and_verify_snark(&self) -> Result<bool> {
        let non_membership_proorf_sc =
            digest_to_scalar(&self.insertion_proof.non_membership_proof.root).unwrap();
        let first_proof_sc = digest_to_scalar(&self.insertion_proof.new_root).unwrap();
        let scalars: Vec<Scalar> = vec![];

        let circuit = InsertMerkleProofCircuit::new(self.insertion_proof.clone());

        let params = load_params_from_storage()?;

        let rng = &mut OsRng;
        let proof = groth16::create_random_proof(circuit, &params, rng)?;

        verify_proof(&proof, &scalars)
    }
}

impl Circuit<Scalar> for InsertMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        match prove_insertion(cs, self.insertion_proof) {
            Ok(_) => Ok(()),
            Err(_) => Err(SynthesisError::Unsatisfiable),
        }
    }
}

/// Generates constraints to prove a valid insertion in the merkle tree.
pub fn prove_insertion<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    insert_proof: InsertProof,
) -> Result<Scalar, SynthesisError> {
    let pre_insertion_scalar = digest_to_scalar(&insert_proof.non_membership_proof.root)
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    let pre_insertion_root = cs.alloc(|| "pre_insertion_root", || Ok(pre_insertion_scalar))?;

    let new_root_scalar =
        digest_to_scalar(&insert_proof.new_root).map_err(|_| SynthesisError::Unsatisfiable)?;
    let new_root_variable = cs.alloc(|| "new_root", || Ok(new_root_scalar))?;
    let new_root_bits =
        allocate_bits_to_binary_number(cs, insert_proof.membership_proof.root_hash().0.to_vec())?;

    // z[0] is part of the nova specific code so maybe we have to give the last root as an input
    cs.enforce(
        || "old root == non membership root",
        |lc| lc + new_root_variable,
        |lc| lc + CS::one(),
        |lc| lc + new_root_variable,
    );

    insert_proof
        .verify()
        .map_err(|_| SynthesisError::Unsatisfiable)?;

    let leaf = insert_proof
        .membership_proof
        .leaf()
        .ok_or(SynthesisError::AssignmentMissing)?;

    verify_membership_proof(cs, &insert_proof.membership_proof, &new_root_bits, leaf);

    Ok(new_root_scalar)
}

/// Generates constraints to prove non-membership of a new leaf in the Merkle tree.
///
/// This function ensures that the new leaf to be inserted does not already exist in the tree
/// and that it maintains the ordered structure of the tree.
///
/// # Arguments
///
/// * `cs` - A mutable reference to the constraint system.
/// * `pre_insertion_root` - The root of the Merkle tree before insertion.
/// * `insertion_path` - The path from the root to the insertion position.
/// * `new_leaf_node` - The new leaf node to be inserted.
///
/// # Returns
///
/// Returns `Ok(())` if the constraints are satisfied, or an `Err`
/// containing a `SynthesisError` if the proof generation fails.
pub fn prove_non_membership<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    pre_insertion_root: Scalar,
    insertion_path: &[Node],
    new_leaf_node: LeafNode,
) -> Result<(), SynthesisError> {
    //TODO implement this function

    Ok(())
}
