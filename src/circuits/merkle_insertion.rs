use crate::{
    circuits::{
        utils::{recalculate_hash_as_scalar, unpack_and_process},
        LessThanCircuit, UpdateCircuit,
    },
    error::PrismError,
    tree::InsertProof,
    utils::{create_proof, verify_proof},
};
use anyhow::Result;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use blstrs::Scalar;
use indexed_merkle_tree::node::{LeafNode, Node};

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
    pub fn new(proof: &InsertProof) -> Result<InsertMerkleProofCircuit, PrismError> {
        let (non_membership_root, non_membership_path) =
            unpack_and_process(&proof.non_membership_proof.merkle_proof)?;

        let first_merkle_circuit = UpdateCircuit::new(&proof.first_proof)?;
        let second_merkle_circuit = UpdateCircuit::new(&proof.second_proof)?;

        Ok(InsertMerkleProofCircuit {
            insertion_proof: proof,
        })
    }

    pub fn create_and_verify_snark(&self) -> Result<bool> {
        let non_membership_proorf_sc =
            Scalar::from_bytes(&self.insertion_proof.non_membership_proof.root).unwrap();
        let first_proof_sc = Scalar::from_bytes(&self.insertion_proof.new_root).unwrap();
        let scalars: Vec<Scalar> = vec![];

        let proof = create_proof(self);
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
    // Step 1: Prove non-membership
    // This ensures that the new leaf we're trying to insert doesn't already exist in the tree.
    insert_proof.non_membership_proof.verify()?;

    insert_proof.membership_proof.verify()?;

    // Step 2: Update the existing leaf
    // This step updates the 'next' pointer of an existing leaf to point to our new leaf.
    /* let updated_root_after_existing_leaf_update = prove_update(
        cs,
        existing_leaf_update.old_root,
        &existing_leaf_update.old_path,
        existing_leaf_update.updated_root,
        &existing_leaf_update.updated_path,
    )?;

    // Step 3: Activate the new leaf
    // This step converts an inactive (empty) leaf into our new active leaf,
    // effectively inserting the new data into the tree.
    let new_root = prove_update(
        cs,
        updated_root_after_existing_leaf_update,
        &new_leaf_activation.old_path,
        new_leaf_activation.updated_root,
        &new_leaf_activation.updated_path,
    )?; */

    let new_root_sc = Scalar::from_bytes(&insert_proof.new_root).unwrap();

    Ok(new_root_sc)
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
    // Ensure that the label of the new leaf node lies between the first element of the path
    // and its next pointer. This guarantees that no other node with a label between these values exists.
    let existing_leaf_label: Scalar = insertion_path[0]
        .get_label()
        .try_into()
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    let existing_leaf_next: Scalar = insertion_path[0]
        .get_next()
        .try_into()
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    let new_leaf_label: Scalar = new_leaf_node
        .label
        .try_into()
        .map_err(|_| SynthesisError::Unsatisfiable)?;

    // Enforce: existing_leaf_label < new_leaf_label < existing_leaf_next
    LessThanCircuit::new(existing_leaf_label, new_leaf_label)
        .synthesize(cs)
        .expect("Failed to synthesize existing_leaf_label < new_leaf_label");
    LessThanCircuit::new(new_leaf_label, existing_leaf_next)
        .synthesize(cs)
        .expect("Failed to synthesize new_leaf_label < existing_leaf_next");

    let allocated_pre_insertion_root =
        cs.alloc(|| "pre_insertion_root", || Ok(pre_insertion_root))?;

    let recalculated_root =
        recalculate_hash_as_scalar(insertion_path).map_err(|_| SynthesisError::Unsatisfiable)?;

    let allocated_recalculated_root = cs.alloc(
        || "recalculated_pre_insertion_root",
        || Ok(recalculated_root),
    )?;

    // Enforce that the provided pre-insertion root matches the recalculated root.
    // This ensures that the ordered structure of the tree is maintained in the path.
    // (allocated_pre_insertion_root) * (1) = allocated_recalculated_root
    cs.enforce(
        || "pre_insertion_root_verification",
        |lc| lc + allocated_pre_insertion_root,
        |lc| lc + CS::one(),
        |lc| lc + allocated_recalculated_root,
    );

    Ok(())
}
