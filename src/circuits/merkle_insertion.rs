use crate::{
    circuits::{
        merkle_update::prove_update,
        utils::{recalculate_hash_as_scalar, unpack_and_process},
        LessThanCircuit, ProofVariantCircuit, UpdateMerkleProofCircuit,
    },
    error::PrismError,
    utils::create_and_verify_snark,
};
use anyhow::Result;
use bellman::{groth16, Circuit, ConstraintSystem, SynthesisError};
use bls12_381::{Bls12, Scalar};
use indexed_merkle_tree::{
    node::{LeafNode, Node},
    tree::InsertProof,
};

/// Represents a circuit for proving the insertion of a new leaf into a the IMT.
///
/// This circuit encapsulates the entire process of inserting a new leaf,
/// including proving non-membership of the new leaf, updating the existing leaf's next pointer,
/// and activating the new leaf.
#[derive(Clone)]
pub struct InsertMerkleProofCircuit {
    /// The root of the tree before the insertion.
    pub pre_insertion_root: Scalar,
    /// The path from the root to the position where the new node will be inserted,
    /// proving that the node doesn't exist yet.
    pub insertion_path: Vec<Node>,
    /// The new node to be inserted.
    pub new_leaf_node: LeafNode,
    /// Proof for updating the existing leaf to point to the new leaf.
    pub existing_leaf_update: UpdateMerkleProofCircuit,
    /// Proof for activating the new leaf (converting an inactive leaf to active).
    pub new_leaf_activation: UpdateMerkleProofCircuit,
}

impl InsertMerkleProofCircuit {
    pub fn new(proof: &InsertProof) -> Result<InsertMerkleProofCircuit, PrismError> {
        let (non_membership_root, non_membership_path) =
            unpack_and_process(&proof.non_membership_proof.merkle_proof)?;

        let first_merkle_circuit = UpdateMerkleProofCircuit::new(&proof.first_proof)?;
        let second_merkle_circuit = UpdateMerkleProofCircuit::new(&proof.second_proof)?;

        Ok(InsertMerkleProofCircuit {
            pre_insertion_root: non_membership_root,
            insertion_path: non_membership_path.clone(),
            new_leaf_node: proof.non_membership_proof.missing_node.clone(),
            existing_leaf_update: first_merkle_circuit,
            new_leaf_activation: second_merkle_circuit,
        })
    }

    pub fn create_and_verify_snark(
        &self,
    ) -> Result<(groth16::Proof<Bls12>, groth16::VerifyingKey<Bls12>)> {
        let scalars: Vec<Scalar> = vec![
            self.pre_insertion_root,
            self.existing_leaf_update.old_root,
            self.existing_leaf_update.updated_root,
            self.new_leaf_activation.old_root,
            self.new_leaf_activation.updated_root,
        ];

        create_and_verify_snark(ProofVariantCircuit::Insert(self.clone()), scalars)
    }
}

impl Circuit<Scalar> for InsertMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Step 1: Prove non-membership
        // This ensures that the new leaf we're trying to insert doesn't already exist in the tree.
        prove_non_membership(
            cs,
            self.pre_insertion_root,
            &self.insertion_path,
            self.new_leaf_node,
        )?;

        // Step 2: Update the existing leaf
        // This step updates the 'next' pointer of an existing leaf to point to our new leaf.
        let updated_root_after_existing_leaf_update = prove_update(
            cs,
            self.existing_leaf_update.old_root,
            &self.existing_leaf_update.old_path,
            self.existing_leaf_update.updated_root,
            &self.existing_leaf_update.updated_path,
        )?;

        // Step 3: Activate the new leaf
        // This step converts an inactive (empty) leaf into our new active leaf,
        // effectively inserting the new data into the tree.
        prove_update(
            cs,
            updated_root_after_existing_leaf_update,
            &self.new_leaf_activation.old_path,
            self.new_leaf_activation.updated_root,
            &self.new_leaf_activation.updated_path,
        )?;

        Ok(())
    }
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
