use crate::{
    circuits::{
        merkle_update::proof_of_update,
        utils::{hash_to_scalar, recalculate_hash_as_scalar, unpack_and_process},
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

#[derive(Clone)]
pub struct InsertMerkleProofCircuit {
    pub non_membership_root: Scalar,
    pub non_membership_path: Vec<Node>,
    pub missing_node: LeafNode,
    pub first_merkle_proof: UpdateMerkleProofCircuit,
    pub second_merkle_proof: UpdateMerkleProofCircuit,
}

impl InsertMerkleProofCircuit {
    pub fn new(proof: &InsertProof) -> Result<InsertMerkleProofCircuit, PrismError> {
        let (non_membership_root, non_membership_path) =
            unpack_and_process(&proof.non_membership_proof.merkle_proof)?;

        let first_merkle_circuit = UpdateMerkleProofCircuit::new(&proof.first_proof)?;
        let second_merkle_circuit = UpdateMerkleProofCircuit::new(&proof.second_proof)?;

        Ok(InsertMerkleProofCircuit {
            non_membership_root,
            non_membership_path: non_membership_path.clone(),
            missing_node: proof.non_membership_proof.missing_node.clone(),
            first_merkle_proof: first_merkle_circuit,
            second_merkle_proof: second_merkle_circuit,
        })
    }

    pub fn create_and_verify_snark(
        &self,
    ) -> Result<(groth16::Proof<Bls12>, groth16::VerifyingKey<Bls12>)> {
        let scalars: Vec<Scalar> = vec![
            self.non_membership_root,
            self.first_merkle_proof.old_root,
            self.first_merkle_proof.updated_root,
            self.second_merkle_proof.old_root,
            self.second_merkle_proof.updated_root,
        ];

        create_and_verify_snark(ProofVariantCircuit::Insert(self.clone()), scalars)
    }
}

impl Circuit<Scalar> for InsertMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Proof of Non-Membership
        match proof_of_non_membership(
            cs,
            self.non_membership_root,
            &self.non_membership_path,
            self.missing_node,
        ) {
            Ok(_) => (),
            Err(_) => return Err(SynthesisError::AssignmentMissing),
        }

        // Proof of Update for old and new node
        let first_proof = proof_of_update(
            cs,
            self.first_merkle_proof.old_root,
            &self.first_merkle_proof.old_path,
            self.first_merkle_proof.updated_root,
            &self.first_merkle_proof.updated_path,
        );
        let second_update = proof_of_update(
            cs,
            first_proof?,
            &self.second_merkle_proof.old_path,
            self.second_merkle_proof.updated_root,
            &self.second_merkle_proof.updated_path,
        );

        match second_update {
            Ok(_) => Ok(()),
            Err(_) => Err(SynthesisError::Unsatisfiable),
        }
    }
}

pub(crate) fn proof_of_non_membership<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    non_membership_root: Scalar,
    non_membership_path: &[Node],
    missing_node: LeafNode,
) -> Result<(), SynthesisError> {
    // first we need to make sure, that the label of the missing node lies between the first element of the path

    let current_label = hash_to_scalar(&non_membership_path[0].get_label()).unwrap();
    let missing_label = hash_to_scalar(&missing_node.label).unwrap();
    let curret_next = hash_to_scalar(&non_membership_path[0].get_next()).unwrap();

    // circuit check
    LessThanCircuit::new(current_label, missing_label)
        .synthesize(cs)
        .expect("Failed to synthesize");
    LessThanCircuit::new(missing_label, curret_next)
        .synthesize(cs)
        .expect("Failed to synthesize");

    let allocated_root = cs.alloc(|| "non_membership_root", || Ok(non_membership_root))?;
    let recalculated_root = recalculate_hash_as_scalar(non_membership_path);

    if recalculated_root.is_err() {
        return Err(SynthesisError::Unsatisfiable);
    }

    let allocated_recalculated_root = cs.alloc(
        || "recalculated non-membership root",
        || Ok(recalculated_root.unwrap()), // we can unwrap here because we checked that the result is ok
    )?;

    cs.enforce(
        || "non-membership root check",
        |lc| lc + allocated_root,
        |lc| lc + CS::one(),
        |lc| lc + allocated_recalculated_root,
    );

    Ok(())
}
