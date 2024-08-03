use anyhow::{anyhow, Result};
use bellpepper_core::{
    num::{AllocatedNum, Num},
    ConstraintSystem, SynthesisError,
};
use core::marker::PhantomData;
use ff::PrimeField;
use indexed_merkle_tree::{
    node::LeafNode,
    node::Node,
    sha256_mod,
    tree::{MerkleProof, NonMembershipProof},
};
use nova_snark::{
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::circuit::StepCircuit,
};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;

#[derive(Clone)]
enum UnifiedProofStep {
    /// Update proof step ensures that an existing LeafNode is updated with a new value.
    /// Cares about inputs z[0].
    // TODO: adr-003: Adding authentication circuit with poseidon hash, which is not needed in Verdict but needed here.
    // This is because Verdict assumes the downstream application verifies the hashchain themselves.
    // We need to be able to prove the validity of the hashchain though, since anybody can post an Update operation.
    Update {
        old_proof: MerkleProof,
        new_proof: MerkleProof,
    },
    /// InsertStart proof step ensures that a LeafNode to be inserted does not yet exist in the tree.
    /// Cares about inputs z[0].
    InsertStart {
        non_membership_proof: NonMembershipProof,
        new_leaf: LeafNode,
    },
    /// InsertUpdate proof step ensures that:
    /// 1. There exists a LeafNode where existing_node.label < new_node.label < existing_node.next
    /// 2. The existing_node's next pointer is updated to new_node.label.
    /// Cares about inputs z[0] and z[2].
    InsertUpdate {
        old_proof: MerkleProof,
        new_proof: MerkleProof,
    },
    /// InsertEnd proof step ensures that the new_node from the last step is added to the tree.
    /// Cares about inputs z[0] and z[1].
    InsertEnd {
        old_proof: MerkleProof,
        new_proof: MerkleProof,
    },
}

#[derive(Clone)]
struct MerkleProofStepCircuit<Scalar: PrimeField> {
    step_type: UnifiedProofStep,
    old_root: Option<Scalar>,
    new_root: Option<Scalar>,
    proof_path: Vec<Node>,

    // Additional fields for non-membership proof
    is_non_membership: bool,
    missing_node: Option<LeafNode>,
    _p: PhantomData<Scalar>,
}

// TODO: these are just here temporarily as I write the circuits, they need to be moved to where the circuit gets instantiated later //////////////////////

struct Hash<Scalar: PrimeField> {
    hash: indexed_merkle_tree::Hash,
    _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField> Hash<Scalar> {
    pub fn new(hash: indexed_merkle_tree::Hash) -> Self {
        Self {
            hash,
            _p: PhantomData,
        }
    }

    // uses [`PrimeField::from_u128`] for inspiration. If the field element's capacity is not enough to hold the hash,
    pub fn to_scalar(&self) -> Result<Scalar> {
        let bytes = self.hash.as_ref();

        // Convert the 32 bytes to two u128 values
        let lower = u128::from_le_bytes(bytes[0..16].try_into()?);
        let upper = u128::from_le_bytes(bytes[16..32].try_into()?);

        let mut tmp = Scalar::from_u128(upper);
        for _ in 0..128 {
            tmp = tmp.double();
        }
        Ok(tmp + Scalar::from_u128(lower))
    }
}

pub fn unpack_and_process<Scalar: PrimeField>(proof: &MerkleProof) -> Result<(Scalar, &Vec<Node>)> {
    if !proof.path.is_empty() {
        let root: Scalar = Hash::new(proof.root_hash).to_scalar()?;
        Ok((root, &proof.path))
    } else {
        // TODO: This if else makes no sense, can't we just give an empty path and let the circuit handle it?
        Err(anyhow!("Proof path is empty."))
    }
}

pub fn recalculate_hash_as_scalar<Scalar: PrimeField>(path: &[Node]) -> Result<Scalar> {
    let mut current_hash = path[0].get_hash();
    for node in path.iter().skip(1) {
        let combined = if node.is_left_sibling() {
            [node.get_hash().as_ref(), current_hash.as_ref()].concat()
        } else {
            [current_hash.as_ref(), node.get_hash().as_ref()].concat()
        };
        // TODO: sha256_mod is not generic for scalar, its using the order of bls12_381
        current_hash = sha256_mod(&combined);
    }
    Hash::new(current_hash).to_scalar()
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

impl<Scalar: PrimeField> StepCircuit<Scalar> for MerkleProofStepCircuit<Scalar> {
    fn arity(&self) -> usize {
        // z[0] is the old root
        // z[1] is the existing node's label
        // z[2] is the missing node's label
        3
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // ahhhh these probably arent always filled in, need to check if they are None and handle that
        let previous_root = &z[0];
        let existing_node_label = &z[1];
        let missing_node_label = &z[2];

        let mut z_out: Vec<AllocatedNum<Scalar>> = Vec::new();

        match self.step_type.clone() {
            UnifiedProofStep::Update {
                old_proof,
                new_proof,
            } => {
                let vars = self.process_update(cs, &old_proof, &new_proof)?;
                let updated_root = vars[1].clone();
                z_out.push(updated_root);
                z_out.push(missing_node_label.clone());
                z_out.push(existing_node_label.clone());
                Ok(z_out)
            }
            UnifiedProofStep::InsertStart {
                non_membership_proof,
                new_leaf,
            } => {
                let (non_membership_root, non_membership_path) =
                    unpack_and_process::<Scalar>(&non_membership_proof.merkle_proof).unwrap();
                // todo: reminder. use push and pop namespace
                // let namespace = format!("non-membership for {:?}", non_membership_root);

                // TODO: LessThan gadget
                let existing_leaf = non_membership_path.first().unwrap();
                let existing_leaf_label: Scalar = Hash::new(existing_leaf.clone().get_label())
                    .to_scalar()
                    .unwrap();
                // let existing_leaf_next: Scalar = Hash::new(existing_leaf.clone().get_next())
                //     .to_scalar()
                //     .unwrap();
                let new_leaf_label: Scalar = Hash::new(new_leaf.label).to_scalar().unwrap();

                let allocated_pre_insertion_root =
                    AllocatedNum::alloc(cs.namespace(|| "pre_insertion_root"), || {
                        Ok(non_membership_root)
                    })?;

                let recalculated_root = recalculate_hash_as_scalar::<Scalar>(non_membership_path)
                    .map_err(|_| SynthesisError::Unsatisfiable)?;

                let allocated_recalculated_root = AllocatedNum::alloc(
                    cs.namespace(|| "recalculated_pre_insertion_root"),
                    || Ok(recalculated_root),
                )?;

                // Enforce that the provided pre-insertion root matches the recalculated root.
                // This ensures that the ordered structure of the tree is maintained in the path.
                // (allocated_pre_insertion_root) * (1) = allocated_recalculated_root
                cs.enforce(
                    || "pre_insertion_root_verification",
                    |lc| lc + allocated_pre_insertion_root.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + allocated_recalculated_root.get_variable(),
                );

                // we don't update the root in this operation, so we pass it on
                z_out.push(previous_root.clone());

                // but we do need to allocate for the next Insert step functions
                let z1 = AllocatedNum::alloc(cs.namespace(|| "z1"), || Ok(existing_leaf_label))?;
                let z2 = AllocatedNum::alloc(cs.namespace(|| "z2"), || Ok(new_leaf_label))?;
                z_out.push(z1);
                z_out.push(z2);
                Ok(z_out)
            }
            UnifiedProofStep::InsertUpdate {
                old_proof,
                new_proof,
            } => {
                let old_element_hash: Scalar = Hash::new(old_proof.path.last().unwrap().get_hash())
                    .to_scalar()
                    .unwrap();
                let old_element_hash_alloc =
                    AllocatedNum::alloc(cs.namespace(|| format!("TODO")), || Ok(old_element_hash))?;
                cs.enforce(
                    || "z1 equality check pre-proof: NAMESPACE TODO",
                    |lc| lc + existing_node_label.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + old_element_hash_alloc.get_variable(),
                );
                // todo: does the hash contain the next value? if so, we shouldnt constrain it to the new proof as below
                let new_element_hash: Scalar = Hash::new(new_proof.path.last().unwrap().get_hash())
                    .to_scalar()
                    .unwrap();
                let new_element_hash_alloc =
                    AllocatedNum::alloc(cs.namespace(|| format!("TODO")), || Ok(new_element_hash))?;
                cs.enforce(
                    || "z1 equality check post-proof: NAMESPACE TODO",
                    |lc| lc + existing_node_label.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + new_element_hash_alloc.get_variable(),
                );

                let vars = self.process_update(cs, &old_proof, &new_proof).unwrap();
                let updated_root = vars[1].clone();

                z_out.push(updated_root);
                z_out.push(missing_node_label.clone());
                z_out.push(existing_node_label.clone());
                Ok(z_out)
            }
            UnifiedProofStep::InsertEnd {
                old_proof,
                new_proof,
            } => {
                let vars = self.process_update(cs, &old_proof, &new_proof)?;
                let updated_root = vars[1].clone();
                z_out.push(updated_root);
                Ok(z_out)
            }
        }
    }
}

impl<Scalar: PrimeField> MerkleProofStepCircuit<Scalar> {
    fn process_update<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        old_proof: &MerkleProof,
        new_proof: &MerkleProof,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // todo: we should be checking z[0] against old_root, the reason I don't yet here is because idk how to handle the case where this is the first proof step

        // todo: perhaps add a cumulative iterator to z to make it easier to find problems later,
        // using intermediate roots as a namespace will cause a bit of searching
        let namespace = format!("{:?}->{:?}", old_proof.root_hash, new_proof.root_hash);

        // todo: repalce unwraps when i get a sec

        let (old_root, old_path) = unpack_and_process::<Scalar>(old_proof).unwrap();
        let (updated_root, updated_path) = unpack_and_process::<Scalar>(new_proof).unwrap();

        let root_with_old_pointer =
            AllocatedNum::alloc(cs.namespace(|| format!("old_root: {namespace}")), || {
                Ok(old_root)
            })?;

        let root_with_new_pointer =
            AllocatedNum::alloc(cs.namespace(|| format!("new_root: {namespace}")), || {
                Ok(updated_root)
            })?;

        let recalculated_old_root = recalculate_hash_as_scalar::<Scalar>(old_path).unwrap();
        let recalculated_updated_root = recalculate_hash_as_scalar::<Scalar>(updated_path).unwrap();

        let allocated_recalculated_old_root = AllocatedNum::alloc(
            cs.namespace(|| format!("recalculated_old_root: {namespace}")),
            || Ok(recalculated_old_root),
        )?;
        let allocated_recalculated_updated_root = AllocatedNum::alloc(
            cs.namespace(|| format!("recalculated_updated_root: {namespace}")),
            || Ok(recalculated_updated_root),
        )?;

        cs.enforce(
            || format!("old_root update equality: {namespace}"),
            |lc| lc + allocated_recalculated_old_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + root_with_old_pointer.get_variable(),
        );

        cs.enforce(
            || format!("new_root update equality: {namespace}"),
            |lc| lc + allocated_recalculated_updated_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + root_with_new_pointer.get_variable(),
        );

        // is this jank or are we fine?
        Ok(vec![
            allocated_recalculated_old_root,
            allocated_recalculated_updated_root,
        ])
    }
}
