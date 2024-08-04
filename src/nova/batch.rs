use anyhow::{anyhow, Result};
use bellpepper_core::{
    num::{AllocatedNum, Num},
    ConstraintSystem, SynthesisError,
};
use core::marker::PhantomData;
use ff::PrimeField;
use indexed_merkle_tree::{
    node::{LeafNode, Node},
    sha256_mod,
    tree::{InsertProof, MerkleProof, NonMembershipProof, Proof, UpdateProof},
};
use nova_snark::{
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::circuit::StepCircuit,
};

#[derive(Clone, Debug)]
pub enum UnifiedProofStep {
    /// Update proof step ensures that an existing LeafNode is updated with a new value.
    /// Cares about inputs z[0].
    // TODO: adr-003: Adding authentication circuit with poseidon hash, which is not needed in Verdict but needed here.
    // This is because Verdict assumes the downstream application verifies the hashchain themselves.
    // We need to be able to prove the validity of the hashchain though, since anybody can post an Update operation.
    Update,
    /// InsertStart proof step ensures that a LeafNode to be inserted does not yet exist in the tree.
    /// Cares about inputs z[0].
    InsertStart,
    /// InsertUpdate proof step ensures that:
    /// 1. There exists a LeafNode where existing_node.label < new_node.label < existing_node.next
    /// 2. The existing_node's next pointer is updated to new_node.label.
    /// Cares about inputs z[0] and z[2].
    InsertUpdate,
    /// InsertEnd proof step ensures that the new_node from the last step is added to the tree.
    /// Cares about inputs z[0] and z[1].
    InsertEnd,
}

#[derive(Clone)]
pub struct MerkleProofStepCircuit<Scalar: PrimeField> {
    pub step_type: UnifiedProofStep,
    old_proof: Option<MerkleProof>,
    new_proof: Option<MerkleProof>,

    // Additional fields for non-membership proof
    is_non_membership: bool,
    missing_node: Option<LeafNode>,
    _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField> MerkleProofStepCircuit<Scalar> {
    pub fn new(
        step: UnifiedProofStep,
        old_proof: Option<MerkleProof>,
        new_proof: Option<MerkleProof>,
        is_non_membership: bool,
        missing_node: Option<LeafNode>,
    ) -> Self {
        MerkleProofStepCircuit {
            step_type: step,
            old_proof,
            new_proof,
            is_non_membership,
            missing_node,
            _p: PhantomData,
        }
    }
}

impl<Scalar: PrimeField> MerkleProofStepCircuit<Scalar> {
    pub fn from_proof(proof: Proof) -> Vec<Self> {
        match proof {
            Proof::Insert(insert_proof) => {
                vec![
                    Self::new(
                        UnifiedProofStep::InsertStart,
                        Some(insert_proof.non_membership_proof.merkle_proof.clone()),
                        None,
                        true,
                        Some(insert_proof.non_membership_proof.missing_node.clone()),
                    ),
                    Self::new(
                        UnifiedProofStep::InsertUpdate,
                        Some(insert_proof.first_proof.old_proof),
                        Some(insert_proof.first_proof.new_proof),
                        false,
                        Some(insert_proof.non_membership_proof.missing_node),
                    ),
                    Self::new(
                        UnifiedProofStep::InsertEnd,
                        Some(insert_proof.second_proof.old_proof),
                        Some(insert_proof.second_proof.new_proof),
                        false,
                        None,
                    ),
                ]
            }
            Proof::Update(update_proof) => {
                vec![Self::new(
                    UnifiedProofStep::Update,
                    Some(update_proof.old_proof),
                    Some(update_proof.new_proof),
                    false,
                    None,
                )]
            }
        }
    }
}

// TODO: these are just here temporarily as I write the circuits, they need to be moved to where the circuit gets instantiated later //////////////////////

pub struct Hash<Scalar: PrimeField> {
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
        3
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        println!("Step: {:?}", self.step_type);
        println!(
            "Input z: {:?}",
            z.iter().map(|num| num.get_value()).collect::<Vec<_>>()
        );

        let previous_root_input = &z[0];
        let existing_node_label_input = &z[1];
        let missing_node_label_input = &z[2];

        let old_proof = self
            .old_proof
            .as_ref()
            .ok_or(SynthesisError::Unsatisfiable)?;

        let mut new_proof: Option<&MerkleProof> = None;
        if !self.is_non_membership {
            new_proof = Some(
                self.new_proof
                    .as_ref()
                    .expect("New proof is missing for non-membership proof."),
            );
        }

        let previous_root_alloc = AllocatedNum::alloc(cs.namespace(|| "old root"), || {
            Ok(Hash::new(old_proof.root_hash).to_scalar().unwrap())
        })
        .unwrap();

        cs.enforce(
            || "z_0 == old_root",
            |lc| lc + previous_root_input.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + previous_root_alloc.get_variable(),
        );

        let mut z_out: Vec<AllocatedNum<Scalar>> = Vec::new();

        match self.step_type {
            UnifiedProofStep::Update => {
                let new_proof = new_proof.ok_or(SynthesisError::Unsatisfiable)?;
                let vars = self.process_update(cs, old_proof, new_proof)?;
                let updated_root = vars[1].clone();
                z_out.extend_from_slice(&[
                    updated_root,
                    existing_node_label_input.clone(),
                    missing_node_label_input.clone(),
                ]);
            }
            UnifiedProofStep::InsertStart => {
                let (non_membership_root, non_membership_path) =
                    unpack_and_process::<Scalar>(old_proof)
                        .map_err(|_| SynthesisError::Unsatisfiable)?;

                let new_leaf = self
                    .missing_node
                    .as_ref()
                    .ok_or(SynthesisError::Unsatisfiable)?;

                let existing_leaf = non_membership_path
                    .first()
                    .ok_or(SynthesisError::Unsatisfiable)?;
                let existing_leaf_label: Scalar = Hash::new(existing_leaf.get_label())
                    .to_scalar()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;
                let new_leaf_label: Scalar = Hash::new(new_leaf.label)
                    .to_scalar()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;

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

                cs.enforce(
                    || "pre_insertion_root_verification",
                    |lc| lc + allocated_pre_insertion_root.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + allocated_recalculated_root.get_variable(),
                );

                let z1 = AllocatedNum::alloc(cs.namespace(|| "z1"), || Ok(existing_leaf_label))?;
                let z2 = AllocatedNum::alloc(cs.namespace(|| "z2"), || Ok(new_leaf_label))?;
                z_out.extend_from_slice(&[allocated_pre_insertion_root, z1, z2]);
            }
            UnifiedProofStep::InsertUpdate => {
                let new_proof = new_proof.ok_or(SynthesisError::Unsatisfiable)?;

                let vars = self.process_update(cs, old_proof, new_proof)?;
                let updated_root = vars[1].clone();

                z_out.extend_from_slice(&[
                    updated_root,
                    existing_node_label_input.clone(),
                    missing_node_label_input.clone(),
                ]);
            }
            UnifiedProofStep::InsertEnd => {
                let new_proof = new_proof.ok_or(SynthesisError::Unsatisfiable)?;

                let vars = self.process_update(cs, old_proof, new_proof)?;
                let updated_root = vars[1].clone();
                z_out.extend_from_slice(&[
                    updated_root,
                    existing_node_label_input.clone(),
                    missing_node_label_input.clone(),
                ]);
            }
        }

        println!(
            "Output z_out: {:?}",
            z_out.iter().map(|num| num.get_value()).collect::<Vec<_>>()
        );
        Ok(z_out)
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
