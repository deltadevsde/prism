use crate::{
    nova::utils::{next_rom_index_and_pc, Digest},
    tree::{Hasher, InsertProof, SPARSE_MERKLE_PLACEHOLDER_HASH},
};
use anyhow::Result;
use arecibo::supernova::StepCircuit;
use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use jmt::proof::{SparseMerkleLeafNode, SparseMerkleNode, SparseMerkleProof};

#[derive(Clone)]
pub struct InsertCircuit<F> {
    pub proof: InsertProof,
    rom_size: usize,
    _phantom: std::marker::PhantomData<F>,
}

impl<Scalar: PrimeField + PrimeFieldBits> InsertCircuit<Scalar> {
    pub fn new(proof: InsertProof, rom_size: usize) -> Self {
        Self {
            proof,
            rom_size,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> StepCircuit<Scalar> for InsertCircuit<Scalar> {
    fn arity(&self) -> usize {
        2 + self.rom_size // old_root + rom_index + rom[].len()
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<Scalar>>,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<(Option<AllocatedNum<Scalar>>, Vec<AllocatedNum<Scalar>>), SynthesisError> {
        let old_root = &z[0];
        let rom_index = &z[1];
        let allocated_rom = &z[2..];

        let pc = pc.ok_or(SynthesisError::AssignmentMissing)?;

        let (rom_index_next, pc_next) = next_rom_index_and_pc(
            &mut cs.namespace(|| "next and rom_index and pc"),
            rom_index,
            allocated_rom,
            pc,
        )?;

        let old_root_bits = allocate_bits_to_binary_number(
            cs,
            Some(self.proof.non_membership_proof.root.to_bytes().to_vec()),
        )?;

        let pre_insertion_scalar = Digest::new(self.proof.non_membership_proof.root)
            .to_scalar()
            .map_err(|_| SynthesisError::Unsatisfiable);
        let pre_insertion_root =
            AllocatedNum::alloc(cs.namespace(|| "pre_insertion_root"), || {
                pre_insertion_scalar
            })?;

        cs.enforce(
            || "z0 == pre_insertion_root",
            |lc| lc + old_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + pre_insertion_root.get_variable(),
        );

        // Allocate the new root
        let new_root = AllocatedNum::alloc(cs.namespace(|| "new_root"), || {
            Digest::new(self.proof.new_root)
                .to_scalar()
                .map_err(|_| SynthesisError::Unsatisfiable)
        })?;

        // Verify the non-membership proof
        // verify_non_membership_proof(
        //     cs.namespace(|| "non_membership_proof"),
        //     &self.proof.non_membership_proof,
        //     &old_root,
        //     &key_bits,
        // )?;

        let leaf = &self
            .proof
            .membership_proof
            .leaf()
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Verify the membership proof (update)
        verify_membership_proof(cs, &self.proof.membership_proof, &old_root_bits, *leaf)?;

        let mut z_next = vec![new_root];
        z_next.push(rom_index_next);
        z_next.extend(z[2..].iter().cloned());

        Ok((Some(pc_next), z_next))
    }

    fn circuit_index(&self) -> usize {
        0
    }
}

fn allocate_bits_to_binary_number<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    value: Option<Vec<u8>>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let bits = value
        .map(|bytes| {
            bytes
                .iter()
                .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![false; 256]);

    let mut result = Vec::new();
    for (i, &bit) in bits.iter().enumerate() {
        let allocated_bit = AllocatedBit::alloc(cs.namespace(|| format!("bit {}", i)), Some(bit))?;
        result.push(Boolean::from(allocated_bit));
    }
    Ok(result)
}

// fn verify_non_membership_proof<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
//     mut cs: CS,
//     proof: &NonMembershipProof,
//     root: &[Boolean],
//     key: &[Boolean],
// ) -> Result<(), SynthesisError> {
//     // 1. Hash the key
//     let key_hash = sha256(cs.namespace(|| "hash key"), key)?;

//     // 2. Traverse the Merkle path

//     // 3. Check that the computed root does not match the given root

//     Ok(())
// }

fn hash_node<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    node: &SparseMerkleNode,
) -> Result<Vec<Boolean>, SynthesisError> {
    match node {
        SparseMerkleNode::Leaf(node) => {
            let node_bits = allocate_bits_to_binary_number(cs, Some(node.to_bytes()))?;
            sha256(cs.namespace(|| "hash key"), &node_bits)
        }
        SparseMerkleNode::Internal(node) => {
            let node_bits = allocate_bits_to_binary_number(cs, Some(node.to_bytes()))?;
            sha256(cs.namespace(|| "hash key"), &node_bits)
        }
        SparseMerkleNode::Null => allocate_bits_to_binary_number(
            cs,
            Some(SPARSE_MERKLE_PLACEHOLDER_HASH.to_bytes().to_vec()),
        ),
    }
}

fn verify_membership_proof<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    proof: &SparseMerkleProof<Hasher>,
    root: &Vec<Boolean>,
    leaf: SparseMerkleLeafNode,
) -> Result<(), SynthesisError> {
    // let leaf = self.proof.membership_proof.leaf().ok_or(SynthesisError::Unsatisfiable)?;
    let mut current = hash_node(cs, &SparseMerkleNode::Leaf(leaf))?;

    for (i, sibling) in proof.siblings().iter().enumerate() {
        let sibling_hash = hash_node(cs, sibling)?;

        current = sha256(
            cs.namespace(|| format!("hash node {}", i)),
            &[current, sibling_hash].concat(),
        )?;
    }

    for (i, (computed_bit, given_bit)) in current.iter().zip(root.iter()).enumerate() {
        Boolean::enforce_equal(
            cs.namespace(|| format!("root bit {} should be equal", i)),
            computed_bit,
            given_bit,
        )?;
    }

    Ok(())
}
