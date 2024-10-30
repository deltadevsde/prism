// use bellpepper_core::ConstraintSystem;
use crate::batch::{EpochCircuit, EpochCircuitSequence};
use anyhow::Result;
use arecibo::{provider::PallasEngine, supernova::PublicParams, traits::snark::default_ck_hint};
use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;
use itertools::Itertools as _;
use jmt::{
    bytes32ext::Bytes32Ext,
    proof::{SparseMerkleLeafNode, SparseMerkleNode, SparseMerkleProof, INTERNAL_DOMAIN_SEPARATOR},
    RootHash,
};
use prism_common::{test_utils::TestTreeState, tree::*};
use std::marker::PhantomData;

use prism_common::tree;

pub struct Digest<Scalar: PrimeField> {
    digest: tree::Digest,
    _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField> Digest<Scalar> {
    pub fn new(digest: tree::Digest) -> Self {
        Self {
            digest,
            _p: PhantomData,
        }
    }

    pub fn from_root_hash(root_hash: RootHash) -> Self {
        Self::new(root_hash.into())
    }

    // uses [`PrimeField::from_u128`] for inspiration. If the field element's capacity is not enough to hold the hash,
    pub fn to_scalar(&self) -> Result<Scalar> {
        let bytes = self.digest.as_ref();

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

pub fn next_rom_index_and_pc<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    rom_index: &AllocatedNum<F>,
    allocated_rom: &[AllocatedNum<F>],
    pc: &AllocatedNum<F>,
) -> Result<(AllocatedNum<F>, AllocatedNum<F>), SynthesisError> {
    // Compute a selector for the current rom_index in allocated_rom
    let current_rom_selector = get_selector_vec_from_index(
        cs.namespace(|| "rom selector"),
        rom_index,
        allocated_rom.len(),
    )?;

    // Enforce that allocated_rom[rom_index] = pc
    for (rom, bit) in allocated_rom.iter().zip_eq(current_rom_selector.iter()) {
        // if bit = 1, then rom = pc
        // bit * (rom - pc) = 0
        cs.enforce(
            || "enforce bit = 1 => rom = pc",
            |lc| lc + &bit.lc(CS::one(), F::ONE),
            |lc| lc + rom.get_variable() - pc.get_variable(),
            |lc| lc,
        );
    }

    // Get the index of the current rom, or the index of the invalid rom if no match
    let current_rom_index = current_rom_selector
        .iter()
        .position(|bit| bit.get_value().is_some_and(|v| v))
        .unwrap_or_default();
    let next_rom_index = current_rom_index + 1;

    let rom_index_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next rom index"), || {
        F::from(next_rom_index as u64)
    });
    cs.enforce(
        || " rom_index + 1 - next_rom_index_num = 0",
        |lc| lc,
        |lc| lc,
        |lc| lc + rom_index.get_variable() + CS::one() - rom_index_next.get_variable(),
    );

    // Allocate the next pc without checking.
    // The next iteration will check whether the next pc is valid.
    let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next pc"), || {
        allocated_rom.get(next_rom_index).and_then(|v| v.get_value()).unwrap_or(-F::ONE)
    });

    Ok((rom_index_next, pc_next))
}

/// Compute a selector vector `s` of size `num_indices`, such that
/// `s[i] == 1` if i == `target_index` and 0 otherwise.
pub fn get_selector_vec_from_index<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    target_index: &AllocatedNum<F>,
    num_indices: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
    assert_ne!(num_indices, 0);

    // Compute the selector vector non-deterministically
    let selector = (0..num_indices)
        .map(|idx| {
            // b <- idx == target_index
            Ok(Boolean::Is(AllocatedBit::alloc(
                cs.namespace(|| format!("allocate s_{:?}", idx)),
                target_index.get_value().map(|v| v == F::from(idx as u64)),
            )?))
        })
        .collect::<Result<Vec<Boolean>, SynthesisError>>()?;

    // Enforce ∑ selector[i] = 1
    {
        let selected_sum = selector.iter().fold(LinearCombination::zero(), |lc, bit| {
            lc + &bit.lc(CS::one(), F::ONE)
        });
        cs.enforce(
            || "exactly-one-selection",
            |_| selected_sum,
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }

    // Enforce `target_index - ∑ i * selector[i] = 0``
    {
        let selected_value =
            selector.iter().enumerate().fold(LinearCombination::zero(), |lc, (i, bit)| {
                lc + &bit.lc(CS::one(), F::from(i as u64))
            });
        cs.enforce(
            || "target_index - ∑ i * selector[i] = 0",
            |lc| lc,
            |lc| lc,
            |lc| lc + target_index.get_variable() - &selected_value,
        );
    }

    Ok(selector)
}

pub fn create_pp() -> PublicParams<PallasEngine> {
    type E1 = PallasEngine;

    let mut test_tree = TestTreeState::default();

    let service = test_tree.register_service("service_1".to_string());
    let mut account = test_tree.create_account("publicparams".to_string(), service.clone());

    test_tree
        .tree
        .insert(
            service.registration.key_hash,
            service.registration.hashchain.clone(),
        )
        .unwrap();

    let insert_proof = test_tree.tree.insert(account.key_hash, account.hashchain.clone()).unwrap();

    test_tree.add_key_to_account(&mut account).unwrap();

    let update_proof = test_tree.update_account(account).unwrap();

    let operations = vec![
        (0, EpochCircuit::new_insert(insert_proof, 2)),
        (1, EpochCircuit::new_update(update_proof, 2)),
    ];

    let circuit_sequence = EpochCircuitSequence::<E1>::new(operations);
    PublicParams::setup(&circuit_sequence, &*default_ck_hint(), &*default_ck_hint())
}

pub fn allocate_bits_to_binary_number<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    value: Vec<u8>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let bits: Vec<bool> =
        value.iter().flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1)).collect();

    let result: Result<Vec<Boolean>, SynthesisError> = bits
        .into_iter()
        .enumerate()
        .map(|(i, bit)| {
            let allocated_bit =
                AllocatedBit::alloc(cs.namespace(|| format!("bit {}", i)), Some(bit))?;
            Ok(Boolean::from(allocated_bit))
        })
        .collect();

    result
}

pub fn hash_node<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    node: &SparseMerkleNode,
) -> Result<Vec<Boolean>, SynthesisError> {
    match node {
        SparseMerkleNode::Leaf(node) => {
            let node_bits = allocate_bits_to_binary_number(cs, node.to_bytes())?;
            sha256(cs.namespace(|| "hash key"), &node_bits)
        }
        SparseMerkleNode::Internal(node) => {
            let node_bits = allocate_bits_to_binary_number(cs, node.to_bytes())?;
            sha256(cs.namespace(|| "hash key"), &node_bits)
        }
        SparseMerkleNode::Null => {
            let node_bits = allocate_bits_to_binary_number(
                cs,
                SPARSE_MERKLE_PLACEHOLDER_HASH.to_bytes().to_vec(),
            )?;
            sha256(
                cs.namespace(|| "placeholder"),
                &[node_bits.clone(), node_bits.clone(), node_bits.clone()].concat(),
            )?;
            Ok(node_bits)
        }
    }
}

// pub fn verify_membership_proof<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
//     cs: &mut CS,
//     proof: &SparseMerkleProof<Hasher>,
//     root: &Vec<Boolean>,
//     leaf: SparseMerkleLeafNode,
// ) -> Result<(), SynthesisError> {
//     dbg!(proof);
//     let mut current = hash_node(cs, &SparseMerkleNode::Leaf(leaf))?;

//     let element_key = leaf.key_hash;

//     for (i, (sibling, key_bit)) in proof
//         .siblings()
//         .iter()
//         .zip(
//             element_key
//                 .0
//                 .iter_bits()
//                 .rev()
//                 .skip(256 - proof.siblings().len()),
//         )
//         .enumerate()
//     {
//         let sibling_hash = hash_node(cs, sibling)?;
//         let separator = allocate_bits_to_binary_number(cs, INTERNAL_DOMAIN_SEPARATOR.to_vec())?;

//         let mut result = Vec::new();
//         if key_bit {
//             result.extend_from_slice(&separator);
//             result.extend_from_slice(&sibling_hash);
//             result.extend_from_slice(&current);
//         } else {
//             result.extend_from_slice(&separator);
//             result.extend_from_slice(&current);
//             result.extend_from_slice(&sibling_hash);
//         }

//         current = sha256(
//             cs.namespace(|| format!("hash node {}", i)),
//             result.as_slice(),
//         )?;
//     }

//     for (i, (computed_bit, given_bit)) in current.iter().zip(root.iter()).enumerate() {
//         Boolean::enforce_equal(
//             cs.namespace(|| format!("root bit {} should be equal", i)),
//             computed_bit,
//             given_bit,
//         )?;
//     }

//     Ok(())
// }

pub fn verify_membership_proof<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    proof: &SparseMerkleProof<Hasher>,
    root: Vec<Boolean>,
    leaf: SparseMerkleLeafNode,
) -> Result<(), SynthesisError> {
    let max_depth = 10;
    let actual_depth = proof.siblings().len();

    let mut current = hash_node(cs, &SparseMerkleNode::Leaf(leaf))?;
    let element_key = leaf.key_hash;

    for i in 0..max_depth {
        let cs = &mut cs.namespace(|| format!("proof step {}", i));

        // Allocate sibling hash (use placeholder if beyond actual proof depth)
        let sibling_hash = if i < actual_depth {
            hash_node(cs, &proof.siblings()[i])?
        } else {
            let bits = allocate_bits_to_binary_number(
                cs,
                SPARSE_MERKLE_PLACEHOLDER_HASH.to_bytes().to_vec(),
            )?;
            sha256(
                cs.namespace(|| "placeholder"),
                &[bits.clone(), bits.clone(), bits.clone()].concat(),
            )?;
            bits
        };

        // Get the key bit
        let key_bit = if i < actual_depth {
            element_key.0.iter_bits().rev().nth(255 - i).unwrap()
        } else {
            false
        };

        let separator = allocate_bits_to_binary_number(cs, INTERNAL_DOMAIN_SEPARATOR.to_vec())?;

        let mut hash_input = Vec::new();
        if key_bit {
            hash_input.extend_from_slice(&separator);
            hash_input.extend_from_slice(&sibling_hash);
            hash_input.extend_from_slice(&current);
        } else {
            hash_input.extend_from_slice(&separator);
            hash_input.extend_from_slice(&current);
            hash_input.extend_from_slice(&sibling_hash);
        }

        let hashed = sha256(cs.namespace(|| "hash node"), &hash_input)?;

        if i < actual_depth {
            current = hashed;
        }
    }

    // Final equality check
    for (i, (computed_bit, given_bit)) in current.iter().zip(root.iter()).enumerate() {
        Boolean::enforce_equal(
            cs.namespace(|| format!("root bit {} should be equal", i)),
            computed_bit,
            given_bit,
        )?;
    }

    Ok(())
}

/// Helper function to conditionally swap two vectors of Booleans
#[allow(dead_code)]
fn conditionally_swap<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    a: &[Boolean],
    b: &[Boolean],
    condition: &Boolean,
) -> Result<(Vec<Boolean>, Vec<Boolean>), SynthesisError> {
    let mut left = Vec::with_capacity(a.len());
    let mut right = Vec::with_capacity(a.len());

    for (a_bit, b_bit) in a.iter().zip(b.iter()) {
        let (left_bit, right_bit) = {
            let and1 = Boolean::and(cs.namespace(|| "condition and a"), condition, a_bit)?;
            let and2 = Boolean::and(
                cs.namespace(|| "not condition a and b"),
                &condition.not(),
                b_bit,
            )?;

            let left = Boolean::xor(cs.namespace(|| "left xor"), &and1, &and2)?;

            let and3 = Boolean::and(cs.namespace(|| "condition and b"), condition, b_bit)?;
            let and4 = Boolean::and(
                cs.namespace(|| "not condition and a"),
                &condition.not(),
                a_bit,
            )?;
            let right = Boolean::xor(cs.namespace(|| "right xor"), &and3, &and4)?;

            (left, right)
        };

        left.push(left_bit);
        right.push(right_bit);
    }

    Ok((left, right))
}

/// Helper function to conditionally select between two vectors of Booleans
#[allow(dead_code)]
fn conditionally_select_vector<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    condition: &Boolean,
    a: &[Boolean],
    b: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    assert_eq!(a.len(), b.len());
    let mut result = Vec::with_capacity(a.len());

    for (i, (a_bit, b_bit)) in a.iter().zip(b.iter()).enumerate() {
        let cs = &mut cs.namespace(|| format!("select bit {}", i));
        let and1 = Boolean::and(cs.namespace(|| "condition and a"), condition, a_bit)?;
        let and2 = Boolean::and(
            cs.namespace(|| "not condition and b"),
            &Boolean::not(condition),
            b_bit,
        )?;

        let selected_bit = Boolean::xor(cs.namespace(|| "xor"), &and1, &and2)?;

        result.push(selected_bit);
    }

    Ok(result)
}

#[allow(dead_code)]
fn boolvec_to_bytes(value: Vec<Boolean>) -> Vec<u8> {
    let bits: Vec<bool> = value.iter().map(|b| b.get_value().unwrap_or(false)).collect();

    bits.chunks(8)
        .map(|chunk| chunk.iter().enumerate().fold(0u8, |acc, (i, &bit)| acc | ((bit as u8) << i)))
        .collect()
}
