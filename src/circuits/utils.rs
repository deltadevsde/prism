use crate::tree::{Digest, Hasher, SPARSE_MERKLE_PLACEHOLDER_HASH};
use anyhow::{anyhow, Result};
use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        sha256::sha256,
    },
    ConstraintSystem, SynthesisError,
};
use blstrs::Scalar;
use ff::PrimeField;
use jmt::{
    bytes32ext::Bytes32Ext,
    proof::{SparseMerkleLeafNode, SparseMerkleNode, SparseMerkleProof, INTERNAL_DOMAIN_SEPARATOR},
};

pub fn digest_to_scalar(digest: &Digest) -> Result<Scalar> {
    let ct_option = Scalar::from_bytes_be(digest.as_bytes());
    if ct_option.is_some().into() {
        Ok(ct_option.unwrap())
    } else {
        Err(anyhow!("Invalid scalar"))
    }
}

pub fn allocate_bits_to_binary_number<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    value: Vec<u8>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let bits: Vec<bool> = value
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();

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
            allocate_bits_to_binary_number(cs, SPARSE_MERKLE_PLACEHOLDER_HASH.to_bytes().to_vec())
        }
    }
}

pub fn verify_membership_proof<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    proof: &SparseMerkleProof<Hasher>,
    root: &Vec<Boolean>,
    leaf: SparseMerkleLeafNode,
) -> Result<(), SynthesisError> {
    let mut current = hash_node(cs, &SparseMerkleNode::Leaf(leaf))?;

    let element_key = leaf.key_hash;

    for (i, (sibling, key_bit)) in proof
        .siblings()
        .iter()
        .zip(
            element_key
                .0
                .iter_bits()
                .rev()
                .skip(256 - proof.siblings().len()),
        )
        .enumerate()
    {
        let sibling_hash = hash_node(cs, sibling)?;
        let separator = allocate_bits_to_binary_number(cs, INTERNAL_DOMAIN_SEPARATOR.to_vec())?;

        let mut result = Vec::new();
        if key_bit {
            result.extend_from_slice(&separator);
            result.extend_from_slice(&sibling_hash);
            result.extend_from_slice(&current);
        } else {
            result.extend_from_slice(&separator);
            result.extend_from_slice(&current);
            result.extend_from_slice(&sibling_hash);
        }

        current = sha256(
            cs.namespace(|| format!("hash node {}", i)),
            result.as_slice(),
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

fn boolvec_to_bytes(value: Vec<Boolean>) -> Vec<u8> {
    let bits: Vec<bool> = value
        .iter()
        .map(|b| b.get_value().unwrap_or(false))
        .collect();

    bits.chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0u8, |acc, (i, &bit)| acc | ((bit as u8) << i))
        })
        .collect()
}
