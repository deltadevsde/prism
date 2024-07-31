use crate::error::{GeneralError, ProofError};
use anyhow::{anyhow, Result};
use bls12_381::Scalar;
use indexed_merkle_tree::{node::Node, sha256_mod, tree::MerkleProof, Hash};

pub fn unpack_and_process(proof: &MerkleProof) -> Result<(Scalar, &Vec<Node>)> {
    if !proof.path.is_empty() {
        let root = hash_to_scalar(&proof.root_hash)?;
        Ok((root, &proof.path))
    } else {
        Err(anyhow!(ProofError::ProofUnpackError(format!(
            "proof path is empty for root hash {}",
            proof.root_hash
        ))))
    }
}

pub fn hash_to_scalar(hash: &Hash) -> Result<Scalar, GeneralError> {
    let mut byte_array = [0u8; 32];
    byte_array.copy_from_slice(hash.as_ref());
    byte_array.reverse();

    // Convert the byte array to an array of four u64 values
    let val = [
        u64::from_le_bytes(<[u8; 8]>::try_from(&byte_array[0..8]).unwrap()),
        u64::from_le_bytes(<[u8; 8]>::try_from(&byte_array[8..16]).unwrap()),
        u64::from_le_bytes(<[u8; 8]>::try_from(&byte_array[16..24]).unwrap()),
        u64::from_le_bytes(<[u8; 8]>::try_from(&byte_array[24..32]).unwrap()),
    ];

    // Use the from_raw method to convert the array to a Scalar
    Ok(Scalar::from_raw(val))
}

pub fn recalculate_hash_as_scalar(path: &[Node]) -> Result<Scalar, GeneralError> {
    let mut current_hash = path[0].get_hash();
    for node in path.iter().skip(1) {
        let combined = if node.is_left_sibling() {
            [node.get_hash().as_ref(), current_hash.as_ref()].concat()
        } else {
            [current_hash.as_ref(), node.get_hash().as_ref()].concat()
        };
        current_hash = sha256_mod(&combined);
    }
    hash_to_scalar(&current_hash)
}
