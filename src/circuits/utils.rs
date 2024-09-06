use crate::error::ProofError;
use anyhow::{anyhow, Result};
use blstrs::Scalar;
use ff::PrimeField;
use indexed_merkle_tree::{node::Node, sha256_mod, tree::MerkleProof};
use jmt::RootHash;

pub fn unpack_and_process(proof: &MerkleProof) -> Result<(Scalar, &Vec<Node>)> {
    if !proof.path.is_empty() {
        let root: Scalar = proof.root_hash.try_into()?;
        Ok((root, &proof.path))
    } else {
        Err(anyhow!(ProofError::ProofUnpackError(format!(
            "proof path is empty for root hash {}",
            proof.root_hash
        ))))
    }
}

pub fn recalculate_hash_as_scalar(path: &[Node]) -> Result<Scalar> {
    let mut current_hash = path[0].get_hash();
    for node in path.iter().skip(1) {
        let combined = if node.is_left_sibling() {
            [node.get_hash().as_ref(), current_hash.as_ref()].concat()
        } else {
            [current_hash.as_ref(), node.get_hash().as_ref()].concat()
        };
        current_hash = sha256_mod(&combined);
    }
    current_hash.try_into()
}

pub fn hash_to_scalar<F: PrimeField>(hash: &RootHash) -> Scalar {
    Scalar::from_bytes(&hash.0)
}
