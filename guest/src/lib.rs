#![cfg_attr(feature = "guest", no_std)]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use heapless::Vec as HVec;

use indexed_merkle_tree::{
    node::Node,
    tree::{
        ZkInsertProof, ZkMerkleProof, ZkNonMembershipProof as NonMembershipProof, ZkProof as Proof,
        ZkUpdateProof as UpdateProof,
    },
};
use sha2::{Digest, Sha256};

#[jolt::provable]
fn fib(n: u32) -> u128 {
    let mut a: u128 = 0;
    let mut b: u128 = 1;
    let mut sum: u128;
    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }
    b
}

#[jolt::provable]
fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    Into::<[u8; 32]>::into(result)
}

#[jolt::provable]
fn recalculate_merkle_tree(merkle_root: ZkMerkleProof) -> bool {
    let mut current_hash = merkle_root.path[0];

    for i in 1..merkle_root.path.len() {
        let mut heapless_string: HVec<u8, 64> = HVec::new();
        let sibling = merkle_root.path[i];

        /* if sibling.is_left_sibling() { */
        heapless_string
            .extend_from_slice(&sibling)
            .expect("heapless string is the problem");
        heapless_string
            .extend_from_slice(&current_hash)
            .expect("heapless string is the problem");
        /* } else {
            heapless_string
                .extend_from_slice(&current_hash)
                .expect("heapless string is the problem");
            heapless_string
                .extend_from_slice(&sibling_hash)
                .expect("heapless string is the problem");
        } */
        let new_hash = sha256(&heapless_string);
        current_hash = new_hash;
    }

    current_hash == merkle_root.root_hash
}

#[jolt::provable]
fn proof_of_non_membership(proof: NonMembershipProof) -> bool {
    let merkle_proof = proof.merkle_proof;
    let not_included_node = proof.missing_node;

    let node_to_verify = proof.node_to_prove;

    node_to_verify.label < not_included_node
        && not_included_node < node_to_verify.next
        && recalculate_merkle_tree(merkle_proof)
}

#[jolt::provable]
fn proof_of_update(proof: UpdateProof) -> bool {
    /* let old_leaf = match proof.old_proof.path[0].clone() {
        Node::Leaf(leaf) => leaf,
        _ => return false,
    };
    let updated_leaf = match proof.new_proof.path[0].clone() {
        Node::Leaf(leaf) => leaf,
        _ => return false,
    }; */
    // to make sure that there are not only two independet valid merkle proofs but also that the old leaf is the same as the updated leaf
    // because the label should be the same, if the old leaf wasnt acitve, the update operation is the "second update proof" of the insert operation
    // and the label of the old leaf is the empty string, dann muss aber irgendein nachbar auf das label des neuen leafs zeigen.
    // buuuut: its not always the direct neighbor that points to the new leaf, so this is not a valid check ... hmmm we have to figure it out
    /* (old_leaf.label == updated_leaf.label || !old_leaf.active) &&*/
    recalculate_merkle_tree(proof.old_proof) && recalculate_merkle_tree(proof.new_proof)
}

#[jolt::provable]
fn proof_of_insert(proof: ZkInsertProof) -> bool {
    proof_of_non_membership(proof.non_membership_proof)
        && proof_of_update(proof.first_proof)
        && proof_of_update(proof.second_proof)
}

#[jolt::provable]
fn proof_epoch(old_commitment: [u8; 32], new_commitment: [u8; 32], proofs: Vec<Proof>) -> bool {
    if proofs.is_empty() || old_commitment != new_commitment {
        return false;
    }

    fn extract_first_root(proof_variant: Proof) -> [u8; 32] {
        match proof_variant {
            Proof::Update(proof) => proof.old_proof.root_hash,
            Proof::Insert(proof) => proof.non_membership_proof.merkle_proof.root_hash,
        }
    }
    fn extract_last_root(proof_variant: Proof) -> [u8; 32] {
        match proof_variant {
            Proof::Update(proof) => proof.new_proof.root_hash,
            Proof::Insert(proof) => proof.second_proof.new_proof.root_hash,
        }
    }

    let first_root = extract_first_root(proofs[0].clone());
    let last_root = extract_last_root(proofs[proofs.len() - 1].clone());

    if old_commitment != first_root || new_commitment != last_root {
        return false;
    }

    for proof in proofs {
        let result = match proof {
            Proof::Update(proof) => proof_of_update(proof),
            Proof::Insert(proof) => proof_of_insert(proof),
        };

        if !result {
            return false;
        }
    }
    true
}
