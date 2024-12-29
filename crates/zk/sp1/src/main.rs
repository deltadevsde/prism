#![no_main]
sp1_zkvm::entrypoint!(main);

use prism_common::digest::Digest;
use prism_tree::proofs::{Batch, Proof};

pub fn main() {
    let batch = sp1_zkvm::io::read::<Batch>();
    let mut current = batch.prev_root;
    sp1_zkvm::io::commit_slice(&current.0);

    for proof in batch.proofs.iter() {
        match proof {
            Proof::Update(p) => {
                assert_eq!(current, Digest::new(p.old_root.0));
                assert!(p.verify().is_ok());
                current = Digest::new(p.new_root.0);
            }
            Proof::Insert(p) => {
                assert_eq!(current, Digest::new(p.non_membership_proof.root.0));
                assert!(p.verify().is_ok());
                current = p.new_root;
            }
        }
    }
    sp1_zkvm::io::commit_slice(&current.0);
}
