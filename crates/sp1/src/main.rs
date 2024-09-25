#![no_main]
sp1_zkvm::entrypoint!(main);

use prism_common::tree::{Batch, Digest, Proof};

pub fn main() {
    let batch = sp1_zkvm::io::read::<Batch>();
    let mut current = batch.prev_root;
    sp1_zkvm::io::commit_slice(&current.0);

    for proof in batch.proofs.iter() {
        match proof {
            Proof::Update(p) => {
                assert_eq!(current, Digest::new(p.old_root.into()));
                assert!(p.verify().is_ok());
                current = Digest::new(p.new_root.into());
            }
            Proof::Insert(p) => {
                assert_eq!(current, p.non_membership_proof.root);
                assert!(p.verify().is_ok());
                current = p.new_root;
            }
        }
    }
    sp1_zkvm::io::commit_slice(&current.0);
}
