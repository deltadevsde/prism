#![no_main]
sp1_zkvm::entrypoint!(main);

use prism_common::tree::{Batch, Digest, Proof};

pub fn main() {
    println!("cycle-tracker-start: setup");
    let batch = sp1_zkvm::io::read::<Batch>();
    let mut current = batch.prev_root;
    sp1_zkvm::io::commit_slice(&current.to_bytes());

    println!("cycle-tracker-end: setup");

    println!("cycle-tracker-start: proof-iteration");
    for proof in batch.proofs.iter() {
        match proof {
            Proof::Update(p) => {
                assert_eq!(current, Digest::new(p.old_root.into()));
                println!("cycle-tracker-start: update");
                assert!(p.verify().is_ok());
                println!("cycle-tracker-end: update");
                current = Digest::new(p.new_root.into());
            }
            Proof::Insert(p) => {
                assert_eq!(current, p.non_membership_proof.root);
                println!("cycle-tracker-start: insert");
                assert!(p.verify().is_ok());
                println!("cycle-tracker-end: insert");
                current = p.new_root;
            }
        }
    }
    println!("cycle-tracker-end: proof-iteration");

    sp1_zkvm::io::commit_slice(&current.to_bytes());
}
