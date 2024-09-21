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

                // todo: @sebastian fix error handling
                if let Some(new_entry) = p.new_value.last() {
                    let message =
                        bincode::serialize(&new_entry.operation.without_signature()).unwrap();
                    let signature_bundle = new_entry.operation.get_signature_bundle().unwrap();

                    let public_key = p
                        .new_value
                        .get_key_at_index(
                            new_entry.operation.get_signature_bundle().unwrap().key_idx as usize,
                        )
                        .unwrap();

                    p.new_value
                        .verify_signature(&public_key, &message, &signature_bundle.signature)
                        .unwrap();
                }

                current = Digest::new(p.new_root.into());
            }
            Proof::Insert(p) => {
                assert_eq!(current, p.non_membership_proof.root);
                println!("cycle-tracker-start: insert");
                assert!(p.verify().is_ok());

                /* if let Some(new_entry) = p.value.last() {
                    let message =
                        bincode::serialize(&new_entry.operation.without_signature()).unwrap();
                    let signature_bundle = new_entry.operation.get_signature_bundle().unwrap();
                    let public_key = new_entry.operation.get_public_key().unwrap();
                    p.value
                        .verify_signature(&public_key, &message, &signature_bundle.signature)
                        .unwrap()
                } */

                println!("cycle-tracker-end: insert");
                current = p.new_root;
            }
        }
    }
    println!("cycle-tracker-end: proof-iteration");

    sp1_zkvm::io::commit_slice(&current.to_bytes());
}
