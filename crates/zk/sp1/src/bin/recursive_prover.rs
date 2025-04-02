#![no_main]
sp1_zkvm::entrypoint!(main);

use prism_tree::proofs::Batch;
use sha2::{Digest, Sha256};

/// Recursive prover - used for all epochs after the initial epoch
/// This binary ALWAYS performs recursive verification, with no option to skip it
pub fn main() {
    println!("cycle-tracker-start: setup");

    // ALWAYS verify the previous proof - no conditional logic
    println!("recursive verification");
    let pv_vec = sp1_zkvm::io::read_vec();
    let pv_digest = Sha256::digest(pv_vec);
    let vk_digest = sp1_zkvm::io::read::<[u32; 8]>();

    sp1_zkvm::lib::verify::verify_sp1_proof(&vk_digest, &pv_digest.into());

    println!("recursive verification succeeded");

    // Process the current batch
    let batch = sp1_zkvm::io::read::<Batch>();
    println!("cycle-tracker-end: setup");
    sp1_zkvm::io::commit_slice(&batch.prev_root.0);

    println!("cycle-tracker-start: proof-iteration");
    batch.verify().unwrap();
    println!("cycle-tracker-end: proof-iteration");
    sp1_zkvm::io::commit_slice(&batch.new_root.0);
}
