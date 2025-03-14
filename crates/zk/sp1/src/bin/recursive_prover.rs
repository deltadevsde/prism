#![no_main]
sp1_zkvm::entrypoint!(main);

use prism_tree::proofs::Batch;
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};

/// Recursive prover - used for all epochs after the initial epoch
/// This binary ALWAYS performs recursive verification, with no option to skip it
pub fn main() {
    println!("cycle-tracker-start: setup");

    // ALWAYS verify the previous proof - no conditional logic
    println!("recursive verification");
    let proof = sp1_zkvm::io::read_vec();
    let public_values = sp1_zkvm::io::read_vec();
    let vkey_hash = sp1_zkvm::io::read::<String>();

    // Verification is mandatory - will panic if it fails
    let result = Groth16Verifier::verify(&proof, &public_values, &vkey_hash, &GROTH16_VK_BYTES);
    if result.is_err() {
        panic!("recursive verification failed");
    }
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
