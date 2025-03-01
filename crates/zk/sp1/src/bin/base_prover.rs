#![no_main]
sp1_zkvm::entrypoint!(main);

use prism_tree::proofs::Batch;

/// Base prover - only used for the initial epoch (epoch 0)
/// This binary intentionally does NOT have recursive verification capability
pub fn main() {
    println!("cycle-tracker-start: setup");

    // Read batch input
    let batch = sp1_zkvm::io::read::<Batch>();
    println!("cycle-tracker-end: setup");
    sp1_zkvm::io::commit_slice(&batch.prev_root.0);

    println!("cycle-tracker-start: proof-iteration");
    batch.verify().unwrap();
    println!("cycle-tracker-end: proof-iteration");
    sp1_zkvm::io::commit_slice(&batch.new_root.0);
}
