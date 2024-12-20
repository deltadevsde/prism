#![no_main]
sp1_zkvm::entrypoint!(main);

use prism_tree::proofs::Batch;

pub fn main() {
    let batch = sp1_zkvm::io::read::<Batch>();
    sp1_zkvm::io::commit_slice(&batch.prev_root.0);
    batch.verify().unwrap();
    sp1_zkvm::io::commit_slice(&batch.new_root.0);
}
