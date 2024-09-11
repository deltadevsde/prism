use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use indexed_merkle_tree::{
    node::Node,
    sha256_mod,
    tree::{IndexedMerkleTree, Proof},
    Hash,
};
use rand::Rng;
use std::time::Duration;

fn create_random_test_hash() -> Hash {
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 32] = rng.gen();
    sha256_mod(&random_bytes)
}

const SIZES: [usize; 3] = [1 << 10, 1 << 11, 1 << 12];
const BATCH_SIZES: [usize; 3] = [32, 64, 128];

fn setup_tree_and_proofs(
    tree_size: usize,
    batch_size: usize,
) -> (IndexedMerkleTree, Vec<Proof>, Hash, Hash) {
    let mut tree = IndexedMerkleTree::new_with_size(tree_size).unwrap();
    let prev_commitment = tree.get_commitment().unwrap();

    let mut proofs = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let mut node = Node::new_leaf(
            true,
            create_random_test_hash(),
            create_random_test_hash(),
            create_random_test_hash(),
        );
        let proof = tree.insert_node(&mut node).unwrap();
        proofs.push(Proof::Insert(proof));
    }

    let current_commitment = tree.get_commitment().unwrap();
    (tree, proofs, prev_commitment, current_commitment)
}

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ZK Proof Generation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.warm_up_time(Duration::from_secs(5));

    for tree_size in SIZES.iter() {
        for batch_size in BATCH_SIZES.iter() {
            group.bench_with_input(
                BenchmarkId::new("tree_size_batch", format!("{}_{}", tree_size, batch_size)),
                &(tree_size, batch_size),
                |b, &(tree_size, batch_size)| {
                    let (_, proofs, prev_commitment, current_commitment) =
                        setup_tree_and_proofs(*tree_size, *batch_size);
                    b.iter(|| {
                        // let circuit = BatchMerkleProofCircuit::new(
                        //     black_box(&prev_commitment),
                        //     black_box(&current_commitment),
                        //     black_box(proofs.clone()),
                        // )
                        // .unwrap();
                        // let _ = circuit.create_and_verify_snark();
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ZK Proof Verification");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.warm_up_time(Duration::from_secs(5));

    for tree_size in SIZES.iter() {
        for batch_size in BATCH_SIZES.iter() {
            group.bench_with_input(
                BenchmarkId::new("tree_size_batch", format!("{}_{}", tree_size, batch_size)),
                &(tree_size, batch_size),
                |b, &(tree_size, batch_size)| {
                    let (_, proofs, prev_commitment, current_commitment) =
                        setup_tree_and_proofs(*tree_size, *batch_size);
                    // let circuit =
                    //     BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs)
                    //         .unwrap();
                    // let (proof, verifying_key) = circuit.create_and_verify_snark().unwrap();
                    b.iter(|| {
                        /* let _ = validate_epoch(
                            black_box(&prev_commitment),
                            black_box(&current_commitment),
                            black_box(proof.clone()),
                            black_box(verifying_key.clone()),
                        ); */
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_proof_generation, bench_proof_verification);
criterion_main!(benches);
