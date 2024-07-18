use std::time::{Duration, Instant};

use bellman::groth16;
use bls12_381::Bls12;
use deimos::{utils::validate_epoch, zk_snark::BatchMerkleProofCircuit};
use indexed_merkle_tree::{
    node::Node,
    sha256_mod,
    tree::{IndexedMerkleTree, Proof},
};
use rand::rngs::OsRng;

fn generate_test_tree(size: usize, node_count: usize) -> Duration {
    let mut tree = IndexedMerkleTree::new_with_size(size).unwrap();

    let prev_commitment = tree.get_commitment().unwrap();
    let mut proofs = Vec::with_capacity(node_count);
    let mut insertion_times: Vec<Duration> = Vec::with_capacity(node_count);
    for i in 0..node_count {
        let mut leaf = Node::new_leaf(
            true,
            true,
            sha256_mod(&[(i + 1) as u8]),
            sha256_mod(&[i as u8]),
            Node::TAIL,
        );

        let start = Instant::now();
        let proof = tree.insert_node(&mut leaf).unwrap();
        let end = Instant::now();
        insertion_times.push(end.duration_since(start));
        proofs.push(Proof::Insert(proof))
    }
    println!(
        "{}x{} Average Insertion Time: {:?}",
        size,
        node_count,
        insertion_times.iter().sum::<Duration>() / node_count as u32
    );

    let current_commitment = tree.get_commitment().unwrap();

    let start = Instant::now();
    let batched_proof =
        BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs).unwrap();

    let rng = &mut OsRng;
    let params =
        groth16::generate_random_parameters::<Bls12, _, _>(batched_proof.clone(), rng).unwrap();
    let proof = groth16::create_random_proof(batched_proof.clone(), &params, rng).unwrap();
    let end = Instant::now();

    let result = validate_epoch(
        &prev_commitment,
        &current_commitment,
        proof.clone(),
        params.vk,
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), proof);
    end.duration_since(start)
}

#[test]
fn test_prover_time() {
    // add more test cases while benchmarking, obviously
    let test_cases: Vec<(usize, usize)> = vec![(usize::pow(2, 13), 8)];

    for (size, node_count) in test_cases {
        let duration = generate_test_tree(size, node_count);
        println!("{}x{}: Proof Time {:?}", size, node_count, duration)
    }
}
