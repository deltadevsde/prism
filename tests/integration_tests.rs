use std::time::{Duration, Instant};

use indexed_merkle_tree::{
    node::Node,
    sha256,
    tree::{IndexedMerkleTree, Proof},
};

fn generate_test_tree(size: usize, node_count: usize) -> Duration {
    let mut tree = IndexedMerkleTree::new_with_size(size).unwrap();
    let (epoch_proof, epoch_verify) = guest::build_proof_epoch();

    let prev_commitment = tree.get_commitment().unwrap();
    let mut proofs = Vec::with_capacity(node_count);
    let mut insertion_times: Vec<Duration> = Vec::with_capacity(node_count);
    for i in 0..node_count {
        let leaf = Node::new_leaf(
            true,
            true,
            sha256((i + 1).to_string()),
            sha256(&i.to_string()),
            Node::TAIL,
        );

        let start = Instant::now();
        let proof = tree.insert_node(&leaf).unwrap();
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

    let proofs = proofs
        .iter()
        .map(|proof| proof.prepare_for_snark())
        .collect();

    let start = Instant::now();
    let (output, proof) = epoch_proof(prev_commitment, current_commitment, proofs);

    let end = Instant::now();

    let result = epoch_verify(proof);

    assert_eq!(result, true);
    assert_eq!(output, true);
    end.duration_since(start)
}

#[test]
fn test_prover_time() {
    let test_cases: Vec<(usize, usize)> = vec![
        (4096, 8),
        (4096, 16),
        (4096, 32),
        (4096, 64),
        (4096, 128),
        (4096, 256),
        (4096, 512),
        (4096, 1024),
        (4096, 2048),
    ];

    for (size, node_count) in test_cases {
        let duration = generate_test_tree(size, node_count);
        println!("{}x{}: Proof Time {:?}", size, node_count, duration)
    }
}
