use std::time::{Duration, Instant};

// use deimos::zk_snark::BatchMerkleProofCircuit;
use bellman::groth16;
use bls12_381::Bls12;
use deimos::{
    error::{DeimosError, GeneralError, ProofError},
    storage::{ChainEntry, Operation},
    utils::validate_epoch,
    zk_snark::{hex_to_scalar, BatchMerkleProofCircuit, InsertMerkleProofCircuit},
};
use indexed_merkle_tree::{
    node::{self, Node},
    sha256,
    tree::{IndexedMerkleTree, Proof},
};
use pyroscope::PyroscopeAgent;
use pyroscope_pprofrs::{pprof_backend, PprofConfig};
use rand::rngs::OsRng;

fn generate_test_tree(size: usize, node_count: usize) -> Duration {
    let mut tree = IndexedMerkleTree::new_with_size(size).unwrap();

    let prev_commitment = tree.get_commitment().unwrap();
    let mut proofs = Vec::with_capacity(node_count);
    for i in 0..node_count {
        let leaf = Node::initialize_leaf(
            true,
            true,
            (i + 1).to_string(),
            sha256(&i.to_string()),
            Node::TAIL.to_string(),
        );

        let start = Instant::now();
        let proof = tree.insert_node(&leaf).unwrap();
        if i == 0 {
            let end = Instant::now();
            println!(
                "{}x{} Insertion Time: {:?}",
                size,
                node_count,
                end.duration_since(start)
            )
        }
        proofs.push(Proof::Insert(proof))
    }

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
fn test_validate_epoch_valid_proof() {
    // Configure profiling backend
    let pprof_config = PprofConfig::new().sample_rate(100);
    let backend_impl = pprof_backend(pprof_config);

    // Configure Pyroscope Agent
    let agent = PyroscopeAgent::builder("http://localhost:4040", "deimos")
        .backend(backend_impl)
        .build()
        .unwrap();

    let agent_running = agent.start().unwrap();

    // Constant tree size with growing nodes
    let test_cases: Vec<(usize, usize)> = vec![
        (2 ^ 12, 2 ^ 3),
        (2 ^ 12, 2 ^ 4),
        (2 ^ 12, 2 ^ 5),
        (2 ^ 12, 2 ^ 6),
        (2 ^ 12, 2 ^ 7),
        (2 ^ 12, 2 ^ 8),
        (2 ^ 12, 2 ^ 9),
        (2 ^ 12, 2 ^ 10),
        (2 ^ 12, 2 ^ 11),
    ];

    for (size, node_count) in test_cases {
        let duration = generate_test_tree(size, node_count);
        println!("{}x{}: Proof Time {:?}", size, node_count, duration)
    }

    agent_running.stop().unwrap();
}
