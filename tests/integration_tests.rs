mod common;
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
    tree::{IndexedMerkleTree, ProofVariant},
};
use pyroscope::PyroscopeAgent;
use pyroscope_pprofrs::{pprof_backend, PprofConfig};
use rand::rngs::OsRng;

fn generate_test_tree(size: usize, node_count: usize) -> Duration {
    // let start = Instant::now();
    // 2^20
    let mut tree = IndexedMerkleTree::new_with_size(size).unwrap();
    // let end = Instant::now();
    // println!("Tree created in {:?}.", end.duration_since(start));

    let prev_commitment = tree.get_commitment().unwrap();
    // println!("Inserting nodes");
    let mut proofs = Vec::with_capacity(node_count);
    for i in 0..node_count {
        let leaf = Node::initialize_leaf(
            true,
            true,
            (i + 1).to_string(),
            "Ford".to_string(), // sha256(&i.to_string()),
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
        proofs.push(ProofVariant::Insert(proof))
    }
    // println!("Done inserting nodes");

    let current_commitment = tree.get_commitment().unwrap();

    let start = Instant::now();
    // println!("Creating zk proof");
    let batched_proof =
        BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs).unwrap();

    let rng = &mut OsRng;
    let params =
        groth16::generate_random_parameters::<Bls12, _, _>(batched_proof.clone(), rng).unwrap();
    let proof = groth16::create_random_proof(batched_proof.clone(), &params, rng).unwrap();
    let end = Instant::now();
    // println!("Proof created in {:?}.", end.duration_since(start));

    // let start = Instant::now();
    // println!("Validating epoch");
    let result = validate_epoch(
        &prev_commitment,
        &current_commitment,
        proof.clone(),
        params.vk,
    );
    // let end = Instant::now();
    // println!("Epoch validated in {:?}.", end.duration_since(start));
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

    let test_cases: Vec<(usize, usize)> = vec![
        // (512, 511),
        // (1024, 512),
        // (2048, 512),
        // (4096, 512),
        // (8192, 512),
        // (16384, 512),
        // (32768, 512),
        // (65536, 512),
        // (2^17, 512),
        // (2^18, 512),
        // (32768, 512),
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

    agent_running.stop().unwrap();
}
