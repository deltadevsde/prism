use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use prism_common::test_transaction_builder::TestTransactionBuilder;
use prism_keys::{CryptoAlgorithm, SigningKey};
use prism_tree::proofs::Batch;
use sp1_sdk::{
    CpuProver, HashableKey as _, Prover as _, ProverClient, SP1Proof, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use std::time::Duration;

// Path to ELF binary - single binary with a boolean flag for recursion
const PRISM_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

// Generate a sample batch with transactions for benchmarking
fn generate_test_batch(transaction_count: usize) -> Batch {
    let mut tx_builder = TestTransactionBuilder::new();
    let algorithm = CryptoAlgorithm::Ed25519;

    // Register service
    let service_tx =
        tx_builder.register_service_with_random_keys(algorithm, "test_service").commit();

    // Create initial accounts
    let mut transactions = vec![service_tx];

    // Add transactions based on the count
    for i in 0..transaction_count {
        let account_id = format!("user_{}", i);
        let account_tx = tx_builder
            .create_account_with_random_key_signed(algorithm, &account_id, "test_service")
            .commit();

        transactions.push(account_tx);

        // Add a key to make the batch more realistic
        if i % 2 == 0 {
            let key_tx =
                tx_builder.add_random_key_verified_with_root(algorithm, &account_id).commit();
            transactions.push(key_tx);
        }

        // Add data to make the batch more realistic
        if i % 3 == 0 {
            let data_tx = tx_builder
                .add_internally_signed_data_verified_with_root(
                    &account_id,
                    format!("test data for user {}", i).into_bytes(),
                )
                .commit();
            transactions.push(data_tx);
        }
    }

    // Create and return the batch
    let prev_root = tx_builder
        .get_account("test_service")
        .unwrap()
        .process_transaction(&transactions[0])
        .unwrap();
    let new_root = prev_root.clone();

    // Note: In a real scenario, we would process all transactions to get the correct
    // prev_root and new_root values, but for benchmarking purposes this is sufficient
    Batch::init(prev_root, new_root, vec![])
}

// Approach 1: Generate Groth16 proof and verify it inside the zkVM program
fn bench_groth16_verify_inside_zkvm(
    batch: &Batch,
    previous_proof: Option<(Vec<u8>, Vec<u8>, String)>,
) -> SP1ProofWithPublicValues {
    let client = ProverClient::builder().cpu().build();
    let (pk, _) = client.setup(PRISM_ELF);

    let mut stdin = SP1Stdin::new();

    // Indicate if we're including a previous proof for verification
    stdin.write(&previous_proof.is_some());

    // If we have a previous proof, write it to the stdin
    if let Some((proof, public_values, vkey_hash)) = previous_proof {
        stdin.write_vec(proof);
        stdin.write_vec(public_values);
        stdin.write(&vkey_hash);
    }

    // Write the batch last
    stdin.write(batch);

    // Generate the Groth16 proof
    client.prove(&pk, &stdin).groth16().run().unwrap()
}

// Approach 2: Generate a compressed proof first, then a separate Groth16 proof for light client verification
fn bench_separate_compressed_and_groth16(
    batch: &Batch,
) -> (SP1ProofWithPublicValues, SP1ProofWithPublicValues) {
    let client = ProverClient::builder().cpu().build();
    let (pk, vk) = client.setup(PRISM_ELF);

    let mut stdin = SP1Stdin::new();

    // For base proof, set has_previous_proof to false
    stdin.write(&false);
    stdin.write(batch);

    // First generate the compressed proof
    let compressed_proof = client.prove(&pk, &stdin).compressed().run().unwrap();

    // Now create a separate Groth16 proof for light client verification
    // This doesn't run in the zkVM, it's just a wrapper for the compressed proof
    let groth16_proof = client.prove(&pk, &stdin).groth16().run().unwrap();

    (compressed_proof, groth16_proof)
}

// Verification benchmarks
fn bench_verify_groth16_proof(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) -> bool {
    let client = ProverClient::builder().cpu().build();
    client.verify(proof, vk).is_ok()
}

// Verify using the Groth16Verifier directly (simulating what happens inside the zkVM)
fn bench_verify_with_groth16_verifier(proof: &[u8], public_values: &[u8], vkey_hash: &str) -> bool {
    Groth16Verifier::verify(proof, public_values, vkey_hash, &GROTH16_VK_BYTES).is_ok()
}

fn benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("zkvm_proof_generation");
    group.measurement_time(Duration::from_secs(60));
    group.sample_size(10); // Adjust based on how long your proofs take

    // Test with different batch sizes
    for tx_count in [5, 10, 20].iter() {
        let batch = generate_test_batch(*tx_count);

        // Benchmark Approach 1: Groth16 proof with verification inside zkVM (no previous proof)
        group.bench_with_input(
            BenchmarkId::new("groth16_verify_inside_zkvm_base", tx_count),
            &batch,
            |b, batch| {
                b.iter(|| bench_groth16_verify_inside_zkvm(batch, None));
            },
        );

        // Benchmark Approach 2: Separate compressed and Groth16 proofs
        group.bench_with_input(
            BenchmarkId::new("separate_compressed_and_groth16", tx_count),
            &batch,
            |b, batch| {
                b.iter(|| bench_separate_compressed_and_groth16(batch));
            },
        );

        // Create a previous proof to use for recursive verification
        let previous_proof = bench_groth16_verify_inside_zkvm(&batch, None);

        // Extract proof components for verification
        let proof_bytes = match &previous_proof.proof {
            SP1Proof::Groth16(p) => p.clone(),
            _ => panic!("Expected Groth16 proof"),
        };
        let public_values = previous_proof.public_values.clone();
        let vkey_hash = "test_vkey_hash".to_string(); // Replace with actual hash in real usage

        // Benchmark Approach 1 with recursive verification
        let recursive_input = (proof_bytes, public_values, vkey_hash);
        group.bench_with_input(
            BenchmarkId::new("groth16_verify_inside_zkvm_recursive", tx_count),
            &(batch, recursive_input.clone()),
            |b, (batch, recursive_input)| {
                b.iter(|| bench_groth16_verify_inside_zkvm(batch, Some(recursive_input.clone())));
            },
        );
    }
    group.finish();

    // Verification benchmarks
    let mut verify_group = c.benchmark_group("zkvm_proof_verification");
    verify_group.measurement_time(Duration::from_secs(30));

    // Generate the proofs once for verification benchmarks
    let batch = generate_test_batch(10); // Medium-sized batch for verification

    // Setup prover and keys
    let client = ProverClient::builder().cpu().build();
    let (pk, vk) = client.setup(PRISM_ELF);

    // Generate Groth16 proof
    let mut stdin = SP1Stdin::new();
    stdin.write(&false); // No previous proof
    stdin.write(&batch);
    let groth16_proof = client.prove(&pk, &stdin).groth16().run().unwrap();

    // Extract proof components for Groth16Verifier benchmark
    let proof_bytes = match &groth16_proof.proof {
        SP1Proof::Groth16(p) => p.clone(),
        _ => panic!("Expected Groth16 proof"),
    };
    let public_values = groth16_proof.public_values.clone();
    let vkey_hash = "test_vkey_hash".to_string(); // Replace with actual hash in real usage

    // Generate separate compressed and Groth16 proofs
    let (compressed_proof, separate_groth16_proof) = bench_separate_compressed_and_groth16(&batch);

    // Benchmark SP1 native verification (normal Groth16 verification)
    verify_group.bench_function("verify_sp1_native", |b| {
        b.iter(|| bench_verify_groth16_proof(&groth16_proof, &vk));
    });

    // Benchmark verification using Groth16Verifier (simulating in-zkVM verification)
    verify_group.bench_function("verify_groth16_verifier", |b| {
        b.iter(|| bench_verify_with_groth16_verifier(&proof_bytes, &public_values, &vkey_hash));
    });

    // Benchmark verification of separate compressed proof
    verify_group.bench_function("verify_separate_compressed", |b| {
        b.iter(|| bench_verify_groth16_proof(&compressed_proof, &vk));
    });

    // Benchmark verification of separate Groth16 proof
    verify_group.bench_function("verify_separate_groth16", |b| {
        b.iter(|| bench_verify_groth16_proof(&separate_groth16_proof, &vk));
    });

    verify_group.finish();
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
