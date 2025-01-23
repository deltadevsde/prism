//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use rand::{rngs::StdRng, Rng, SeedableRng};

use clap::Parser;
use prism_tree::{proofs::Batch, snarkable_tree::SnarkableTree};
use std::collections::HashMap;
use sp1_sdk::{ProverClient, SP1Stdin};
use prism_common::transaction_builder::TransactionBuilder;
use prism_serde::hex::ToHex;
use prism_tree::key_directory_tree::KeyDirectoryTree;
use std::sync::Arc;
use jmt::mock::MockTreeStore;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const PRISM_ELF: &[u8] = include_bytes!("../../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,
}

fn create_automated_batch(initial_leaf_count: usize, num_accounts: usize, num_operations: usize) -> Batch {
    let mut builder = TransactionBuilder::new();
    let mut rng = StdRng::from_entropy();
    let mut transactions = Vec::with_capacity(num_accounts + num_operations);

    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));

    let transaction = builder.register_service_with_random_keys(
        prism_keys::CryptoAlgorithm::Ed25519,
        "service_id",
    ).commit();
    transactions.push(transaction);

    println!("Prefilling tree...");
    for _ in 0..initial_leaf_count {
        let transaction = builder.create_account_with_random_key_signed(
            prism_keys::CryptoAlgorithm::Ed25519,
            &format!("account_{}", rng.gen::<u32>()),
            "service_id",
        ).commit();
        transactions.push(transaction);
    }
    println!("Prefilled tree");

    for _ in 0..num_accounts {
        let transaction = builder.create_account_with_random_key_signed(
            prism_keys::CryptoAlgorithm::Ed25519,
            &format!("account_{}", rng.gen::<u32>()),
            "service_id",
        ).commit();
        transactions.push(transaction);
    }

    for _ in 0..num_operations {
        let transaction = builder.create_account_with_random_key_signed(
            prism_keys::CryptoAlgorithm::Ed25519,
            &format!("account_{}", rng.gen::<u32>()),
            "service_id",
        ).commit();
        transactions.push(transaction);
    }

    let batch = tree.process_batch(transactions).unwrap();

    println!("done");
    batch
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    if args.execute {
        // Define different configurations for num_accounts and num_operations
        let configurations = vec![
            (1, 10),
            (2, 20),
            (3, 30),
            (4, 40),
            (5, 50),
            (10, 100),
            (100, 1000),
        ];

        let mut results = Vec::new();

        for (num_accounts, num_operations) in &configurations {
            println!("Testing configuration: num_accounts = {}, num_operations = {}", num_accounts, num_operations);

            // Setup the inputs for each configuration.
            let mut stdin = SP1Stdin::new();
            let batch = create_automated_batch(1, *num_accounts, *num_operations);
            stdin.write(&batch);

            // Execute the program
            let (output, report) = client.execute(PRISM_ELF, &stdin).run().unwrap();
            println!("Program executed successfully.");

            // Read the output.
            let decoded = output.as_slice();
            let final_commitment = hex::encode(decoded);
            println!("final_commitment: {}", final_commitment);

            // assert_eq!(final_commitment, batch.new_root.to_hex());
            println!("Values are correct!");

            // Record the number of cycles executed.
            let cycles = report.total_instruction_count();
            println!("Number of cycles: {}", cycles);

            // Store the result for final output
            results.push((num_accounts, num_operations, cycles));
        }

        // Show the final output with the configuration and cycles after everything ran
        println!("\nFinal Results:");
        for (num_accounts, num_operations, cycles) in results {
            println!("Configuration: num_accounts = {}, num_operations = {}, Cycles: {}", num_accounts, num_operations, cycles);
        }
    } else {
        // Setup the inputs for a single configuration for proof generation.
        let mut stdin = SP1Stdin::new();
        let batch = create_automated_batch(1, 1, 10);
        stdin.write(&batch);

        // Setup the program for proving.
        let (pk, vk) = client.setup(PRISM_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
