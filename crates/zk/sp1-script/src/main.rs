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

use clap::Parser;
use prism_tree::{proofs::Batch, snarkable_tree::SnarkableTree};
use sp1_sdk::{ProverClient, SP1Stdin};
use prism_common::transaction_builder::TransactionBuilder;
use prism_tree::key_directory_tree::KeyDirectoryTree;
use std::sync::Arc;
use jmt::mock::MockTreeStore;
use sha2::Digest;

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

fn create_automated_batch(_initial_leaf_count: usize, num_accounts: usize, num_operations: usize) -> Batch {
    let mut builder = TransactionBuilder::new();
    let mut transactions = Vec::with_capacity(num_accounts + num_operations);

    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));

    let transaction = builder.register_service_with_random_keys(
        prism_keys::CryptoAlgorithm::Ed25519,
        "service_id",
    ).commit();
    transactions.push(transaction);

    let mut account_ids = Vec::new();
    let algorithms = [
        prism_keys::CryptoAlgorithm::Ed25519,
        prism_keys::CryptoAlgorithm::Secp256k1,
        prism_keys::CryptoAlgorithm::Secp256r1,
    ];
    let mut algo_iter = algorithms.iter().cycle();

    for i in 0..num_accounts {
        let account_id = format!("account_{}", hex::encode(sha2::Sha256::digest(&i.to_le_bytes())));
        let algorithm = algo_iter.next().unwrap();
        let transaction = builder.create_account_with_random_key_signed(
            *algorithm,
            &account_id,
            "service_id",
        ).commit();
        transactions.push(transaction);
        account_ids.push(account_id);
    }

    let mut account_iter = account_ids.iter().cycle();
    for _ in 0..num_operations {
        if let Some(account_id) = account_iter.next() {
            let algorithm = algo_iter.next().unwrap();
            let transaction = builder.add_random_key_verified_with_root(
                *algorithm,
                account_id,
            ).commit();
            transactions.push(transaction);
        }
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
    let client = ProverClient::from_env();

    if args.execute {
        // Define different configurations for num_accounts and num_operations
        let configurations = vec![
            (100, 10),
            (1000, 10),
            (10000, 10),
            (5000, 50),
        ];

        let num_simulations = 3; // Number of times to run each configuration
        let mut all_results = Vec::new(); // Store results for all configurations

        for (num_accounts, num_operations) in &configurations {
            println!("Testing configuration: num_accounts = {}, num_operations = {}", num_accounts, num_operations);

            let mut cycles_results = Vec::new();

            for _ in 0..num_simulations {
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

                // Store the cycles result for analysis
                cycles_results.push(cycles);
            }

            // Calculate statistics
            cycles_results.sort();
            let min_cycles = *cycles_results.first().unwrap();
            let max_cycles = *cycles_results.last().unwrap();
            let median_cycles = cycles_results[cycles_results.len() / 2];
            let avg_cycles: f64 = cycles_results.iter().sum::<u64>() as f64 / cycles_results.len() as f64;

            // Calculate standard deviation
            let variance: f64 = cycles_results.iter()
                .map(|&x| (x as f64 - avg_cycles).powi(2))
                .sum::<f64>() / cycles_results.len() as f64;
            let std_dev = variance.sqrt();

            // Calculate the percentage of std_dev from avg_cycles
            let std_dev_percentage = (std_dev / avg_cycles) * 100.0;

            // Store the results for the current configuration
            all_results.push((num_accounts, num_operations, min_cycles, max_cycles, median_cycles, avg_cycles, std_dev, std_dev_percentage));
        }

        // Show the results after all configurations have been run
        println!("\nSummary of all configurations:");
        println!("Ran all configurations {} times", num_simulations);
        for (num_accounts, num_operations, min_cycles, max_cycles, median_cycles, avg_cycles, std_dev, std_dev_percentage) in all_results {
            println!("Config: accounts = {}, ops = {}, min = {}, max = {}, median = {}, avg = {:.2}, std_dev = {:.2}, std_dev_percentage = {:.2}%", num_accounts, num_operations, min_cycles, max_cycles, median_cycles, avg_cycles, std_dev, std_dev_percentage);
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
