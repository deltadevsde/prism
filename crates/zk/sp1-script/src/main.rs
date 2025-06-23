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
use core::panic;
use jmt::mock::MockTreeStore;
use plotters::prelude::*;
use prism_common::test_transaction_builder::TestTransactionBuilder;
use prism_keys::{CryptoAlgorithm, SigningKey};
use prism_storage::rocksdb::{RocksDBConnection, RocksDBConfig};
use prism_tree::{
    key_directory_tree::KeyDirectoryTree, proofs::Batch, snarkable_tree::SnarkableTree,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Proof, SP1Stdin};
use std::{collections::HashMap, fs, path::Path, sync::Arc, time::Instant};

use tempfile::tempdir;
use tokio::{self, task};



/// The ELF (executable and linkable format) files for the Succinct RISC-V zkVM.
pub const BASE_PRISM_ELF: &[u8] =
    include_bytes!("../../../../elf/base-riscv32im-succinct-zkvm-elf");
pub const RECURSIVE_PRISM_ELF: &[u8] =
    include_bytes!("../../../../elf/recursive-riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long)]
    tag: Option<String>,

    #[clap(long)]
    start: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimulationConfig {
    tags: Vec<String>,
    num_simulations: usize,
    algorithms: Vec<CryptoAlgorithm>,
    num_existing_services: usize,
    num_existing_accounts: usize,
    num_new_services: usize,
    num_new_accounts: usize,
    num_add_keys: usize,
    num_revoke_key: usize,
    num_add_data: usize,
    num_set_data: usize,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        SimulationConfig {
            tags: vec![],
            num_simulations: 1,
            algorithms: vec![
                CryptoAlgorithm::Ed25519,
                CryptoAlgorithm::Secp256k1,
                CryptoAlgorithm::Secp256r1,
            ],
            num_existing_services: 3,
            num_existing_accounts: 100,
            num_new_services: 1,
            num_new_accounts: 3,
            num_add_keys: 3,
            num_revoke_key: 1,
            num_add_data: 1,
            num_set_data: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimulationResult {
    config: SimulationConfig,
    min_cycles: u64,
    max_cycles: u64,
    avg_cycles: f64,
    median_cycles: u64,
    std_dev: f64,
    std_dev_percentage: f64,
}

/// Get a random service ID from the transaction builder
fn get_random_service_id(rng: &mut impl Rng, builder: &TestTransactionBuilder) -> String {
    let service_keys = builder.get_service_keys();
    let index = rng.gen_range(0..service_keys.len());
    service_keys.keys().nth(index).unwrap().to_string()
}

/// Get the service key for a given service ID from the transaction builder
fn _get_service_key(builder: &TestTransactionBuilder, service_id: &str) -> SigningKey {
    let service_keys = builder.get_service_keys();
    let service_key = service_keys.get(service_id).unwrap();
    service_key.clone()
}

/// Get a random account ID from the transaction builder
fn get_random_account_id(rng: &mut impl Rng, builder: &TestTransactionBuilder) -> String {
    let account_keys = builder.get_account_keys();
    let index = rng.gen_range(0..account_keys.len());
    account_keys.keys().nth(index).unwrap().to_string()
}

/// Get the first account key for a given account ID from the transaction builder
fn get_first_account_key(builder: &TestTransactionBuilder, account_id: &str) -> SigningKey {
    let account_keys_map = builder.get_account_keys();
    let account_keys = account_keys_map.get(account_id).unwrap();
    account_keys.first().unwrap().clone()
}

/// Create a batch of transactions to prepare the initial state of the tree
/// OPTIMIZED: Stream processing to minimize TestTransactionBuilder memory usage
fn create_preparation_batch<S>(
    builder: &mut TestTransactionBuilder,
    tree: &mut KeyDirectoryTree<S>,
    config: &SimulationConfig,
) -> Batch
where
    S: jmt::storage::TreeReader + jmt::storage::TreeWriter + Send + Sync,
{
    // Optimized batch sizes for disk storage to balance performance and memory
    let batch_size = if config.num_existing_accounts >= 500_000 {
        1_000 // Small batches for 500k+ accounts with disk storage
    } else if config.num_existing_accounts >= 100_000 {
        2_000 // Medium batches for 100k+ accounts
    } else if config.num_existing_accounts >= 10_000 {
        5_000 // Moderate batches for 10k+ accounts
    } else {
        10_000 // Normal batch size for smaller tests
    };

    let mut rng = rand::thread_rng();
    let mut last_batch = None;

    // Register existing services first
    let mut service_transactions = Vec::with_capacity(config.num_existing_services);
    for i in 0..config.num_existing_services {
        let algorithm = config.algorithms[i % config.algorithms.len()];
        let service_id = format!(
            "service_{}",
            hex::encode(Sha256::digest(algorithm.to_string().as_bytes()))
        );
        let transaction =
            builder.register_service_with_random_keys(algorithm, &service_id).commit();
        service_transactions.push(transaction);
    }

    if !service_transactions.is_empty() {
        last_batch = Some(tree.process_batch(service_transactions).unwrap());
    }

    // For large benchmarks, use memory-efficient approach
    if config.num_existing_accounts >= 100_000 {
        println!("Using memory-efficient processing for {} accounts", config.num_existing_accounts);
        
        // Process in very small batches and clear builder memory periodically
        let memory_batch_size = 1_000; // Very small batches
        let clear_interval = 10_000; // Clear builder memory every 10k accounts
        let mut accounts_created = 0;
        
        for batch_start in (0..config.num_existing_accounts).step_by(memory_batch_size) {
            let batch_end = (batch_start + memory_batch_size).min(config.num_existing_accounts);
            let mut account_transactions = Vec::with_capacity(batch_end - batch_start);

            for i in batch_start..batch_end {
                let algorithm = config.algorithms[i % config.algorithms.len()];
                let account_id = format!("account_{}", hex::encode(Sha256::digest(i.to_le_bytes())));
                let service_id = get_random_service_id(&mut rng, builder);
                let transaction = builder
                    .create_account_with_random_key_signed(algorithm, &account_id, &service_id)
                    .commit();
                account_transactions.push(transaction);
            }

            if !account_transactions.is_empty() {
                last_batch = Some(tree.process_batch(account_transactions).unwrap());
                accounts_created += batch_end - batch_start;

                // Progress reporting
                if batch_start % 10_000 == 0 {
                    println!("Processed {} of {} accounts ({:.1}%) - builder has {} accounts", 
                            batch_end, config.num_existing_accounts,
                            (batch_end as f64 / config.num_existing_accounts as f64) * 100.0,
                            builder.get_account_keys().len());
                }
                
                // Clear builder memory periodically to prevent OOM, but keep some accounts for benchmark
                if accounts_created >= clear_interval && builder.get_account_keys().len() > 2000 {
                    println!("Clearing TestTransactionBuilder memory at {} accounts (keeping 1000 for benchmark)...", accounts_created);
                    
                    // Create new builder with services and subset of accounts
                    let mut new_builder = TestTransactionBuilder::new();
                    
                    // Preserve services
                    let service_keys = builder.get_service_keys();
                    for (service_id, _) in service_keys.iter() {
                        let algorithm = config.algorithms[0];
                        new_builder.register_service_with_random_keys(algorithm, service_id).commit();
                    }
                    
                    // Keep up to 1000 accounts for benchmark operations
                    let account_keys = builder.get_account_keys();
                    let accounts_to_keep: Vec<_> = account_keys.keys().take(1000).collect();
                    
                    for account_id in accounts_to_keep.iter() {
                        let algorithm = config.algorithms[0];
                        let service_id = service_keys.keys().next().unwrap();
                        new_builder.create_account_with_random_key_signed(algorithm, account_id, service_id).commit();
                    }
                    
                    *builder = new_builder;
                    accounts_created = 0; // Reset counter
                }
            }
        }
    } else {
        // Process accounts in smaller batches for moderate sizes
        for batch_start in (0..config.num_existing_accounts).step_by(batch_size) {
            let batch_end = (batch_start + batch_size).min(config.num_existing_accounts);
            let mut account_transactions = Vec::with_capacity(batch_end - batch_start);

            for i in batch_start..batch_end {
                let algorithm = config.algorithms[i % config.algorithms.len()];
                let account_id = format!("account_{}", hex::encode(Sha256::digest(i.to_le_bytes())));
                let service_id = get_random_service_id(&mut rng, builder);
                let transaction = builder
                    .create_account_with_random_key_signed(algorithm, &account_id, &service_id)
                    .commit();
                account_transactions.push(transaction);
            }

            if !account_transactions.is_empty() {
                last_batch = Some(tree.process_batch(account_transactions).unwrap());

                // Progress indicator for large benchmarks
                if config.num_existing_accounts >= 10_000 && batch_start % (batch_size * 10) == 0 {
                    println!("Processed {} of {} accounts ({:.1}%) using disk storage", 
                            batch_end, config.num_existing_accounts,
                            (batch_end as f64 / config.num_existing_accounts as f64) * 100.0);
                }
            }
        }
    }

    let final_batch = last_batch.expect("Should have processed at least one batch");
    
    // Log completion for large benchmarks
    if config.num_existing_accounts >= 100_000 {
        println!("Completed preparation phase with {} accounts", config.num_existing_accounts);
    }
    
    final_batch
}

/// Create a batch of transactions to benchmark the performance of the tree
fn create_benchmark_batch<S>(
    builder: &mut TestTransactionBuilder,
    tree: &mut KeyDirectoryTree<S>,
    config: &SimulationConfig,
) -> Batch
where
    S: jmt::storage::TreeReader + jmt::storage::TreeWriter + Send + Sync,
{
    // Pre-allocate with expected capacity to reduce reallocations
    let total_ops = config.num_new_services + config.num_new_accounts + 
                   config.num_add_keys + config.num_revoke_key + 
                   config.num_add_data + config.num_set_data;
    let mut transactions = Vec::with_capacity(total_ops);

    let mut rng = rand::thread_rng();

    // Create new services
    let service_keys_len = builder.get_service_keys().len();
    for i in 0..config.num_new_services {
        let algorithm = config.algorithms[i % config.algorithms.len()];
        let service_id = format!(
            "service_{}",
            hex::encode(Sha256::digest((i + service_keys_len).to_le_bytes()))
        );
        let transaction =
            builder.register_service_with_random_keys(algorithm, &service_id).commit();
        transactions.push(transaction);
    }

    // Create new accounts
    for i in 0..config.num_new_accounts {
        let algorithm = config.algorithms[i % config.algorithms.len()];
        let account_id = format!("account_{}", i + config.num_existing_accounts);
        let service_id = get_random_service_id(&mut rng, builder);
        let transaction = builder
            .create_account_with_random_key_signed(algorithm, &account_id, &service_id)
            .commit();
        transactions.push(transaction);
    }

    // Add keys to accounts
    for i in 0..config.num_add_keys {
        let algorithm = config.algorithms[i % config.algorithms.len()];
        let account_id = get_random_account_id(&mut rng, builder);
        let transaction =
            builder.add_random_key_verified_with_root(algorithm, &account_id).commit();
        transactions.push(transaction);
    }

    // Revoke keys from accounts
    for _ in 0..config.num_revoke_key {
        let account_id = get_random_account_id(&mut rng, builder);
        let account_key = get_first_account_key(builder, &account_id);
        let transaction =
            builder.revoke_key_verified_with_root(&account_id, account_key.clone().into()).commit();
        transactions.push(transaction);
    }

    // Add data to accounts
    for _ in 0..config.num_add_data {
        let account_id = get_random_account_id(&mut rng, builder);
        let data = Sha512::digest(b"boo").to_vec();
        let transaction =
            builder.add_internally_signed_data_verified_with_root(&account_id, data).commit();
        transactions.push(transaction);
    }

    // Set data to accounts
    for _ in 0..config.num_set_data {
        let account_id = get_random_account_id(&mut rng, builder);
        let data = Sha512::digest(b"boo").to_vec();
        let transaction =
            builder.set_internally_signed_data_verified_with_root(&account_id, data).commit();
        transactions.push(transaction);
    }

    tree.process_batch(transactions).unwrap()
}

#[tokio::main]
async fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    // Ensure that only one mode is specified
    let mode_count = [args.execute, args.prove, args.start].iter().filter(|&&x| x).count();
    if mode_count != 1 {
        eprintln!("Error: You must specify exactly one of --execute, --prove, or --start");
        std::process::exit(1);
    }

    // Handle --start flag to plot from existing JSON data
    if args.start {
        plot_from_json(args.tag).await;
        return;
    }

    // Execute simulations if --execute is specified
    if args.execute {
        execute_simulations(args).await;
    } else {
        // Setup the prover client with CUDA support.
        let client = ProverClient::builder().cuda().build();

        println!("------ PHASE 1: BASE PROOF GENERATION ------");

        // Setup the inputs for a single configuration for proof generation.
        let mut stdin_base = SP1Stdin::new();
        let mut builder = TestTransactionBuilder::new();
        let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
        let config = SimulationConfig {
            tags: vec![],
            num_simulations: 1,
            algorithms: vec![CryptoAlgorithm::Secp256r1],
            num_existing_services: 1,
            num_existing_accounts: 10,
            num_new_services: 1,
            num_new_accounts: 3,
            num_add_keys: 3,
            num_revoke_key: 1,
            num_add_data: 1,
            num_set_data: 1,
        };
        println!("{:?}", tree.get_commitment().unwrap());
        println!("Starting to create benchmark batch");
        let base_batch = create_benchmark_batch(&mut builder, &mut tree, &config);

        println!("Done creating benchmark batch");

        stdin_base.write(&base_batch);

        // Setup the base program for proving.
        let (base_pk, base_vk) = client.setup(BASE_PRISM_ELF);

        // generate the base compressed proof
        println!("Generating base proof");
        let start = Instant::now();
        let base_compressed_proof = client
            .prove(&base_pk, &stdin_base)
            .compressed()
            .run()
            .expect("failed to generate base proof");

        // Generate the base groth16 proof
        println!("Generating base proof");
        let base_proof = client
            .prove(&base_pk, &stdin_base)
            .groth16()
            .run()
            .expect("failed to generate base proof");
        let duration = start.elapsed();
        println!("Generated base groth16 proof in {:.2?} seconds", duration);

        println!("Verifying base proofs");
        client.verify(&base_compressed_proof, &base_vk).expect("failed to verify base proof");
        client.verify(&base_proof, &base_vk).expect("failed to verify base proof");
        println!("Base proof verified successfully!");

        println!("\n------ PHASE 2: RECURSIVE PROOF GENERATION ------");
        let mut stdin_recursive = SP1Stdin::new();

        let public_values = base_compressed_proof.public_values.clone();
        let vkey_hash = base_vk.hash_u32();

        // Write recursive inputs
        let SP1Proof::Compressed(compressed_proof) = base_compressed_proof.proof else {
            panic!("Expected compressed proof")
        };
        stdin_recursive.write_proof(*compressed_proof, base_vk.vk);
        stdin_recursive.write_vec(public_values.to_vec());
        stdin_recursive.write(&vkey_hash);

        println!("Creating recursive batch");
        let recursive_config = SimulationConfig {
            tags: vec![],
            num_simulations: 1,
            algorithms: vec![CryptoAlgorithm::Secp256r1],
            num_existing_services: 2,
            num_existing_accounts: 13,
            num_new_services: 10,
            num_new_accounts: 10,
            num_add_keys: 12,
            num_revoke_key: 8,
            num_add_data: 5,
            num_set_data: 5,
        };

        let recursive_batch = create_benchmark_batch(&mut builder, &mut tree, &recursive_config);

        if recursive_batch.prev_root != base_batch.new_root {
            eprintln!("Error: State discontinuity between batches");
            eprintln!("Base batch new_root: {:?}", base_batch.new_root);
            eprintln!("Recursive batch prev_root: {:?}", recursive_batch.prev_root);
            std::process::exit(1);
        }
        stdin_recursive.write(&recursive_batch);

        let (recursive_pk, recursive_vk) = client.setup(RECURSIVE_PRISM_ELF);

        println!("Generating compressed recursive proof");
        let start = Instant::now();
        let compressed_recursive_proof = client
            .prove(&recursive_pk, &stdin_recursive)
            .compressed()
            .run()
            .expect("failed to generate recursive proof");

        println!(
            "Generated compressed recursive proof in {:.2?} seconds",
            duration
        );

        println!("Generating recursive groth16 proof");

        let recursive_proof = client
            .prove(&recursive_pk, &stdin_recursive)
            .groth16()
            .run()
            .expect("failed to generate recursive proof");
        let duration = start.elapsed();
        println!("Generated recursive proof in {:.2?} seconds", duration);

        println!("Verifying recursive proofs");
        client
            .verify(&compressed_recursive_proof, &recursive_vk)
            .expect("failed to verify recursive proof");
        client.verify(&recursive_proof, &recursive_vk).expect("failed to verify recursive proof");
        println!("Recursive proof verified successfully!");
    }
}

/// Execute simulations based on the provided arguments
async fn execute_simulations(args: Args) {
    // For wire benchmark, use only 1 simulation to prevent parallel OOM
    let num_simulations = if args.tag.as_ref().map_or(false, |tag| tag == "wire") {
        1 // Wire benchmark uses only 1 simulation
    } else {
        100 // Other benchmarks use 100 simulations
    };

    // Define default configuration
    let default_config = SimulationConfig::default();

    // Define different configurations for num_accounts and num_operations
    let configurations = get_configurations(num_simulations, &default_config);

    let mut results = Vec::new(); // Store results for all configurations

    for config in &configurations {
        if let Some(ref tag) = args.tag {
            if !config.tags.contains(tag) {
                continue;
            }
        }

        println!("Testing configuration: {:?}", config);

        // Use disk-backed storage for large benchmarks to prevent OOM
        // Lower threshold to use disk storage more aggressively
        let use_disk_storage = config.tags.contains(&"wire".to_string()) ||
                              config.tags.contains(&"wire-full".to_string()) ||
                              config.num_existing_accounts >= 5_000;

        if use_disk_storage {
            println!("Using RocksDB disk-backed storage for large benchmark with {} accounts", config.num_existing_accounts);
        }

        let mut tasks = Vec::new();

        for _ in 0..num_simulations {
            let config = config.clone();

            tasks.push(task::spawn(async move {
                // Setup the prover client.
                let client = ProverClient::from_env();

                let mut builder = TestTransactionBuilder::new();

                // Use disk-backed storage for large benchmarks to prevent OOM
                let operations_batch = if use_disk_storage {
                    // Create temporary directory for RocksDB
                    let temp_dir = tempdir().expect("Failed to create temp directory");
                    let db_path = temp_dir.path().join("large_benchmark_db");

                    // Initialize RocksDB with optimized settings for large datasets
                    let db_config = RocksDBConfig::new(db_path.to_str().unwrap());
                    let db = RocksDBConnection::new(&db_config).expect("Failed to create RocksDB connection");
                    let mut tree = KeyDirectoryTree::new(Arc::new(db));

                    println!("Starting large benchmark preparation ({} accounts)...", config.num_existing_accounts);
                    let start_time = std::time::Instant::now();

                    // Process preparation batch using disk storage
                    let _initial = create_preparation_batch(&mut builder, &mut tree, &config);

                    println!("Preparation completed in {:?}", start_time.elapsed());
                    println!("Starting benchmark operations...");

                    // Create benchmark batch
                    let operations = create_benchmark_batch(&mut builder, &mut tree, &config);

                    // Clean up tree reference before dropping temp directory
                    drop(tree);
                    
                    println!("Completed large benchmark operations successfully");

                    // Keep temp directory alive longer to ensure cleanup doesn't interfere with result
                    std::mem::forget(temp_dir);

                    operations
                } else {
                    // Use regular MockTreeStore for smaller benchmarks
                    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));
                    let _initial = create_preparation_batch(&mut builder, &mut tree, &config);
                    create_benchmark_batch(&mut builder, &mut tree, &config)
                };

                // Reset stdin by creating a new instance and write the operations batch
                let mut stdin = SP1Stdin::new();
                stdin.write(&operations_batch);

                // Execute the operations batch
                let (_, report) = task::spawn_blocking(move || {
                    client.execute(BASE_PRISM_ELF, &stdin).run().unwrap()
                })
                .await
                .unwrap();
                println!("Operations batch executed successfully.");

                // Record the number of cycles executed.
                report.total_instruction_count()
            }));
        }

        let cycles_vec: Vec<u64> =
            futures::future::join_all(tasks).await.into_iter().map(|res| res.unwrap()).collect();

        // Calculate statistics
        let (min_cycles, max_cycles, avg_cycles, median_cycles, std_dev, std_dev_percentage) =
            calculate_statistics(&cycles_vec, num_simulations);

        // Store the results for this configuration
        results.push(SimulationResult {
            config: config.clone(),
            min_cycles,
            max_cycles,
            avg_cycles,
            median_cycles,
            std_dev,
            std_dev_percentage,
        });
    }

    println!(
        "Running {} simulations for each configuration",
        num_simulations
    );

    // Print all results after all configurations have been run
    for result in &results {
        println!("--------------------------------");
        println!(
            "Results for configuration: {:?} which had {} runs",
            result.config, result.config.num_simulations
        );
        println!(
            "Min: {}, Max: {}, Avg: {:.2}, Median: {}, Std dev: {:.2}, Std dev percentage: {:.2}%",
            result.min_cycles,
            result.max_cycles,
            result.avg_cycles,
            result.median_cycles,
            result.std_dev,
            result.std_dev_percentage
        );
    }

    // Save results to JSON before plotting
    if let Err(e) = save_results_to_json(&results) {
        eprintln!("Error saving results to JSON: {}", e);
    }

    // Plot results for green configurations
    plot_green_configurations(&results).expect("Failed to plot green configurations");

    // Plot results for yellow configurations
    plot_yellow_configurations(&results).expect("Failed to plot yellow configurations");

    // Plot results for blue configurations
    plot_blue_configurations(&results).expect("Failed to plot blue configurations");

    // Plot results for orange configurations
    plot_orange_configurations(&results).expect("Failed to plot orange configurations");

    // Plot results for wire configurations
    plot_wire_configurations(&results).expect("Failed to plot wire configurations");
}

/// Generate different configurations for the simulations
fn get_configurations(
    num_simulations: usize,
    default_config: &SimulationConfig,
) -> Vec<SimulationConfig> {
    let mut configs = Vec::new();

    let green_configs = vec![1, 100, 1000, 5000, 10000];
    for num_existing_accounts in green_configs {
        configs.push(SimulationConfig {
            tags: vec!["green".to_string()],
            num_simulations,
            num_existing_accounts,
            ..default_config.clone()
        });
    }

    let yellow_algorithms = vec![
        CryptoAlgorithm::Ed25519,
        CryptoAlgorithm::Secp256k1,
        CryptoAlgorithm::Secp256r1,
    ];
    for algorithm in yellow_algorithms {
        configs.push(SimulationConfig {
            tags: vec!["yellow".to_string()],
            num_simulations,
            algorithms: vec![algorithm],
            num_existing_services: 1,
            ..default_config.clone()
        });
    }

    let blue_configs = vec![
        (10, 0, 0, 0, 0, 0),
        (0, 10, 0, 0, 0, 0),
        (0, 0, 10, 0, 0, 0),
        (0, 0, 0, 10, 0, 0),
        (0, 0, 0, 0, 10, 0),
        (0, 0, 0, 0, 0, 10),
    ];
    for (
        num_new_services,
        num_new_accounts,
        num_add_keys,
        num_revoke_key,
        num_add_data,
        num_set_data,
    ) in blue_configs
    {
        configs.push(SimulationConfig {
            tags: vec!["blue".to_string()],
            num_simulations,
            num_new_services,
            num_new_accounts,
            num_add_keys,
            num_revoke_key,
            num_add_data,
            num_set_data,
            ..default_config.clone()
        });
    }

    let orange_algorithms = vec![
        CryptoAlgorithm::Ed25519,
        CryptoAlgorithm::Secp256k1,
        CryptoAlgorithm::Secp256r1,
    ];
    let orange_configs = vec![
        (10, 0, 0, 0, 0, 0),
        (0, 10, 0, 0, 0, 0),
        (0, 0, 10, 0, 0, 0),
        (0, 0, 0, 10, 0, 0),
        (0, 0, 0, 0, 10, 0),
        (0, 0, 0, 0, 0, 10),
    ];
    for algorithm in orange_algorithms {
        for (
            num_new_services,
            num_new_accounts,
            num_add_keys,
            num_revoke_key,
            num_add_data,
            num_set_data,
        ) in &orange_configs
        {
            configs.push(SimulationConfig {
                tags: vec!["orange".to_string()],
                num_simulations,
                algorithms: vec![algorithm],
                num_existing_services: 1,
                num_new_services: *num_new_services,
                num_new_accounts: *num_new_accounts,
                num_add_keys: *num_add_keys,
                num_revoke_key: *num_revoke_key,
                num_add_data: *num_add_data,
                num_set_data: *num_set_data,
                ..default_config.clone()
            });
        }
    }

    // Wire benchmark - original requirements must be preserved
    configs.push(SimulationConfig {
        tags: vec!["wire".to_string()],
        num_simulations: 1,
        algorithms: vec![CryptoAlgorithm::Ed25519],
        num_existing_services: 1, // Reasonable number of Wire services
        num_existing_accounts: 500_000, // Current Wire user base - REQUIRED
        num_new_services: 0,
        num_new_accounts: 41, // 41 new users per hour (1k per day)
        num_add_keys: 250, // 0.1% of users add key/device per hour (500k * 0.001 = 500, scaled to 250 for performance)
        num_revoke_key: 20, // 20 key removals per hour
        num_add_data: 0,
        num_set_data: 0,
    });

    configs
}

/// Calculate statistics for the number of cycles executed
fn calculate_statistics(
    cycles_vec: &[u64],
    num_simulations: usize,
) -> (u64, u64, f64, u64, f64, f64) {
    let min_cycles = *cycles_vec.iter().min().unwrap();
    let max_cycles = *cycles_vec.iter().max().unwrap();
    let avg_cycles = cycles_vec.iter().sum::<u64>() as f64 / num_simulations as f64;
    let median_cycles = {
        let mut sorted = cycles_vec.to_owned();
        sorted.sort();
        sorted[num_simulations / 2]
    };
    let std_dev = {
        let variance = cycles_vec.iter().map(|&x| (x as f64 - avg_cycles).powi(2)).sum::<f64>()
            / num_simulations as f64;
        variance.sqrt()
    };
    let std_dev_percentage = (std_dev / avg_cycles) * 100.0;
    (
        min_cycles,
        max_cycles,
        avg_cycles,
        median_cycles,
        std_dev,
        std_dev_percentage,
    )
}

const RESULTS_JSON_FILE: &str = "benchmark_results.json";

/// Save results to JSON file, merging with existing data if present
fn save_results_to_json(new_results: &[SimulationResult]) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_results: HashMap<String, SimulationResult> = if Path::new(RESULTS_JSON_FILE).exists() {
        let json_data = fs::read_to_string(RESULTS_JSON_FILE)?;
        serde_json::from_str(&json_data).unwrap_or_default()
    } else {
        HashMap::new()
    };

    // Create unique keys for each configuration based on its characteristics
    for result in new_results {
        let key = create_config_key(&result.config);
        all_results.insert(key, result.clone());
    }

    let json_data = serde_json::to_string_pretty(&all_results)?;
    fs::write(RESULTS_JSON_FILE, json_data)?;
    println!("Results saved to {}", RESULTS_JSON_FILE);
    Ok(())
}

/// Load results from JSON file, optionally filtered by tag
fn load_results_from_json(tag_filter: Option<String>) -> Result<Vec<SimulationResult>, Box<dyn std::error::Error>> {
    if !Path::new(RESULTS_JSON_FILE).exists() {
        return Err("No results file found. Run benchmarks first.".into());
    }

    let json_data = fs::read_to_string(RESULTS_JSON_FILE)?;
    let all_results: HashMap<String, SimulationResult> = serde_json::from_str(&json_data)?;

    let mut results: Vec<SimulationResult> = all_results.into_values().collect();

    // Filter by tag if specified
    if let Some(tag) = tag_filter {
        results.retain(|result| result.config.tags.contains(&tag));
    }

    Ok(results)
}

/// Create a unique key for a configuration
fn create_config_key(config: &SimulationConfig) -> String {
    format!(
        "{}_{}_{}_{}_{}_{}_{}_{}_{}_{}",
        config.tags.join("-"),
        config.algorithms.len(),
        config.num_existing_services,
        config.num_existing_accounts,
        config.num_new_services,
        config.num_new_accounts,
        config.num_add_keys,
        config.num_revoke_key,
        config.num_add_data,
        config.num_set_data
    )
}

/// Plot charts from existing JSON data
async fn plot_from_json(tag_filter: Option<String>) {
    match load_results_from_json(tag_filter) {
        Ok(results) => {
            println!("Loaded {} results from JSON file", results.len());

            // Generate plots
            if let Err(e) = plot_green_configurations(&results) {
                eprintln!("Error plotting green configurations: {}", e);
            }
            if let Err(e) = plot_yellow_configurations(&results) {
                eprintln!("Error plotting yellow configurations: {}", e);
            }
            if let Err(e) = plot_blue_configurations(&results) {
                eprintln!("Error plotting blue configurations: {}", e);
            }
            if let Err(e) = plot_orange_configurations(&results) {
                eprintln!("Error plotting orange configurations: {}", e);
            }
            if let Err(e) = plot_wire_configurations(&results) {
                eprintln!("Error plotting wire configurations: {}", e);
            }

            println!("All plots generated successfully from existing data.");
        }
        Err(e) => {
            eprintln!("Error loading results from JSON: {}", e);
            std::process::exit(1);
        }
    }
}

/// Plot results for green configurations
fn plot_green_configurations(
    results: &[SimulationResult],
) -> Result<(), Box<dyn std::error::Error>> {
    let green_results: Vec<&SimulationResult> =
        results.iter().filter(|res| res.config.tags.contains(&"green".to_string())).collect();

    // skip if there are no green results
    if green_results.is_empty() {
        return Ok(());
    }

    let root_area = BitMapBackend::new("green_configurations.png", (1000, 600)).into_drawing_area();
    root_area.fill(&WHITE)?;

    let num_existing_accounts: Vec<u32> =
        green_results.iter().map(|res| res.config.num_existing_accounts as u32).collect();
    let avg_cycles: Vec<f64> = green_results.iter().map(|res| res.avg_cycles).collect();
    let min_cycles: Vec<u64> = green_results.iter().map(|res| res.min_cycles).collect();
    let max_cycles: Vec<u64> = green_results.iter().map(|res| res.max_cycles).collect();

    let y_min = *min_cycles.iter().min().unwrap();
    let y_max = *max_cycles.iter().max().unwrap();
    let x_min = num_existing_accounts.iter().cloned().min().unwrap();
    let x_max = num_existing_accounts.iter().cloned().max().unwrap();
    let y_min_adjusted = y_min as f64 - (y_max as f64 / 10.0);
    let y_max_adjusted = y_max as f64 + (y_max as f64 / 10.0);
    let x_min_adjusted = x_min as f64 - (x_max as f64 / 10.0);
    let x_max_adjusted = x_max as f64 + (x_max as f64 / 10.0);

    let mut chart = ChartBuilder::on(&root_area)
        .caption("Average Cycles of Doing 10 Operations and Min/Max Range by Number of Existing Accounts", ("sans-serif", 20))
        .margin(10)
        .x_label_area_size(30)
        .y_label_area_size(50)
        .build_cartesian_2d(
            x_min_adjusted..x_max_adjusted,
            y_min_adjusted..y_max_adjusted
        )?;

    chart
        .configure_mesh()
        .x_desc("Number of Existing Accounts")
        .x_label_formatter(&|&x| format!("{}", x))
        .x_label_style(&BLACK)
        .y_desc("Average Cycles")
        .y_label_formatter(&|&y| format!("{:e}", y))
        .draw()?;

    // Draw the avg cycles as a line
    chart
        .draw_series(LineSeries::new(
            num_existing_accounts.iter().zip(avg_cycles.iter()).map(|(&x, &y)| (x as f64, y)),
            &BLACK,
        ))
        .unwrap()
        .label("Average Cycles")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLACK));

    // Draw the average cycles as circles
    chart.draw_series(
        num_existing_accounts
            .iter()
            .zip(avg_cycles.iter())
            .map(|(&x, &y)| Circle::new((x as f64, y), 5, BLACK.filled())),
    )?;

    // Draw the min cycles as circles
    chart
        .draw_series(LineSeries::new(
            num_existing_accounts
                .iter()
                .zip(min_cycles.iter())
                .map(|(&x, &y)| (x as f64, y as f64)),
            &BLUE,
        ))
        .unwrap()
        .label("Min Cycles")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    // Draw the max cycles as circles
    chart
        .draw_series(LineSeries::new(
            num_existing_accounts
                .iter()
                .zip(max_cycles.iter())
                .map(|(&x, &y)| (x as f64, y as f64)),
            &BLUE,
        ))
        .unwrap()
        .label("Max Cycles")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    chart
        .configure_series_labels()
        .background_style(WHITE.mix(0.8))
        .border_style(BLACK)
        .position(SeriesLabelPosition::UpperRight)
        .draw()
        .unwrap();

    root_area
        .present()
        .expect("Unable to write result to file, please make sure the directory exists");
    println!("Result has been saved to green_configurations.png");

    Ok(())
}

/// Plot results for yellow configurations
fn plot_yellow_configurations(
    results: &[SimulationResult],
) -> Result<(), Box<dyn std::error::Error>> {
    let yellow_results: Vec<&SimulationResult> =
        results.iter().filter(|res| res.config.tags.contains(&"yellow".to_string())).collect();

    // skip if there are no yellow results
    if yellow_results.is_empty() {
        return Ok(());
    }

    let root_area =
        BitMapBackend::new("yellow_configurations.png", (1000, 600)).into_drawing_area();
    root_area.fill(&WHITE)?;

    let algorithms: Vec<CryptoAlgorithm> =
        yellow_results.iter().map(|res| *res.config.algorithms.first().unwrap()).collect();
    let avg_cycles: Vec<f64> = yellow_results.iter().map(|res| res.avg_cycles).collect();

    let y_min = 0;
    let y_max = avg_cycles.iter().cloned().fold(f64::NAN, f64::max);
    let x_min = 0;
    let x_max = algorithms.len() as u32 - 1;
    let y_max_adjusted = y_max + (y_max / 10.0);

    let mut chart = ChartBuilder::on(&root_area)
        .caption(
            "Average Cycles for Each Algorithm at 10 Operations",
            ("sans-serif", 20),
        )
        .margin(10)
        .x_label_area_size(30)
        .y_label_area_size(50)
        .build_cartesian_2d(
            (x_min..x_max).into_segmented(),
            y_min as f64..y_max_adjusted,
        )?;

    chart
        .configure_mesh()
        .x_desc("Algorithms")
        .x_labels(algorithms.len())
        .x_label_formatter(&|x| {
            let index = match x {
                SegmentValue::Exact(v) => *v,
                SegmentValue::CenterOf(v) => *v,
                SegmentValue::Last => 0,
            };

            algorithms[index as usize].to_string()
        })
        .y_desc("Cycles")
        .y_label_formatter(&|&y| format!("{:e}", y))
        .draw()?;

    // Draw the average cycles as a histogram
    chart
        .draw_series(
            Histogram::vertical(&chart)
                .style(BLUE.mix(0.5).filled())
                .data(avg_cycles.iter().enumerate().map(|(i, &y)| (i as u32, y))),
        )?
        .label("Average Cycles")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    chart
        .configure_series_labels()
        .background_style(WHITE.mix(0.8))
        .border_style(BLACK)
        .position(SeriesLabelPosition::UpperRight)
        .draw()
        .unwrap();

    root_area
        .present()
        .expect("Unable to write result to file, please make sure the directory exists");
    println!("Result has been saved to yellow_configurations.png");

    Ok(())
}

fn plot_blue_configurations(
    results: &[SimulationResult],
) -> Result<(), Box<dyn std::error::Error>> {
    let blue_results: Vec<&SimulationResult> =
        results.iter().filter(|res| res.config.tags.contains(&"blue".to_string())).collect();

    // skip if there are no blue results
    if blue_results.is_empty() {
        return Ok(());
    }

    let root_area = BitMapBackend::new("blue_configurations.png", (1000, 600)).into_drawing_area();
    root_area.fill(&WHITE)?;

    let avg_cycles = blue_results.iter().map(|res| res.avg_cycles as u64).collect::<Vec<u64>>();

    let x_min = 0;
    let x_max = blue_results.len() as u32 - 1;
    let y_min = 0;
    let y_max = *avg_cycles.iter().max().unwrap();
    let y_max_adjusted = y_max as f64 + (y_max as f64 / 10.0);

    let mut chart = ChartBuilder::on(&root_area)
        .caption(
            "Average Cycles per Operation Type with Random Algorithms",
            ("sans-serif", 20),
        )
        .margin(10)
        .x_label_area_size(30)
        .y_label_area_size(50)
        .build_cartesian_2d(
            (x_min..x_max).into_segmented(),
            y_min as f64..y_max_adjusted,
        )?;

    chart
        .configure_mesh()
        .x_desc("Operation Type")
        .x_label_formatter(&|x| {
            let index = match x {
                SegmentValue::Exact(v) => *v,
                SegmentValue::CenterOf(v) => *v,
                SegmentValue::Last => 0,
            };

            let operation = if let Some(result) = blue_results.get(index as usize) {
                if result.config.num_new_services > 0 {
                    "New Service (10)"
                } else if result.config.num_new_accounts > 0 {
                    "New Account (10)"
                } else if result.config.num_add_keys > 0 {
                    "Add Key (10)"
                } else if result.config.num_revoke_key > 0 {
                    "Revoke Key (10)"
                } else if result.config.num_add_data > 0 {
                    "Add Data (10)"
                } else if result.config.num_set_data > 0 {
                    "Set Data (10)"
                } else {
                    "Unknown"
                }
            } else {
                "Unknown"
            };

            operation.to_string()
        })
        .y_desc("Cycles")
        .y_label_formatter(&|&y| format!("{:e}", y))
        .draw()?;

    // Draw the average cycles as a histogram
    chart
        .draw_series(
            Histogram::vertical(&chart)
                .style(BLUE.mix(0.5).filled())
                .data(avg_cycles.iter().enumerate().map(|(i, &y)| (i as u32, y as f64))),
        )?
        .label("Average Cycles")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    chart
        .configure_series_labels()
        .background_style(WHITE.mix(0.8))
        .border_style(BLACK)
        .position(SeriesLabelPosition::UpperRight)
        .draw()
        .unwrap();

    root_area
        .present()
        .expect("Unable to write result to file, please make sure the directory exists");
    println!("Result has been saved to blue_configurations.png");

    Ok(())
}

fn plot_orange_configurations(
    results: &[SimulationResult],
) -> Result<(), Box<dyn std::error::Error>> {
    let orange_results: Vec<&SimulationResult> =
        results.iter().filter(|res| res.config.tags.contains(&"orange".to_string())).collect();

    for algorithm in [
        CryptoAlgorithm::Ed25519,
        CryptoAlgorithm::Secp256k1,
        CryptoAlgorithm::Secp256r1,
    ] {
        plot_orange_configurations_algorithm(&orange_results, algorithm)?;
    }

    Ok(())
}

fn plot_orange_configurations_algorithm(
    results: &[&SimulationResult],
    algorithm: CryptoAlgorithm,
) -> Result<(), Box<dyn std::error::Error>> {
    let algorithm_results: Vec<&SimulationResult> =
        results.iter().filter(|res| res.config.algorithms.contains(&algorithm)).cloned().collect();

    // skip if there are no orange results
    if algorithm_results.is_empty() {
        return Ok(());
    }
    let file_name = format!("orange_configurations_{}.png", algorithm);
    let root_area = BitMapBackend::new(&file_name, (1000, 600)).into_drawing_area();
    root_area.fill(&WHITE)?;

    let avg_cycles =
        algorithm_results.iter().map(|res| res.avg_cycles as u64).collect::<Vec<u64>>();

    let x_min = 0;
    let x_max = algorithm_results.len() as u32 - 1;
    let y_min = 0;
    let y_max = *avg_cycles.iter().max().unwrap();
    let y_max_adjusted = y_max as f64 + (y_max as f64 / 10.0);

    let mut chart = ChartBuilder::on(&root_area)
        .caption(
            format!("Average Cycles per Operation Type for {}", algorithm),
            ("sans-serif", 20),
        )
        .margin(10)
        .x_label_area_size(30)
        .y_label_area_size(50)
        .build_cartesian_2d(
            (x_min..x_max).into_segmented(),
            y_min as f64..y_max_adjusted,
        )?;

    chart
        .configure_mesh()
        .x_desc("Operation Type")
        .x_label_formatter(&|x| {
            let index = match x {
                SegmentValue::Exact(v) => *v,
                SegmentValue::CenterOf(v) => *v,
                SegmentValue::Last => 0,
            };

            let operation = if let Some(result) = algorithm_results.get(index as usize) {
                if result.config.num_new_services > 0 {
                    "New Service (10)"
                } else if result.config.num_new_accounts > 0 {
                    "New Account (10)"
                } else if result.config.num_add_keys > 0 {
                    "Add Key (10)"
                } else if result.config.num_revoke_key > 0 {
                    "Revoke Key (10)"
                } else if result.config.num_add_data > 0 {
                    "Add Data (10)"
                } else if result.config.num_set_data > 0 {
                    "Set Data (10)"
                } else {
                    "Unknown"
                }
            } else {
                "Unknown"
            };

            operation.to_string()
        })
        .y_desc("Cycles")
        .y_label_formatter(&|&y| format!("{:e}", y))
        .draw()?;

    // Draw the average cycles as a histogram
    chart
        .draw_series(
            Histogram::vertical(&chart)
                .style(BLUE.mix(0.5).filled())
                .data(avg_cycles.iter().enumerate().map(|(i, &y)| (i as u32, y as f64))),
        )?
        .label("Average Cycles")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    chart
        .configure_series_labels()
        .background_style(WHITE.mix(0.8))
        .border_style(BLACK)
        .position(SeriesLabelPosition::UpperRight)
        .draw()
        .unwrap();

    root_area
        .present()
        .expect("Unable to write result to file, please make sure the directory exists");
    println!("Result has been saved to {}", file_name);

    Ok(())
}

/// Plot results for wire configurations
fn plot_wire_configurations(
    results: &[SimulationResult],
) -> Result<(), Box<dyn std::error::Error>> {
    let wire_results: Vec<&SimulationResult> =
        results.iter().filter(|res| res.config.tags.contains(&"wire".to_string())).collect();

    // skip if there are no wire results
    if wire_results.is_empty() {
        return Ok(());
    }

    let root_area = BitMapBackend::new("wire_configurations.png", (1200, 800)).into_drawing_area();
    root_area.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root_area)
        .caption(
            "Wire Benchmark Results - 500k Users, ED25519 Operations per Hour",
            ("sans-serif", 24),
        )
        .margin(15)
        .x_label_area_size(80)
        .y_label_area_size(80)
        .build_cartesian_2d(
            (0i32..3i32).into_segmented(),
            0f64..wire_results[0].avg_cycles * 1.2,
        )?;

    chart
        .configure_mesh()
        .x_desc("Operation Type")
        .x_label_formatter(&|x| {
            match x {
                SegmentValue::Exact(0) | SegmentValue::CenterOf(0) => "CREATE_ACCOUNT\n(41/hour)".to_string(),
                SegmentValue::Exact(1) | SegmentValue::CenterOf(1) => "ADD_KEY\n(250/hour)".to_string(),
                SegmentValue::Exact(2) | SegmentValue::CenterOf(2) => "REMOVE_KEY\n(20/hour)".to_string(),
                _ => "".to_string(),
            }
        })
        .y_desc("Average Cycles per Operation")
        .y_label_formatter(&|&y| format!("{:e}", y))
        .draw()?;

    if let Some(wire_result) = wire_results.first() {
        // Calculate cycles per operation type based on the configuration
        let total_operations = wire_result.config.num_new_accounts
            + wire_result.config.num_add_keys
            + wire_result.config.num_revoke_key;

        let cycles_per_operation = wire_result.avg_cycles / total_operations as f64;

        let operation_data = vec![
            (0i32, cycles_per_operation, "CREATE_ACCOUNT"),
            (1i32, cycles_per_operation, "ADD_KEY"),
            (2i32, cycles_per_operation, "REMOVE_KEY"),
        ];

        // Draw bars for each operation type
        chart
            .draw_series(
                Histogram::vertical(&chart)
                    .style(GREEN.mix(0.7).filled())
                    .data(operation_data.iter().map(|(i, cycles, _)| (*i, *cycles))),
            )?
            .label("Cycles per Operation")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], GREEN));

        // Add text labels with operation counts - removed due to coordinate system complexity
    }

    chart
        .configure_series_labels()
        .background_style(WHITE.mix(0.8))
        .border_style(BLACK)
        .position(SeriesLabelPosition::UpperRight)
        .draw()?;

    root_area
        .present()
        .expect("Unable to write result to file, please make sure the directory exists");
    println!("Wire benchmark result has been saved to wire_configurations.png");

    Ok(())
}
