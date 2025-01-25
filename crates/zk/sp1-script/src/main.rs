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
use jmt::mock::MockTreeStore;
use prism_common::transaction_builder::TransactionBuilder;
use prism_keys::SigningKey;
use prism_tree::{
    key_directory_tree::KeyDirectoryTree, proofs::Batch, snarkable_tree::SnarkableTree,
};
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use sp1_sdk::{ProverClient, SP1Stdin};
use std::sync::Arc;
use tokio::{self, task};
use prism_keys::CryptoAlgorithm;

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

    #[clap(long)]
    tag: Option<String>,
}

#[derive(Debug, Clone)]
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
            algorithms: vec![CryptoAlgorithm::Ed25519, CryptoAlgorithm::Secp256k1, CryptoAlgorithm::Secp256r1],
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

#[derive(Debug)]
struct SimulationResult {
    config: SimulationConfig,
    min_cycles: u64,
    max_cycles: u64,
    avg_cycles: f64,
    median_cycles: u64,
    std_dev: f64,
    std_dev_percentage: f64,
}

fn get_random_service_id(rng: &mut impl Rng, builder: &TransactionBuilder) -> String {
    let service_keys = builder.get_service_keys().clone();
    let service_id = service_keys.keys().nth(rng.gen_range(0..service_keys.len())).unwrap();
    service_id.to_string()
}

fn get_service_key(builder: &TransactionBuilder, service_id: &str) -> SigningKey {
    let service_keys = builder.get_service_keys().clone();
    let service_key = service_keys.get(service_id).unwrap();
    service_key.clone()
}

fn get_random_account_id(rng: &mut impl Rng, builder: &TransactionBuilder) -> String {
    let account_keys = builder.get_account_keys().clone();
    let account_id = account_keys.keys().nth(rng.gen_range(0..account_keys.len())).unwrap();
    account_id.to_string()
}

fn get_first_account_key(builder: &TransactionBuilder, account_id: &str) -> SigningKey {
    let account_keys_map = builder.get_account_keys().clone();
    let account_keys = account_keys_map.get(account_id).unwrap();
    account_keys.first().unwrap().clone()
}

fn create_preparation_batch(
    builder: &mut TransactionBuilder,
    tree: &mut KeyDirectoryTree<MockTreeStore>,
    config: &SimulationConfig,
) -> Batch {
    let mut transactions = Vec::with_capacity(config.num_existing_services + config.num_existing_accounts);

    let mut rng = rand::thread_rng();

    for i in 0..config.num_existing_services {
        let algorithm = config.algorithms[i % config.algorithms.len()];
        let service_id = format!(
            "service_{}",
            hex::encode(Sha256::digest(algorithm.to_string().as_bytes()))
        );
        let transaction =
            builder.register_service_with_random_keys(algorithm, &service_id).commit();
        transactions.push(transaction);
    }

    for i in 0..config.num_existing_accounts {
        let algorithm = config.algorithms[i % config.algorithms.len()];
        let account_id = format!("account_{}", hex::encode(Sha256::digest(i.to_le_bytes())));
        let service_id = get_random_service_id(&mut rng, builder);
        let transaction = builder
            .create_account_with_random_key_signed(algorithm, &account_id, &service_id)
            .commit();
        transactions.push(transaction);
    }

    tree.process_batch(transactions).unwrap()
}

fn create_benchmark_batch(
    builder: &mut TransactionBuilder,
    tree: &mut KeyDirectoryTree<MockTreeStore>,
    config: &SimulationConfig,
) -> Batch {
    let mut transactions = Vec::new();

    let mut rng = rand::thread_rng();

    // Create new services
    let service_keys = builder.get_service_keys().clone();
    for i in 0..config.num_new_services {
        let algorithm = config.algorithms[i % config.algorithms.len()];
        let service_id = format!(
            "service_{}",
            hex::encode(Sha256::digest((i + service_keys.len()).to_le_bytes()))
        );
        let transaction =
            builder.register_service_with_random_keys(algorithm, &service_id).commit();
        transactions.push(transaction);
    }

    // Create new accounts
    let account_keys = builder.get_account_keys().clone();
    for i in 0..config.num_new_accounts {
        let algorithm = config.algorithms[i % config.algorithms.len()];
        let account_id = format!(
            "account_{}",
            hex::encode(Sha256::digest((i + account_keys.len()).to_le_bytes()))
        );
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

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    if args.execute {
        let num_simulations = 100; // Number of times to run each configuration

        // Define default configuration
        let default_config = SimulationConfig::default();

        // Define different configurations for num_accounts and num_operations
        let configurations = vec![
            SimulationConfig {
                tags: vec!["green".to_string()],
                num_simulations: num_simulations,
                num_existing_accounts: 1,
                ..default_config.clone()
            },
            SimulationConfig {
                tags: vec!["green".to_string()],
                num_simulations: num_simulations,
                num_existing_accounts: 100,
                ..default_config.clone()
            },
            SimulationConfig {
                tags: vec!["green".to_string()],
                num_simulations: num_simulations,
                num_existing_accounts: 1000,
                ..default_config.clone()
            },
            SimulationConfig {
                tags: vec!["green".to_string()],
                num_simulations: num_simulations,
                num_existing_accounts: 5000,
                ..default_config.clone()
            },
            SimulationConfig {
                tags: vec!["green".to_string()],
                num_simulations: num_simulations,
                num_existing_accounts: 10000,
                ..default_config.clone()
            },
            // SimulationConfig {
            //     tags: vec!["yellow".to_string()],
            //     num_simulations: num_simulations,
            //     algorithms: vec![CryptoAlgorithm::Ed25519],
            //     num_existing_services: 1,
            //     ..default_config.clone()
            // },
            // SimulationConfig {
            //     tags: vec!["yellow".to_string()],
            //     num_simulations: num_simulations,
            //     algorithms: vec![CryptoAlgorithm::Secp256k1],
            //     num_existing_services: 1,
            //     ..default_config.clone()
            // },
            // SimulationConfig {
            //     tags: vec!["yellow".to_string()],
            //     num_simulations: num_simulations,
            //     algorithms: vec![CryptoAlgorithm::Secp256r1],
            //     num_existing_services: 1,
            //     ..default_config.clone()
            // },
            // Add more configurations as needed
        ];

        let mut results = Vec::new(); // Store results for all configurations

        for config in &configurations {
            if let Some(ref tag) = args.tag {
                if !config.tags.contains(tag) {
                    continue;
                }
            }

            println!("Testing configuration: {:?}", config);

            let mut tasks = Vec::new();

            for _ in 0..num_simulations {
                let config = config.clone();

                tasks.push(task::spawn(async move {
                    // Setup the prover client.
                    let client = ProverClient::from_env();

                    let mut builder = TransactionBuilder::new();
                    let mut tree = KeyDirectoryTree::new(Arc::new(MockTreeStore::default()));

                    // Setup the inputs for each configuration.
                    let initial_batch = create_preparation_batch(
                        &mut builder,
                        &mut tree,
                        &config,
                    );

                    // Execute the initial batch to add accounts (only once per configuration)
                    let mut stdin = SP1Stdin::new();
                    stdin.write(&initial_batch);

                    // Create operations batch
                    let operations_batch = create_benchmark_batch(
                        &mut builder,
                        &mut tree,
                        &config,
                    );

                    // Reset stdin by creating a new instance and write the operations batch
                    let mut stdin = SP1Stdin::new();
                    stdin.write(&operations_batch);

                    // Execute the operations batch
                    let (_, report) = client.execute(PRISM_ELF, &stdin).run().unwrap();
                    println!("Operations batch executed successfully.");

                    // Record the number of cycles executed.
                    report.total_instruction_count()
                }));
            }

            let cycles_vec: Vec<u64> = futures::future::join_all(tasks)
                .await
                .into_iter()
                .map(|res| res.unwrap())
                .collect();

            // Calculate statistics
            let (min_cycles, max_cycles, avg_cycles, median_cycles, std_dev, std_dev_percentage) = {
                let min_cycles = *cycles_vec.iter().min().unwrap();
                let max_cycles = *cycles_vec.iter().max().unwrap();
                let avg_cycles = cycles_vec.iter().sum::<u64>() as f64 / num_simulations as f64;
                let median_cycles = {
                    let mut sorted = cycles_vec.clone();
                    sorted.sort();
                    sorted[num_simulations / 2]
                };
                let std_dev = {
                    let variance =
                        cycles_vec.iter().map(|&x| (x as f64 - avg_cycles).powi(2)).sum::<f64>()
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
            };

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

        println!("Running {} simulations for each configuration", num_simulations);

        // Print all results after all configurations have been run
        for result in results {
            println!("--------------------------------");
            println!("Results for configuration: {:?} which had {} runs", result.config, result.config.num_simulations);
            println!("Min: {}, Max: {}, Avg: {:.2}, Median: {}, Std dev: {:.2}, Std dev percentage: {:.2}%", result.min_cycles, result.max_cycles, result.avg_cycles, result.median_cycles, result.std_dev, result.std_dev_percentage);
        }
    } else {
        // // Setup the inputs for a single configuration for proof generation.
        // let mut stdin = SP1Stdin::new();
        // let operations_batch,  = create_operations_batch(&vec!["account_1".to_string()], 10);
        // stdin.write(&operations_batch);

        // // Setup the program for proving.
        // let (pk, vk) = client.setup(PRISM_ELF);

        // // Generate the proof
        // let proof = client
        //     .prove(&pk, &stdin)
        //     .groth16()
        //     .run()
        //     .expect("failed to generate proof");

        // println!("Successfully generated proof!");

        // // Verify the proof.
        // client.verify(&proof, &vk).expect("failed to verify proof");
        // println!("Successfully verified proof!");
    }
}
