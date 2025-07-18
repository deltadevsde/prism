use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use tempfile::TempDir;

use jmt::{
    KeyHash, OwnedValue, Version,
    storage::{TreeReader, TreeWriter},
};
use prism_common::test_transaction_builder::TestTransactionBuilder;
use prism_keys::CryptoAlgorithm;
use prism_tree::snarkable_tree::SnarkableTree;
// Import your database implementations
use prism_tree::{hasher::TreeHasher, key_directory_tree::KeyDirectoryTree};

use prism_storage::{
    Database,
    sled::{SledConfig, SledConnection},
};

#[cfg(feature = "rocksdb")]
use prism_storage::rocksdb::{RocksDBConfig, RocksDBConnection};

// Benchmark helper functions
#[cfg(feature = "rocksdb")]
fn setup_rocksdb() -> (TempDir, RocksDBConnection) {
    let temp_dir = TempDir::new().unwrap();
    let cfg = RocksDBConfig::new(temp_dir.path().to_str().unwrap());
    let db = RocksDBConnection::new(&cfg).unwrap();
    (temp_dir, db)
}

fn setup_sled() -> (TempDir, SledConnection) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_sled");
    let cfg = SledConfig::new(db_path.to_str().unwrap());
    let db = SledConnection::new(&cfg).unwrap();
    (temp_dir, db)
}

// Benchmark database operations directly
fn bench_direct_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("direct_operations");

    // Test commitment operations
    #[cfg(feature = "rocksdb")]
    group.bench_function("rocksdb_commitment_write", |b| {
        let (_temp_dir, db) = setup_rocksdb();
        b.iter(|| {
            for i in 0..100 {
                let epoch = black_box(i);
                let commitment = prism_common::digest::Digest([i as u8; 32]);
                db.set_commitment(&epoch, &commitment).unwrap();
            }
        });
    });

    group.bench_function("sled_commitment_write", |b| {
        let (_temp_dir, db) = setup_sled();
        b.iter(|| {
            for i in 0..100 {
                let epoch = black_box(i);
                let commitment = prism_common::digest::Digest([i as u8; 32]);
                db.set_commitment(&epoch, &commitment).unwrap();
            }
        });
    });

    #[cfg(feature = "rocksdb")]
    group.bench_function("rocksdb_commitment_read", |b| {
        let (_temp_dir, db) = setup_rocksdb();
        // Setup data
        for i in 0..100 {
            let commitment = prism_common::digest::Digest([i as u8; 32]);
            db.set_commitment(&i, &commitment).unwrap();
        }

        b.iter(|| {
            for i in 0..100 {
                let epoch = black_box(i);
                let _ = db.get_commitment(&epoch).unwrap();
            }
        });
    });

    group.bench_function("sled_commitment_read", |b| {
        let (_temp_dir, db) = setup_sled();
        // Setup data
        for i in 0..100 {
            let commitment = prism_common::digest::Digest([i as u8; 32]);
            db.set_commitment(&i, &commitment).unwrap();
        }

        b.iter(|| {
            for i in 0..100 {
                let epoch = black_box(i);
                let _ = db.get_commitment(&epoch).unwrap();
            }
        });
    });

    group.finish();
}

// Benchmark JMT operations
fn bench_jmt_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("jmt_operations");

    group.bench_function("sled_node_batch_write", |b| {
        let (_temp_dir, db) = setup_sled();
        b.iter(|| {
            let mut batch = jmt::storage::NodeBatch::default();
            for i in 0..50 {
                let key_hash = KeyHash([i as u8; 32]);
                let value: OwnedValue = vec![i as u8; 100];
                batch.insert_value(black_box(i as Version), key_hash, value);
            }
            db.write_node_batch(&batch).unwrap();
        });
    });

    // Test node batch operations
    #[cfg(feature = "rocksdb")]
    group.bench_function("rocksdb_node_batch_write", |b| {
        let (_temp_dir, db) = setup_rocksdb();
        b.iter(|| {
            let mut batch = jmt::storage::NodeBatch::default();
            for i in 0..50 {
                let key_hash = KeyHash([i as u8; 32]);
                let value: OwnedValue = vec![i as u8; 100];
                batch.insert_value(black_box(i as Version), key_hash, value);
            }
            db.write_node_batch(&batch).unwrap();
        });
    });

    #[cfg(feature = "rocksdb")]
    group.bench_function("rocksdb_value_read", |b| {
        let (_temp_dir, db) = setup_rocksdb();
        // Setup data
        let mut batch = jmt::storage::NodeBatch::default();
        for i in 0..100 {
            let key_hash = KeyHash([i as u8; 32]);
            let value: OwnedValue = vec![i as u8; 100];
            batch.insert_value(i as Version, key_hash, value);
        }
        db.write_node_batch(&batch).unwrap();

        b.iter(|| {
            for i in 0..100 {
                let key_hash = KeyHash([i as u8; 32]);
                let version = black_box(i as Version);
                let _ = db.get_value_option(version, key_hash).unwrap();
            }
        });
    });

    group.bench_function("sled_value_read", |b| {
        let (_temp_dir, db) = setup_sled();
        // Setup data
        let mut batch = jmt::storage::NodeBatch::default();
        for i in 0..100 {
            let key_hash = KeyHash([i as u8; 32]);
            let value: OwnedValue = vec![i as u8; 100];
            batch.insert_value(i as Version, key_hash, value);
        }
        db.write_node_batch(&batch).unwrap();

        b.iter(|| {
            for i in 0..100 {
                let key_hash = KeyHash([i as u8; 32]);
                let version = black_box(i as Version);
                let _ = db.get_value_option(version, key_hash).unwrap();
            }
        });
    });

    group.finish();
}

// Benchmark KeyDirectoryTree operations
fn bench_key_directory_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_directory_tree");

    // Test service registration and account creation
    #[cfg(feature = "rocksdb")]
    group.bench_function("rocksdb_service_and_account_creation", |b| {
        b.iter_with_setup(
            || {
                let (_temp_dir, db) = setup_rocksdb();
                let tree = KeyDirectoryTree::new(Arc::new(db));
                let tx_builder = TestTransactionBuilder::new();
                (tree, tx_builder)
            },
            |(mut tree, mut tx_builder)| {
                let service_tx = tx_builder
                    .register_service_with_random_keys(CryptoAlgorithm::Ed25519, "service_1")
                    .commit();
                tree.process_transaction(service_tx).unwrap();

                for i in 0..10 {
                    let account_name = format!("acc_{}", i);
                    let account_tx = tx_builder
                        .create_account_with_random_key_signed(
                            CryptoAlgorithm::Ed25519,
                            &account_name,
                            "service_1",
                        )
                        .commit();
                    tree.process_transaction(black_box(account_tx)).unwrap();
                }
            },
        );
    });

    group.bench_function("sled_service_and_account_creation", |b| {
        b.iter_with_setup(
            || {
                let (_temp_dir, db) = setup_sled();
                let tree = KeyDirectoryTree::new(Arc::new(db));
                let tx_builder = TestTransactionBuilder::new();
                (tree, tx_builder)
            },
            |(mut tree, mut tx_builder)| {
                let service_tx = tx_builder
                    .register_service_with_random_keys(CryptoAlgorithm::Ed25519, "service_1")
                    .commit();
                tree.process_transaction(service_tx).unwrap();

                for i in 0..10 {
                    let account_name = format!("acc_{}", i);
                    let account_tx = tx_builder
                        .create_account_with_random_key_signed(
                            CryptoAlgorithm::Ed25519,
                            &account_name,
                            "service_1",
                        )
                        .commit();
                    tree.process_transaction(black_box(account_tx)).unwrap();
                }
            },
        );
    });

    group.finish();
}

// Benchmark key updates and data operations
fn bench_update_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_operations");

    #[cfg(feature = "rocksdb")]
    group.bench_function("rocksdb_key_updates", |b| {
        b.iter_with_setup(
            || {
                let (_temp_dir, db) = setup_rocksdb();
                let mut tree = KeyDirectoryTree::new(Arc::new(db));
                let mut tx_builder = TestTransactionBuilder::new();

                // Setup initial data
                let service_tx = tx_builder
                    .register_service_with_random_keys(CryptoAlgorithm::Ed25519, "service_1")
                    .commit();
                tree.process_transaction(service_tx).unwrap();

                for i in 0..10 {
                    let account_name = format!("acc_{}", i);
                    let account_tx = tx_builder
                        .create_account_with_random_key_signed(
                            CryptoAlgorithm::Ed25519,
                            &account_name,
                            "service_1",
                        )
                        .commit();
                    tree.process_transaction(account_tx).unwrap();
                }

                (tree, tx_builder)
            },
            |(mut tree, mut tx_builder)| {
                for i in 0..10 {
                    let account_name = format!("acc_{}", i);
                    let key_tx = tx_builder
                        .add_random_key_verified_with_root(CryptoAlgorithm::Ed25519, &account_name)
                        .commit();
                    tree.process_transaction(black_box(key_tx)).unwrap();
                }
            },
        );
    });

    group.bench_function("sled_key_updates", |b| {
        b.iter_with_setup(
            || {
                let (_temp_dir, db) = setup_sled();
                let mut tree = KeyDirectoryTree::new(Arc::new(db));
                let mut tx_builder = TestTransactionBuilder::new();

                // Setup initial data
                let service_tx = tx_builder
                    .register_service_with_random_keys(CryptoAlgorithm::Ed25519, "service_1")
                    .commit();
                tree.process_transaction(service_tx).unwrap();

                for i in 0..10 {
                    let account_name = format!("acc_{}", i);
                    let account_tx = tx_builder
                        .create_account_with_random_key_signed(
                            CryptoAlgorithm::Ed25519,
                            &account_name,
                            "service_1",
                        )
                        .commit();
                    tree.process_transaction(account_tx).unwrap();
                }

                (tree, tx_builder)
            },
            |(mut tree, mut tx_builder)| {
                for i in 0..10 {
                    let account_name = format!("acc_{}", i);
                    let key_tx = tx_builder
                        .add_random_key_verified_with_root(CryptoAlgorithm::Ed25519, &account_name)
                        .commit();
                    tree.process_transaction(black_box(key_tx)).unwrap();
                }
            },
        );
    });

    group.finish();
}

// Benchmark data operations
fn bench_data_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_operations");

    #[cfg(feature = "rocksdb")]
    group.bench_function("rocksdb_data_operations", |b| {
        b.iter_with_setup(
            || {
                let (_temp_dir, db) = setup_rocksdb();
                let mut tree = KeyDirectoryTree::new(Arc::new(db));
                let mut tx_builder = TestTransactionBuilder::new();

                // Setup initial data
                let service_tx = tx_builder
                    .register_service_with_random_keys(CryptoAlgorithm::Ed25519, "service_1")
                    .commit();
                tree.process_transaction(service_tx).unwrap();

                let account_tx = tx_builder
                    .create_account_with_random_key_signed(
                        CryptoAlgorithm::Ed25519,
                        "acc_1",
                        "service_1",
                    )
                    .commit();
                tree.process_transaction(account_tx).unwrap();

                (tree, tx_builder)
            },
            |(mut tree, mut tx_builder)| {
                for i in 0..10 {
                    let data = format!("test data {}", i).into_bytes();
                    let data_tx = tx_builder
                        .add_internally_signed_data_verified_with_root("acc_1", data)
                        .commit();
                    tree.process_transaction(black_box(data_tx)).unwrap();
                }
            },
        );
    });

    group.bench_function("sled_data_operations", |b| {
        b.iter_with_setup(
            || {
                let (_temp_dir, db) = setup_sled();
                let mut tree = KeyDirectoryTree::new(Arc::new(db));
                let mut tx_builder = TestTransactionBuilder::new();

                // Setup initial data
                let service_tx = tx_builder
                    .register_service_with_random_keys(CryptoAlgorithm::Ed25519, "service_1")
                    .commit();
                tree.process_transaction(service_tx).unwrap();

                let account_tx = tx_builder
                    .create_account_with_random_key_signed(
                        CryptoAlgorithm::Ed25519,
                        "acc_1",
                        "service_1",
                    )
                    .commit();
                tree.process_transaction(account_tx).unwrap();

                (tree, tx_builder)
            },
            |(mut tree, mut tx_builder)| {
                for i in 0..10 {
                    let data = format!("test data {}", i).into_bytes();
                    let data_tx = tx_builder
                        .add_internally_signed_data_verified_with_root("acc_1", data)
                        .commit();
                    tree.process_transaction(black_box(data_tx)).unwrap();
                }
            },
        );
    });

    group.finish();
}

// Benchmark read operations
fn bench_read_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_operations");

    #[cfg(feature = "rocksdb")]
    group.bench_function("rocksdb_batch_reads", |b| {
        let (_temp_dir, db) = setup_rocksdb();
        let mut tree = KeyDirectoryTree::new(Arc::new(db));
        let mut tx_builder = TestTransactionBuilder::new();

        // Setup initial data
        let service_tx = tx_builder
            .register_service_with_random_keys(CryptoAlgorithm::Ed25519, "service_1")
            .commit();
        tree.process_transaction(service_tx).unwrap();

        for i in 0..100 {
            let account_name = format!("acc_{}", i);
            let account_tx = tx_builder
                .create_account_with_random_key_signed(
                    CryptoAlgorithm::Ed25519,
                    &account_name,
                    "service_1",
                )
                .commit();
            tree.process_transaction(account_tx).unwrap();
        }

        b.iter(|| {
            for i in 0..100 {
                let account_name = format!("acc_{}", i);
                let key_hash = KeyHash::with::<TreeHasher>(&account_name);
                let _ = tree.get(black_box(key_hash)).unwrap();
            }
        });
    });

    group.bench_function("sled_batch_reads", |b| {
        let (_temp_dir, db) = setup_sled();
        let mut tree = KeyDirectoryTree::new(Arc::new(db));
        let mut tx_builder = TestTransactionBuilder::new();

        // Setup initial data
        let service_tx = tx_builder
            .register_service_with_random_keys(CryptoAlgorithm::Ed25519, "service_1")
            .commit();
        tree.process_transaction(service_tx).unwrap();

        for i in 0..100 {
            let account_name = format!("acc_{}", i);
            let account_tx = tx_builder
                .create_account_with_random_key_signed(
                    CryptoAlgorithm::Ed25519,
                    &account_name,
                    "service_1",
                )
                .commit();
            tree.process_transaction(account_tx).unwrap();
        }

        b.iter(|| {
            for i in 0..100 {
                let account_name = format!("acc_{}", i);
                let key_hash = KeyHash::with::<TreeHasher>(&account_name);
                let _ = tree.get(black_box(key_hash)).unwrap();
            }
        });
    });

    group.finish();
}

// Benchmark different payload sizes
fn bench_payload_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload_sizes");

    for size in [100, 1000, 10000, 100000].iter() {
        #[cfg(feature = "rocksdb")]
        group.bench_with_input(
            BenchmarkId::new("rocksdb_large_data", size),
            size,
            |b, &size| {
                b.iter_with_setup(
                    || {
                        let (_temp_dir, db) = setup_rocksdb();
                        let mut tree = KeyDirectoryTree::new(Arc::new(db));
                        let mut tx_builder = TestTransactionBuilder::new();

                        // Setup initial data
                        let service_tx = tx_builder
                            .register_service_with_random_keys(
                                CryptoAlgorithm::Ed25519,
                                "service_1",
                            )
                            .commit();
                        tree.process_transaction(service_tx).unwrap();

                        let account_tx = tx_builder
                            .create_account_with_random_key_signed(
                                CryptoAlgorithm::Ed25519,
                                "acc_1",
                                "service_1",
                            )
                            .commit();
                        tree.process_transaction(account_tx).unwrap();

                        (tree, tx_builder)
                    },
                    |(mut tree, mut tx_builder)| {
                        let large_data = vec![0u8; size];
                        let data_tx = tx_builder
                            .add_internally_signed_data_verified_with_root("acc_1", large_data)
                            .commit();
                        tree.process_transaction(black_box(data_tx)).unwrap();
                    },
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sled_large_data", size),
            size,
            |b, &size| {
                b.iter_with_setup(
                    || {
                        let (_temp_dir, db) = setup_sled();
                        let mut tree = KeyDirectoryTree::new(Arc::new(db));
                        let mut tx_builder = TestTransactionBuilder::new();

                        // Setup initial data
                        let service_tx = tx_builder
                            .register_service_with_random_keys(
                                CryptoAlgorithm::Ed25519,
                                "service_1",
                            )
                            .commit();
                        tree.process_transaction(service_tx).unwrap();

                        let account_tx = tx_builder
                            .create_account_with_random_key_signed(
                                CryptoAlgorithm::Ed25519,
                                "acc_1",
                                "service_1",
                            )
                            .commit();
                        tree.process_transaction(account_tx).unwrap();

                        (tree, tx_builder)
                    },
                    |(mut tree, mut tx_builder)| {
                        let large_data = vec![0u8; size];
                        let data_tx = tx_builder
                            .add_internally_signed_data_verified_with_root("acc_1", large_data)
                            .commit();
                        tree.process_transaction(black_box(data_tx)).unwrap();
                    },
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_direct_operations,
    bench_jmt_operations,
    bench_key_directory_tree,
    bench_update_operations,
    bench_data_operations,
    bench_read_operations,
    bench_payload_sizes
);

criterion_main!(benches);
