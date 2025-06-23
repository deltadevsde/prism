# Wire Benchmark Memory Analysis

## Executive Summary

The wire benchmark simulates a production workload with 500,000 existing users and performs operations typical of the Wire messaging platform. This analysis identifies the key memory-intensive operations and data structures in the execution path.

## Key Memory-Intensive Areas

### 1. Large Data Structure Allocations

#### TestTransactionBuilder (main.rs)
- **HashMap Storage**: Maintains three large HashMaps that grow with user count:
  ```rust
  accounts: HashMap<String, Account>          // 500k entries for wire benchmark
  service_keys: HashMap<String, SigningKey>   // Service count entries
  account_keys: HashMap<String, Vec<SigningKey>> // 500k+ entries
  ```
- **Memory Impact**: With 500k users, these HashMaps alone consume significant memory
- **Growth Pattern**: Linear with user count, no deallocation during benchmark

#### Batch Processing (proofs.rs)
- **Batch Structure**:
  ```rust
  pub struct Batch {
      pub service_proofs: HashMap<String, ServiceProof>,
      pub proofs: Vec<Proof>,
  }
  ```
- **Memory Impact**: 
  - Wire benchmark creates batches with 41 CreateAccount + 250 AddKey + 20 RevokeKey operations
  - Each proof contains merkle proof data with siblings and tree nodes
  - Service proofs HashMap grows with each unique service

### 2. Tree Operations

#### KeyDirectoryTree Storage
- Uses `MockTreeStore` from JMT library (in-memory implementation)
- **NodeBatch accumulation**: 
  ```rust
  pending_batch: Option<NodeBatch>
  ```
- Batches tree updates before writing, accumulating node changes in memory

#### Merkle Proof Generation
- Each operation generates either `InsertProof` or `UpdateProof`
- **Proof Components**:
  - SparseMerkleProof with sibling nodes (tree depth = log(n) siblings)
  - UpdateMerkleProof for modifications
  - Account serialization for each proof

### 3. Transaction Generation

#### Key Generation (TestTransactionBuilder)
- Creates new `SigningKey` instances for:
  - 41 new accounts per batch
  - 250 key additions per batch
- Each key generation involves cryptographic operations and memory allocation

#### Account Data
- **Account Structure**:
  ```rust
  pub struct Account {
      id: String,
      nonce: u64,
      valid_keys: Vec<VerifyingKey>,
      signed_data: Vec<SignedData>,
      service_challenge: Option<ServiceChallenge>,
  }
  ```
- With 500k accounts, even small per-account overhead becomes significant

### 4. Specific Wire Benchmark Configuration

```rust
SimulationConfig {
    num_existing_accounts: 500_000,  // Major memory consumer
    num_new_accounts: 41,            // Per hour
    num_add_keys: 250,               // Per hour  
    num_revoke_key: 20,              // Per hour
}
```

### 5. Memory Hotspots in Execution Path

1. **Initial State Creation** (`create_preparation_batch`):
   - Allocates 500k accounts
   - Generates cryptographic keys for each
   - Builds transaction vector with 500k+ entries

2. **Benchmark Batch Creation** (`create_benchmark_batch`):
   - Random account selection from 500k pool
   - Transaction vector allocation (311 transactions)
   - Proof generation for each transaction

3. **Tree Processing** (`process_batch`):
   - Iterates through all transactions
   - Generates merkle proofs
   - Accumulates node updates in memory

4. **Proof Structures**:
   - Each proof contains full merkle path
   - Serialized account data
   - Cryptographic signatures

## Optimization Opportunities

1. **Streaming Processing**: Process accounts in chunks rather than loading all 500k at once
2. **Key Storage**: Use more memory-efficient key representations
3. **Proof Batching**: Aggregate proofs to reduce per-proof overhead
4. **Tree Store**: Implement disk-backed storage instead of pure in-memory
5. **Account Indexing**: Use more efficient indexing structures for random access
6. **Lazy Loading**: Load accounts on-demand rather than preloading all

## Memory Usage Estimation

For the wire benchmark with 500k users:
- TestTransactionBuilder HashMaps: ~100-200 MB (depending on key sizes)
- Account structures: ~50-100 MB 
- Transaction vectors: ~10-20 MB per batch
- Merkle proofs: ~5-10 MB per batch
- Tree node storage: Growing with operations

Total estimated memory usage: 200-500 MB baseline + growth during execution