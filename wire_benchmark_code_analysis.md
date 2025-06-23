# Wire Benchmark Code-Level Memory Analysis

## Critical Memory Allocations by Code Location

### 1. TestTransactionBuilder Memory Usage

**Location**: `crates/common/src/test_transaction_builder.rs`

```rust
pub struct TestTransactionBuilder {
    accounts: HashMap<String, Account>,          // O(n) where n = 500k for wire
    service_keys: HashMap<String, SigningKey>,   // O(s) where s = service count
    account_keys: HashMap<String, Vec<SigningKey>>, // O(n*k) where k = keys per account
}
```

**Memory Pattern**:
- Never deallocates during benchmark run
- Grows linearly with operations
- Each `commit()` adds to these structures

### 2. Batch Creation Memory Spikes

**Location**: `crates/zk/sp1-script/src/main.rs:129-163`

```rust
fn create_preparation_batch(
    builder: &mut TestTransactionBuilder,
    tree: &mut KeyDirectoryTree<MockTreeStore>,
    config: &SimulationConfig,
) -> Batch {
    let mut transactions = 
        Vec::with_capacity(config.num_existing_services + config.num_existing_accounts);
    // Wire: capacity = 1 + 500,000 = 500,001
```

**Critical allocation**: Single vector holding 500k transactions before processing

### 3. Tree Processing Memory Growth

**Location**: `crates/tree/src/snarkable_tree.rs:42-89`

```rust
fn process_batch(&mut self, transactions: Vec<Transaction>) -> Result<Batch> {
    let mut services = HashSet::new();
    let mut proofs = Vec::new();
    
    for transaction in transactions {
        // Each iteration:
        // 1. Processes transaction
        // 2. Creates proof (InsertProof or UpdateProof)
        // 3. Stores in proofs vector
        proofs.push(proof)
    }
    
    // Additional HashMap for service proofs
    let mut batch = Batch::init(prev_commitment, current_commitment, proofs);
    
    for service in services {
        // Fetches and stores ServiceProof for each unique service
        batch.service_proofs.insert(service.clone(), service_proof);
    }
}
```

### 4. Proof Structure Memory Overhead

**Location**: `crates/tree/src/proofs.rs`

```rust
pub struct InsertProof {
    pub non_membership_proof: MerkleProof,
    pub new_root: Digest,
    pub membership_proof: SparseMerkleProof<TreeHasher>,
    pub tx: Transaction,  // Full transaction copy
}

pub struct UpdateProof {
    pub old_root: Digest,
    pub new_root: Digest,
    pub key: KeyHash,
    pub old_account: Account,  // Full account copy
    pub tx: Transaction,        // Full transaction copy
    pub inclusion_proof: SparseMerkleProof<TreeHasher>,
    pub update_proof: UpdateMerkleProof<TreeHasher>,
}
```

**Memory Impact**: Each proof contains full copies of accounts and transactions

### 5. JMT Tree Operations

**Location**: `crates/tree/src/key_directory_tree.rs`

```rust
impl<S> KeyDirectoryTree<S> {
    pub(crate) fn queue_batch(&mut self, batch: TreeUpdateBatch) {
        match self.pending_batch {
            Some(ref mut pending_batch) => pending_batch.merge(batch.node_batch),
            None => self.pending_batch = Some(batch.node_batch),
        }
    }
}
```

**Pattern**: Accumulates all node changes in memory before writing

### 6. Random Access Patterns

**Location**: `crates/zk/sp1-script/src/main.rs:101-127`

```rust
fn get_random_service_id(rng: &mut impl Rng, builder: &TestTransactionBuilder) -> String {
    let service_keys = builder.get_service_keys().clone();  // CLONE of entire HashMap
    let service_id = service_keys.keys().nth(rng.gen_range(0..service_keys.len())).unwrap();
    service_id.to_string()
}

fn get_random_account_id(rng: &mut impl Rng, builder: &TestTransactionBuilder) -> String {
    let account_keys = builder.get_account_keys().clone();  // CLONE of entire HashMap
    let account_id = account_keys.keys().nth(rng.gen_range(0..account_keys.len())).unwrap();
    account_id.to_string()
}
```

**Issue**: Clones entire HashMaps for random selection

### 7. Account Serialization

**Location**: Throughout tree operations

```rust
// In insert() method
let serialized_account = account.encode_to_bytes()?;

// In update() method  
let old_account = Account::decode_from_bytes(&old_serialized_account)?;
let serialized_value = new_account.encode_to_bytes()?;
```

**Pattern**: Frequent serialization/deserialization creates temporary allocations

## Memory Allocation Timeline

1. **Startup**: TestTransactionBuilder initialized (empty HashMaps)
2. **Preparation Phase**: 
   - 500k account allocations
   - 500k transaction creations
   - Tree batch processing
3. **Benchmark Phase**:
   - 311 new transactions
   - 311 proof generations
   - Tree updates accumulation
4. **No Cleanup**: All data remains in memory

## Specific Wire Benchmark Numbers

- **Existing accounts**: 500,000
- **Operations per batch**: 311 (41 + 250 + 20)
- **Estimated memory per account**: ~200-400 bytes
- **Estimated memory per proof**: ~1-2 KB
- **Total baseline memory**: ~100-200 MB for accounts alone

## Key Findings

1. **HashMap Cloning**: Random selection functions clone entire HashMaps
2. **No Streaming**: All 500k accounts processed in single batch
3. **Proof Overhead**: Each proof contains full transaction/account copies
4. **Tree Batching**: All updates accumulated before write
5. **No Memory Reuse**: New allocations for each operation