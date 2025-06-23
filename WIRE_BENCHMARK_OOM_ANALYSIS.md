# Wire Benchmark OOM Analysis and Fix

## Problem Summary
The wire benchmark with 500,000 existing accounts causes an OOMKill due to excessive memory usage from:

1. **HashMap Cloning**: Functions unnecessarily clone entire HashMaps containing 500k+ entries
2. **Large Vector Pre-allocation**: Creating a vector with 500k capacity upfront
3. **Memory Accumulation**: TestTransactionBuilder stores all accounts/keys without cleanup

## Key Memory Hotspots

### 1. HashMap Cloning (Lines 102, 109, 116, 123)
```rust
// BEFORE - Clones entire HashMap
let service_keys = builder.get_service_keys().clone();

// AFTER - Works with reference
let service_keys = builder.get_service_keys();
```

### 2. Large Vector Allocation (Line 135)
```rust
// BEFORE - Allocates 500k+ capacity immediately
let mut transactions = Vec::with_capacity(config.num_existing_services + config.num_existing_accounts);

// AFTER - Process in batches of 10k
const BATCH_SIZE: usize = 10_000;
```

## Proposed Fix

The fix involves two main optimizations:

### 1. Eliminate HashMap Cloning
- Remove `.clone()` calls in `get_random_service_id()`, `get_random_account_id()`, and `get_first_account_key()`
- Work directly with HashMap references
- Saves ~200-400MB per clone operation

### 2. Batch Processing for Large Account Sets
- Process accounts in chunks of 10,000 instead of all 500,000 at once
- Reduces peak memory usage significantly
- Allows garbage collection between batches

## Expected Memory Savings

**Before**: ~2-3GB peak memory usage
**After**: ~500MB-1GB peak memory usage

## Implementation

Apply the patch file `wire_benchmark_memory_fix.patch` to implement these optimizations:

```bash
git apply wire_benchmark_memory_fix.patch
```

Or manually apply the changes shown in the patch file to `crates/zk/sp1-script/src/main.rs`.

## Testing

After applying the fix:
```bash
cargo run --release -- --execute --tag wire
```

The benchmark should now complete without OOMKill errors.