# Jellyfish Merkle Proofs

Jellyfish Merkle Trees (JMT) are designed to support efficient membership and non-membership proofs, similar to Indexed Merkle Trees from Verdict. However, the proof format and verification process are optimized for better performance and smaller proof sizes.

## Proof Format

JMT uses a simplified proof format that can represent both inclusion and exclusion proofs. The proof structure is as follows:

```rust
struct Leaf {
    HashValue address;
    HashValue value_hash;
};

struct Proof {
    Leaf leaf;
    Vec<HashValue> siblings;
};
```

This format allows for three types of proofs:

1. Proof of Inclusion
2. Proof of Exclusion (with another leaf)
3. Proof of Exclusion (with an empty node)

## Proof of Inclusion

A proof of inclusion in JMT is similar to traditional Merkle proofs but takes advantage of the tree's structure to reduce the proof size. When proving the existence of a node, the proof includes:

1. The leaf node containing the key and value hash
2. A list of sibling hashes along the path from the leaf to the root

The verification process involves:

1. Verifying that the provided leaf matches the queried key
2. Reconstructing the path from the leaf to the root using the provided siblings
3. Comparing the calculated root hash with the known root hash

## Proof of Exclusion

JMT supports two types of exclusion proofs:

1. Exclusion proof with another leaf:

   - Proves that a different leaf exists with a key that shares a common prefix with the queried key
   - The proof includes the existing leaf and the necessary sibling hashes

2. Exclusion proof with an empty node:

   - Proves that an empty node exists on the path to where the queried key would be
   - The proof includes the sibling hashes up to the empty node

The verification process for exclusion proofs involves:

1. Checking if the provided leaf (if any) has a different key than the queried key
2. Verifying that the common prefix length is correct
3. Reconstructing the path to the root and comparing the calculated root hash with the known root hash

## Efficiency Improvements

Jellyfish Merkle Trees offer several efficiency improvements over traditional Merkle trees:

1. Smaller proof sizes: By collapsing consecutive levels of empty siblings, JMT proofs are more compact.
2. Faster verification: The simplified proof format allows for more efficient proof verification.
3. Optimized for sparse trees: JMT is particularly efficient for sparse trees, which is common in many applications.
4. Optimized for LSM backed storage: features version-based key that circumvents heavy I/O brought about by the randomness of a pervading hash-based key.

## Versioning

JMT incorporates versioning, which allows for efficient updates and historical queries. Each update to the tree creates a new version, and proofs can be generated for any specific version of the tree.

In summary, Jellyfish Merkle Trees provide an optimized solution for generating and verifying both membership and non-membership proofs, with improvements in proof size and verification efficiency compared to traditional and indexed Merkle trees.

## Considerations for Zero-Knowledge Proofs

While JMTs offer significant advantages in terms of efficiency and proof size compared to IMTs, there are important considerations when using JMT in the context of zero-knowledge proofs:

1. Variable Proof Size: JMT produces shorter proofs compared to IMT, which has a constant proof size. JMT proofs have $\Theta(\log(\text{number of existent leaves}))$ sibling digests, compared to the constant size of $n-1$ for the IMT.
2. Challenges with handwritten SNARKs: Implementing JMT in handwritten SNARKs can be challenging. The variable proof size of JMT requires manual handling to keep the proof size constant within the SNARK circuit, which is complex and extremely inefficient.
3. Advantages of zkVMs: When using a zkVM, it becomes possible to leverage the shorter proofs of JMT more effectively. zkVMs can handle the variable-sized proofs without the need for manual size normalization.
