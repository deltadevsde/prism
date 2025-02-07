# Prism Datastructures

## Accounts

In Prism, Accounts are the values stored in the leaves of the key directory.

```rust
/// Represents an account or service on prism, making up the values of our state
/// tree.
pub struct Account {
    /// The unique identifier for the account.
    id: String,

    /// The transaction nonce for the account.
    nonce: u64,

    /// The current set of valid keys for the account. Any of these keys can be
    /// used to sign transactions.
    valid_keys: Vec<VerifyingKey>,

    /// Arbitrary signed data associated with the account, used for bookkeeping
    /// externally signed data from keys that don't live on Prism.
    signed_data: Vec<SignedData>,

    /// The service challenge for the account, if it is a service.
    service_challenge: Option<ServiceChallenge>,
}

```

Users can register a unique ID in Prism using various [account sources](./labels.md). Any number of additional public keys can then be added, and keys that have already been added can be revoked. The prerequisite for adding new keys or revoking existing keys is that the operation has been signed with a private key associated with some unrevoked public key of that ID.

In addition to adding and revoking keys, we also support adding arbitrary data with the `AddData` and `SetData` operation. This data must either be signed by one of the user's own valid keys, or supplemented with an external key that applications can interpret themselves. This data is stored in the account and can be used for various purposes, such as storing metadata or other information.

## Jellyfish Merkle Trees

Prism uses [Jellyfish Merkle Trees](https://developers.diem.com/papers/jellyfish-merkle-tree/2021-01-14.pdf) (JMT) instead of indexed Merkle trees. JMTs are a space-and-computation-efficient sparse Merkle tree optimized for Log-Structured Merge-tree (LSM-tree) based key-value storage.

Key features of Jellyfish Merkle Trees include:

1. Version-based Node Key: JMT uses a version-based key schema, which facilitates version-based sharding, reduces compaction overhead in LSM-tree based storage engines, and results in smaller key sizes on average.

2. Simplified Structure: JMT has only two physical node types - Internal Node and Leaf Node.

3. Concise Proof Format: The number of sibling digests in a JMT proof is less on average than that of the same Addressable Radix Merkle Tree (ARMT) without optimizations, requiring less computation and space.

4. Efficient for Sparse Trees: JMT is particularly efficient for sparse trees, which is often the case in blockchain applications.

[More about Merkle trees](./crypto-intro/merkle-trees.md)

## Service Registration

Prism introduces a `REGISTER_SERVICE` operation that allows for creating novel account sources. You can read more about it [here](./labels.md).

## Account Creation

Prism introduces a `CREATE_ACCOUNT` operation that allows for decentralized account creation. This operation supports various account sources, not just email addresses. The process works as follows:

1. Users prove ownership of a resource (e.g., a social media account, email address) using services like [TLSNotary](https://tlsnotary.org/) or [zkEmail](https://prove.email/).
2. The proof is generated off-chain and then submitted as part of the `CREATE_ACCOUNT` operation.
3. The Prism protocol includes validity rules for each supported external protocol's proof system.
4. Full nodes verify the `CREATE_ACCOUNT` operation according to the corresponding proof system's ruleset before applying the state transition in the Jellyfish Merkle Tree.

This approach allows for:

- Addition of arbitrary account sources
- Decentralized account creation without relying on a single trusted entity
- Flexibility for applications to use various types of accounts for registration

> **Note**: The `CREATE_ACCOUNT` operation enhances the security and decentralization of the account creation process in Prism. It mitigates the risks associated with centralized account creation while allowing for diverse account sources.

The combination of append-only hashchains and Jellyfish Merkle Trees, along with the decentralized account creation process, enables Prism to maintain a transparent and verifiable record of public keys associated with user IDs from various sources.
