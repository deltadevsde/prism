# ADR-004 - Account Model

Status: In development
Authors: @distractedm1nd

## Context

In Verdict, accounts are represented as append-only hashchains. This design was chosen to avoid proving account operations’ validity and signatures on-chain using expensive SNARK operations. Instead, validity checks were offloaded to clients, enabling simpler and cheaper proofs on the service side. The hashchain’s correctness hinged on verifying each node’s hash and the coherence of the sequence of signed operations.

> To
reduce the service’s overhead, instead of directly proving
that the service only processes operations that are valid
according to an application-specific policy or that the
server processes those operations faithfully, Verdict
employs a simpler and cheaper alternative. In Verdict’s
transparency dictionary, the value associated with a label
is an append-only hashchain of operations, where nodes
store raw operations requested on the label, as well as the
cryptographic hash of the previous node in the chain. For
example, in the context of key transparency, a hashchain
records two types of operations: (1) adding a new key;
and (2) revoking an existing key, and each operation is
digitally signed by the client requesting the update.
A hashchain is valid if each node includes a correct
hash of the previous node, and if the result of applying
each operation complies with the application’s-specific
policy defined by F. For example, in key transparency,
each computed value vi would be a set of public keys.
F would allow any key to be added if it is the first
operation (i.e., vi = ⊥), and it would accept subsequent
operations if they are digitally signed by an unrevoked
key previously added in the hashchain.
When a client retrieves a hashchain associated with
a label, it can quickly apply operations recorded on
the hashchain to construct the current value associated
with the label, checking the validity of the cryptographic
hashes and compliance with F along the way. This design
supports a richer class of application-specific policies
without requiring the service to prove the validity of
those policies using SNARKs.

## Rationale

Prism, initially inspired by Verdict, adopted a similar hashchain model for account data. However, this approach no longer aligns with our current technical and ecosystem goals. Our present development strategy involves proving the entire state machine in-circuit, including signatures and policy checks. As proving costs continue to drop, we can now afford to include these validations directly in zero-knowledge proofs, making the original hashchain model less beneficial.

Moreover, the append-only hashchain model leads to unbounded growth in account state, which is problematic for certain applications (e.g., certificate transparency services). Such growth increases storage overhead, complexity, and client logic. By using a richer account model that stores and updates state directly, we can more efficiently manage account data, reduce complexity, and improve developer experience.

## Proposal

We propose replacing the append-only hashchain approach with a direct, mutable account model. Instead of recording each operation in a growing hashchain, each account will be represented as a struct containing its keys, state, and associated signed data. Since we are already validating operations and signatures in-circuit, this shift does not compromise trust assumptions.

This new model simplifies application logic: operations like key revocation can effectively reduce account size and complexity, rather than perpetually expanding a hashchain. It also makes it easier to implement future features—such as account balances—necessary for more dynamic and permissionless services. Overall, this change will streamline the codebase, lower storage and verification burdens, and provide a more intuitive development framework.

### Account Diff Example
Before:
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Hashchain {
    pub entries: Vec<HashchainEntry>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
// A [`HashchainEntry`] represents a single entry in an account's hashchain.
// The value in the leaf of the corresponding account's node in the IMT is the hash of the last node in the hashchain.
pub struct HashchainEntry {
    pub hash: Digest,
    pub previous_hash: Digest,
    pub operation: Operation,
    pub signature_bundle: HashchainSignatureBundle,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// An [`Operation`] represents a state transition in the system.
/// In a blockchain analogy, this would be the full set of our transaction types.
pub enum Operation {
    /// Creates a new account with the given id and key.
    CreateAccount {
        id: String,
        service_id: String,
        challenge: ServiceChallengeInput,
        key: VerifyingKey,
    },
    /// Registers a new service with the given id.
    RegisterService {
        id: String,
        creation_gate: ServiceChallenge,
        key: VerifyingKey,
    },
    /// Adds arbitrary signed data to an existing account.
    AddData {
        #[serde(with = "raw_or_b64")]
        data: Vec<u8>,
        data_signature: Option<SignatureBundle>,
    },
    /// Adds a key to an existing account.
    AddKey { key: VerifyingKey },
    /// Revokes a key from an existing account.
    RevokeKey { key: VerifyingKey },
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
/// Represents a signature bundle, which includes the index of the key
/// in the user's hashchain and the associated signature.
pub struct HashchainSignatureBundle {
    /// Index of the key in the hashchain
    pub key_idx: usize,
    /// The actual signature
    pub signature: Signature,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Transaction {
    pub id: String,
    pub entry: HashchainEntry,
}
```

After:
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Hash)]
pub struct Account {
    pub id: String,
    pub nonce: u64,
    pub valid_keys: Vec<VerifyingKey>,
    pub signed_data: HashMap<VerifyingKey, Vec<Vec<u8>>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// An [`Operation`] represents a state transition in the system.
/// In a blockchain analogy, this would be the full set of our transaction types.
pub enum Operation {
    /// Creates a new account with the given id and key.
    CreateAccount {
        id: String,
        service_id: String,
        challenge: ServiceChallengeInput,
        key: VerifyingKey,
    },
    /// Registers a new service with the given id.
    RegisterService {
        id: String,
        creation_gate: ServiceChallenge,
        key: VerifyingKey,
    },
    /// Adds arbitrary signed data to an existing account.
    AddData {
        #[serde(with = "raw_or_b64")]
        data: Vec<u8>,
        data_signature: Option<SignatureBundle>,
    },
    /// Adds a key to an existing account.
    AddKey { key: VerifyingKey },
    /// Revokes a key from an existing account.
    RevokeKey { key: VerifyingKey },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Transaction {
    pub id: String,
    pub operation: Operation,
    pub nonce: u64,
    pub signature: Signature,
}
```

## Effects

Moving to an account model broadens the design space of feasible services on Prism by removing the account state growth that comes with append-only hashchains.

This will be a heavy refactor, but in the end it will reduce code complexity massivley and improve developer experience. It is much more intuitive to work with account models than append-only hashchains.

It also unlocks the possibliity of adding a balance field to accounts, which is a requirement for enabling permissionless service registration and other use cases (through one-way bridging from Celestia).

That being said, we do lose one nice feature that we haven't implemented yet: The hashchain model allows retrieving the last entry of the account state, which is useful for some applications using `AddSignedData`. If we were to only store the last entry in the JMT rather than the full hashchain, this would allow for a more efficient way to retrieve the latest update to an account. This is a tradeoff we are willing to make for the benefits of the account model.

## Further Considerations

- Nonce Handling: With a hashchain, the nonce was implicit in the entry sequence. Moving to an account model requires explicitly tracking a nonce to ensure operation ordering and prevent replay attacks.
- Reset and Clearing Data: Services like certificate transparency may need to prune old data. The new model should support resetting or clearing some parts of the account state as needed.
- ServiceChallenge Verification: The move to in-circuit verification should include checking ServiceChallenge values during account creation.
- Storage Backend Updates: The storage backend must be adapted to store full account states as JMT values, rather than just the final hash of a hashchain.


## Action Items

Ryan will implement the account model refactor.
