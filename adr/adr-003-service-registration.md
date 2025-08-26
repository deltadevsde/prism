# ADR-003 - Service Registration

Status: In development
Authors: @distractedm1nd

## Rationale

[ADR-002](./adr-002-create-account-op.md) discussed basic ideas surrounding account creation and the concept of external account sources.

To quote ADR-002,

> Once a new user is added to the JMT, we know that all updates to a hashchain are valid by construction- updates must be signed by an already existing key in the hashchain. But who gets to add the first key for a user? Why should we trust that the first key added actually comes from the user?
>

While ADR-002 discussed the concept behind a `CreateAccount` operation, it proposed that all account services must be enshrined to the protocol. This ADR discusses permissionless service (a.k.a `AccountSource`) registration and potential resource pricing for account creation.

## Proposal

Until we are confident in the state growth benchmarks, and to maintain simplicity, we will start with whitelisted service registration. The effects of this are following:

1. Registering a service requires a signature from the prover/sequencer
2. The only way to add nodes to the tree is by completing a service-specific challenge (either a signature check or providing a groth16 proof)

This may look something like this:

```rust
/// Represents a public key supported by the system.
pub enum PublicKey {
    Secp256k1(Vec<u8>),  // Bitcoin, Ethereum
    Ed25519(Vec<u8>),    // Cosmos, OpenSSH, GnuPG
    Curve25519(Vec<u8>), // Signal, Tor
}

/// Represents a signature bundle, which includes the index of the key
/// in the user's hashchain and the associated signature.
pub struct SignatureBundle {
    key_idx: u64,       // Index of the key in the hashchain
    signature: Vec<u8>, // The actual signature
}

/// A service-specific challenge required to create an account or perform other actions.
pub enum ServiceChallenge {
    Groth(groth16::VerifyingKey),
    Signed(PublicKey),
}

/// Input required to complete a challenge for account creation.
pub enum ServiceChallengeInput {
    Groth(groth16::Proof),
    Signed(Vec<u8>), // Signature bytes
}

/// Operations that can be performed on accounts or services.
pub enum Operation {
    CreateAccount(CreateAccountArgs),
    RegisterService(RegisterServiceArgs),
    AddKey(KeyOperationArgs),
    RevokeKey(KeyOperationArgs),
    AddNote(NoteOperationArgs),
}

/// Arguments for creating an account with a service.
pub struct CreateAccountArgs {
    id: String,                         // Account ID
    value: String,                      // Initial value
    service_id: String,                 // Associated service ID
    challenge: ServiceChallengeInput,   // Challenge input for verification
}

/// Arguments for registering a new service.
pub struct RegisterServiceArgs {
    id: String,                // Service ID
    gate: ServiceChallenge,    // Challenge gate for access control
		signature: Option<Vec<u8>> // Signature from sequencer allowing service registration
}

/// Common structure for operations involving keys (adding or revoking).
pub struct KeyOperationArgs {
    id: String,               // Account ID
    value: PublicKey,         // Public key being added or revoked
    signature: SignatureBundle, // Signature to authorize the action
}

/// Arguments for adding a note (plaintext) to an account.
pub struct NoteOperationArgs {
    id: String,               // Account ID
    value: String,            // Plaintext note
    signature: SignatureBundle, // Signature to authorize the action
}

```

This differs from the existing implementation significantly, whose only account source is a SignedBySequencer. Further adjustments were made to AddKey and RevokeKey to enable hashchain verification using a SignatureBundle as originally intended.

## Effects

If we determine state growth will be an issue, we can add resource pricing by requiring service registration to take a Celestia TxHash of a deposit to the sequencer, which provides a fixed amount of credits that can be spent to make accounts.

The reasoning behind not taking this approach from the get-go is that it requires us zk-proving inclusion of the TxHash from a Celestia block’s reserved namespace via the NMT. While this is feasible, especially with SP1, we don’t want to overengineer it until we see the benchmarks.

The ideal case is that state growth is not enough of an issue with the NMT that the price of TIA backing a CreateAccount operation is enough to deter spam. This is also assuming we require non-enshrined account source creation to submit their operations directly to the DA layer, avoiding the subsidized operations the sequencer provides.

## Further Considerations

A further consideration is the usage of the above operation types for using the Prism state tree as a nullifier tree, enabling a native shielded pool. Unfortunately, I have determined that it is not possible without running an extra protocol on top. First consider a shielded pool service could be registered whose groth16 verifying key corresponds to a circuit that verifies the user knows the plaintext to an encrypted note in their hashchain, whose hash does not yet exist as an account in the JMT. The user would submit a CreateAccount operation which would actually be meant to spend a nullifier for one of their notes. But this restricts the consumption and output to a single note, and it does not account for intermediate state roots.

Enabling a native shielded pool will likely require a few more operation types which handle these special cases, which opens a huge pandoras box about what asset to use, if it would be native to Prism, and if not, how bridging would work.

## Action Items

The team will implement a permissioned yet flexible service registration system, that can be made permissionless by removing the signature verification requirement once key benchmarks are investigated and discussed.

The team will discuss extending the protocol to enable a native shielded pool in a future ADR before the first version of the protocol is finalized.
