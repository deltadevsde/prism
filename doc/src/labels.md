# Accounts on Prism

Once a new user is added to the JMT, we know that all updates to a hashchain are valid by construction - updates must be signed by an already existing key in the hashchain. But who gets to add the first key for a user? Why should we trust that the first key added actually comes from the user?

## High Level Overview

The entries in the transparency dictionary are indexed by labels. These labels are arbitrary strings, and in the majority of the documentation we simplify the type of label to an email address.

But to add a new email address/phone number for a user, the owner of that resource must be able to prove that they own it. This is done by means of a centralized service that verifies resource ownership. Once a user has verified ownership of an email address, the sequencer adds an entry to the hashchain.

We must move away from this, as it is both not scalable and not trust-minimized. We will register services such as [zkEmail](https://prove.email/) and [TLSNotary](https://tlsnotary.org/) to provide resource ownership proofs. This will allow us to move to a trust-minimized system where the user can add their own account to the state directly by posting to the DA layer.

See more in [adr-002 (Account Sources)](https://github.com/deltadevsde/prism/blob/main/adr/adr-002-create-account-op.md) and [adr-003 (Service Registration)](https://github.com/deltadevsde/prism/blob/main/adr/adr-003-service-registration.md).

## Account Creation and Service Registration
In the current design, account creation is managed through [registered services](https://github.com/deltadevsde/prism/blob/main/adr/adr-003-service-registration.md). Here's how it works:

1. Services must be registered in the system via a `RegisterService` operation.
2. Initially, service registration will be permissioned, requiring a signature from the prover/sequencer.
3. Each service defines a specific challenge that must be completed to create an account. This could be either a signature check or providing a groth16 proof.
4. Users create accounts by completing the service-specific challenge.

This approach allows for flexibility while maintaining control over account creation. It also paves the way for more decentralized account creation methods in the future.

## Other Considerations

If all labels were stored in plaintext, services would be vulnerable to enumeration attacks. A simple protection against this is to hash identifiers, meaning users must know the ID plaintext before resolving the user's hashchain. However, this is not a strong attack prevention, as hash functions are publically known.

For this reason, we distinguish between the notion of public  and private services.
1. Private services would have labels run through a VRF -- completely preventing enumeration attacks, but requiring centralized (albeit publically verifiable) identity resolution.
2. Public services simply hash their labels pre-insertion.

## Future Developments
As the system evolves, we plan to implement the following improvements:

1. Permissionless Service Registration: Once we're confident in state growth benchmarks, we may remove the signature requirement for service registration, allowing anyone to register a service.
2. Resource Pricing: If state growth becomes an issue, we may introduce a credit system for account creation. Services would deposit funds (via a Celestia transaction) to obtain credits for creating accounts.
3. Native Shielded Pool: While not currently implemented, there are considerations for adding operations to support a native shielded pool in the future.

## Protocols

This construction allows for some interesting application-layer protocols that can be added. For example, we are adding a transaction type for registering a service. These services register with a public key or groth16 verifying key and service identifier. Then, a validity rule is added for full nodes that new entries to the JMT, if preceded by the service identifier, must be signed by the service provider's keypair or provide a valid groth16 proof for the corresponding verifying key.
