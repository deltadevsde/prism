# Accounts on Prism

Using Prism, we run into an interesting problem:

Once a new user is added to the JMT, we know that all updates to a hashchain are valid by construction - updates must be signed by an already existing key in the hashchain. But who gets to add the first key for a user? Why should we trust that the first key added actually comes from the user?

## Labels

The entries in the transparency dictionary are indexed by labels. These labels are arbitrary strings, and in the majority of the documentation we simplify the type of label to an email address.

But to add a new email address for a user, the owner of that email address must be able to prove that they own it. In Stage 1 of the architecture, this is done by means of a centralized service that verifies resource ownership. Once a user has verified ownership of an email address, the sequencer adds an entry to the hashchain.

We must move away from this, as it is both not scalable and not trust-minimized. In Stage 2, we will use services such as [zkEmail](https://prove.email/) and [TLSNotary](https://tlsnotary.org/) to provide resource ownership proofs that can be verified by any client. This will allow us to move to a trust-minimized system where the user can add their own account to the state directly by posting to the DA layer.

See more in [adr-002 (Account Sources)](https://github.com/deltadevsde/prism/blob/main/adr/adr-002-create-account-op.md).

## Protocols

This construction allows for some interesting application-layer protocols that can be added. For example, in the future we may add a transaction type for registering a service. These services register with a public key and service identifier. Then, a validity rule is added for full nodes that new entries to the JMT, if preceded by the service identifier, must be signed by the service provider's keypair.
