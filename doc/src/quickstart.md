# Quickstart

This guide introduces the core concepts behind Prism and why it's essential for modern internet security.

> **Note**: New to cryptography and internet security? Check out our [simplified overview](./crypto-intro/intro.md) for beginners.

## The Authentication Challenge

Every day, billions of internet users rely on cryptographic authentication to secure their digital interactions. Whether you're checking your email, browsing websites, or sending encrypted messages, you need to verify you're connecting to the right service or person.

Currently, this verification relies heavily on trusted intermediaries—certificate authorities for websites, key directories for messaging apps, and identity providers for online services. While these intermediaries use encryption, they remain central points of failure that can be compromised without users knowing.

> "This whole business of protecting public keys from tampering is the single most difficult problem in practical public key applications. It is the ‘Achilles heel’ of public key cryptography, and a lot of software complexity is tied up in solving this one problem."
>
> —Zimmermann et al. (“PGP User’s Guide Volume I: Essential Topics,” 1992)


## The Split-World Vulnerability

This centralized trust creates what security researchers call a "split-world" vulnerability: a malicious actor could show different security credentials to different users without detection. For example:

- A compromised certificate authority could issue fake certificates for banking websites
- A messaging service could secretly provide different encryption keys to enable surveillance
- An identity provider could selectively authenticate false credentials

These vulnerabilities persist even with strong encryption because users lack direct means to verify the authenticity of cryptographic materials.

## What is Key Transparency?

Key transparency is a security system that makes the distribution and management of cryptographic materials (like public keys and certificates) auditable and verifiable. While some services implement partial solutions, they still rely on trusted intermediaries and lack practical verification mechanisms for end users.

Traditional solutions often put the burden on users to manually verify credentials (like comparing key fingerprints or scanning QR codes). Research shows this is impractical—only a small percentage of users successfully complete these verifications, and even fewer understand their purpose.

## What is Prism?

From a high level, Prism is simply a trust-minimized service that manages data - more precisely, a label-value-map - that produces evidence that it has acted correctly and honestly. Correct and honest here refer to application-specific policies by which it purports to act.

Prism originated as a toy implementation of a paper from [Tzialla et al.](https://eprint.iacr.org/2021/1263.pdf), from which it has significantly diverged. In this documentation, _"Keypal"_ is described as a concrete application example, which serves as a POC of an application that could run on Prism.

# What is Celestia?
Celestia is a modular
[data availability network](https://blog.celestia.org/celestia-a-scalable-general-purpose-data-availability-layer-for-decentralized-apps-and-trust-minimized-sidechains)
that securely scales with the number of users.

Celestia scales by
[decoupling execution from consensus](https://arxiv.org/abs/1905.09274) and
introducing a new primitive,
[data availability sampling](https://arxiv.org/abs/1809.09044).

The former entails that Celestia is only responsible for ordering
transactions and guaranteeing their data availability; this is
similar to [reducing consensus to atomic broadcast](https://en.wikipedia.org/wiki/Atomic_broadcast#Equivalent_to_Consensus).

The latter provides an efficient solution to the
[data availability problem](https://coinmarketcap.com/alexandria/article/what-is-data-availability)
by only requiring resource-limited light nodes to sample a
small number of random shares from each block to verify data availability.

Interestingly, more light nodes that participate in sampling
increases the amount of data that the network can safely handle,
enabling the block size to increase without equally increasing the
cost to verify the chain.

Using Celestia enables extremely lightweight clients that can access a shared ledger in a trust-minimized way, without even relying on the network's fullnodes. In addition, the Prism protocol only has to pay Celestia for exactly what it needs from a shared ledger: Data Availability. There is no need for onchain execution or settlement.


## Prism as a Sovereign Rollup on Celestia

Prism operates as a sovereign-based rollup on the [Celestia](https://docs.celestia.org/learn/how-celestia-works/overview) blockchain. A rollup is a scaling solution for blockchain networks, particularly designed to increase transaction throughput and reduce fees while maintaining the security guarantees of the underlying Layer 1 (L1) blockchain. Unlike traditional rollups, Prism does not rely on Celestia's L1 to validate its blocks - the nodes of the rollup network are responsible for validating them, allowing Prism to take charge of its own settlement.

### Block Sequencing in Prism
Prism's block sequencing and ordering are directly determined by Celestia’s validators as they produce blocks on the Celestia chain. This means that Prism transactions and state updates are included within Celestia blocks, ensuring a tight coupling with Celestia’s consensus mechanism. This offers strong security guarantees for Prism, as the state progression is backed by Celestia's validator set, enhancing security by leveraging Celestia’s data availability layer.

### Prism Node Types

Prism employs three primary node types, each with distinct responsibilities:

1. **Prover**: A singleton node that generates epoch proofs for operations in the previous Prism block and posts them to a proof namespace on Celestia.
2. **Full Nodes**: These nodes run all operations posted to Prism blocks, ensuring that the Merkle root is updated according to the application-specific policies, independent of the SNARK contents.
3. **Light Nodes**: Running on end-user devices, light nodes verify epoch proofs without downloading Prism blocks or single operations, making them efficient for minimal-resource environments.

### Why Celestia?

Prism utilizes the Celestia blockchain because of its unique focus on data availability, a crucial quality for a key transparency solution like Prism. By relying on Celestia, Prism circumvents the need to pay for execution and settlement functionalities typical in monolithic blockchains, optimizing for both efficiency and cost-effectiveness.

### Enhancing Security with Trust-Minimized Light Clients

Celestia’s innovations enable trust-minimized light clients that can read the blockchain without relying on RPCs. This capability allows Prism to embed WASM light clients into end-user applications, enabling direct access to the common data layer. As a result, split-view attacks on the key directory's root are prevented, while the security of the Celestia network is directly enhanced.

This integration with Celestia not only bolsters Prism's scalability and security but also establishes a robust framework for end-to-end encrypted communication systems that rely on a decentralized key directory.
