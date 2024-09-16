# Prism as a Sovereign Rollup on Celestia

Prism operates as a sovereign based rollup on the Celestia blockchain. A rollup is a scaling solution for blockchain networks, particularly designed to increase transaction throughput and reduce fees while maintaining the security guarantees of the underlying Layer 1 (L1) blockchain. Unlike traditional rollups, Prism does not rely on the Celestia L1 to validate its blocks - the nodes of the rollup network are responsible for validating them, allowing Prism to take charge of its own settlement.

## Block Sequencing in Prism
Prism's block sequencing and ordering are directly determined by Celestia’s validators as they produce blocks on the Celestia chain. This means that Prism transactions and state updates are included within Celestia blocks, ensuring a tight coupling with Celestia’s consensus mechanism. This offers strong security guarantees for Prism, as the state progression is backed by Celestia's validator set, enhancing security by leveraging Celestia’s data availability layer.

## Prism Node Types

Prism employs three primary node types, each with distinct responsibilities:

1. **Sequencer/Prover**: A singleton node that generates epoch proofs for operations in the previous Prism block and posts them to a proof namespace on Celestia.
2. **Full Nodes**: These nodes run all operations posted to Prism blocks, ensuring that the Merkle root is updated according to the application-specific policies, independent of the SNARK contents.
3. **Light Nodes**: Running on end-user devices, light nodes verify epoch proofs without downloading Prism blocks or single operations, making them efficient for minimal-resource environments.

## Why Celestia?

Prism utilizes the Celestia blockchain because of its unique focus on data availability, a crucial quality for a key transparency solution like Prism. By relying on Celestia, Prism circumvents the need to pay for execution and settlement functionalities typical in monolithic blockchains, optimizing for both efficiency and cost-effectiveness.

## Enhancing Security with Trust-Minimized Light Clients

Celestia’s innovations enable trust-minimized light clients that can read the blockchain without relying on RPCs. This capability allows Prism to embed WASM light clients into end-user applications, enabling direct access to the common data layer. As a result, split-view attacks on the key directory's root are prevented, while the security of the Celestia network is directly enhanced.

This integration with Celestia not only bolsters Prism's scalability and security but also establishes a robust framework for end-to-end encrypted communication systems that rely on a decentralized key directory.
