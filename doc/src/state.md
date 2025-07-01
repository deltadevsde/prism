# State of Prism

This post is an overview on the current development status of Prism as of Nov 12th 2024. We will do our best to keep it routinely updated.

## 1. Circuits

Our handwritten circuits have now been succeeded by our sp1 implementation, but the groth16 and supernova variants can still be found under the `zk` directory.
We're actively working on the next steps:

- Optimizing code run in circuit
- Adding Celestia state proof, that all transactions since the last epoch have been included
- Recursive epoch proofs for near-instant state sync

**Next steps:** Finish benchmarking before rebooting testnet

## 2. Rollup Status

We've made significant progress in the rollup logic:

- Implemented full nodes, light nodes, and prover
- Successfully implemented based sequencing with a batcher + prover
- Enabled direct base layer update operations for users
- Implemented recursive snarks for near instant sync of light nodes

**Next steps:** Bring in own p2p layer for light nodes to request state without relying on bootstrapper

## 3. API Development

We've initiated a comprehensive API redesign to better serve our diverse user base:

- Collaborating closely with application developers to ensure API alignment with integration needs
- Focusing on versatility to support various use cases, including keystore rollups, messaging, and certificate transparency

**Next steps:** Expand API methods based on developer feedback and use case requirements

## 4. State Tree Optimization

Since our last update, we have migrated fully to using a Jellyfish Merkle Tree. While functional, there are many opportunities for enhancement:

- Evaluating lower level proof verification optimizations to reduce cycle count in SP1
- Upstreaming our changes or publishing our fork as a crate if not reconcilable

**Next steps:** Analyze SP1 cycles during proof verification

## 5. WASM + Uniffi Compatibility

We now have full WASM support, as well as native bindings via uniffi.

They can be found in the `node_types/uniffi-lightclient` and `node_types/wasm-lightclient` crates.


## 6. Alternative DA Solutions

Not all clients can rely on Celestia's DA solution, particularly where a p2p node cannot be integrated or better performance is required.

For this, we are building a DA Multiplexer that will allow posting the FinalizedEpochs to centralized providers as well, such as AWS.

In addition, we are exploring a gossip-based solution to supplement the use of DA providers. This is the approach that iMessage takes, and the one that Certificate Transparency was supposed to take.

## 7. Further reducing trust assumptions + ensuring compliance with regulatory requirements

- Adding another layer of protection to the zkSNARKs with TEEs [(see here)](https://blog.succinct.xyz/sp1-2fa/)
- Ensuring GDPR and SOC compliance
