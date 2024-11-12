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
- Developed a robust proof of concept for further refinement

**Next steps:** Implement checkpoint SNARKs for fast sync (ADR-001)

## 3. API Development

We've initiated a comprehensive API redesign to better serve our diverse user base:

- Collaborating closely with application developers to ensure API alignment with integration needs
- Focusing on versatility to support various use cases, including keystore rollups, messaging, and certificate transparency

**Next steps:** Expand API methods based on developer feedback and use case requirements

## 4. State Tree Optimization

Since our last update, we have migrated fully to using a Jellyfish Merkle Tree. While functional, there are many opportunities for enhancement:

- Evaluating lower level proof verification optimizations to reduce cycle count in SP1
- Upstreaming our changes or publishing our fork as a crate if not reconcilable
- Implementing a LSM datastore, moving away from the Redis PoC

**Next steps:** Analyze SP1 cycles during proof verification, implement LSM-backed datastore

## 5. WASM Compatibility

We're making strides in WASM compatibility to ensure widespread accessibility:

- Nearing completion of WASM compatibility for light nodes
- Working towards full integration with Lumina's WASM nodes for blob submission and retrieval

**Next steps:** Integrate Lumina's WASM nodes and develop an SDK for seamless mobile framework integration
