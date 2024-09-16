# State of Prism

This post is an overview on the current development status of Prism as of Aug 26th 2024. We will do our best to keep it routinely updated.

## 1. Circuits

Our current circuit implementations serve as a functional prototype, allowing us to ship an initial Proof of Concept. These circuits are missing critical components and constraints. In the repo you will find our groth16 and supernova circuits, as well as our SP1 program. We're actively enhancing this system by:

- Rewriting original groth16 circuits using bellpepper for increased flexibility in proving systems
- Finishing Supernova circuits to leverage folding schemes and move to a trusted ZK setup
- Developing additional core circuits (related to Celestia state and hashchain verification) to eliminate further trust assumptions
- Exploring zkVM solutions (e.g., Risc0, Jolt, SP1) for Celestia state awareness and harnessing JMT proof optimizations without compromise

**Next steps:** Complete Nova rewrite and zkVM PoC

## 2. Rollup Status

We've made significant progress in rollup implementation:

- Successfully implemented based sequencing with a partially unprivileged sequencer
- Enabled direct base layer update operations for users
- Developed a robust proof of concept for further refinement

**Next steps:** Implement full nodes and develop checkpoint SNARKs for fast sync (ADR-001)

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
