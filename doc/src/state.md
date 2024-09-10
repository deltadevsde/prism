# State of Prism

This post is an overview on the current development status of Prism as of Aug 26th 2024. We will do our best to keep it routinely updated.

## 1. SNARK Implementation

Our current circuit implementations serves as a functional prototype, allowing us to ship an initial Proof of Concept. These circuits are missing critical components and constraints. We're actively enhancing this system by:

- Rewriting circuits using bellpepper for increased flexibility in proving systems
- Adapting circuits for Supernova compatibility to leverage folding schemes and move to a trusted ZK setup
- Developing additional core circuits to ensure comprehensive security in our permissionless rollup construction
- Exploring zkVM solutions (e.g., Risc0, Jolt) for Celestia state awareness and WASM verification in light clients

**Next steps:** Complete Nova rewrite and integrate a zkVM solution

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

Our current state tree implementation, while functional, presents opportunities for enhancement:

- Evaluating optimizations for our `indexed-merkle-tree` crate
- Considering alternatives such as jellyfish merkle trees or NOSM for improved efficiency

**Next steps:** Determine optimal tree implementation and proceed with enhancements

## 5. WASM Compatibility

We're making strides in WASM compatibility to ensure widespread accessibility:

- Nearing completion of WASM compatibility for light nodes
- Working towards full integration with Lumina's WASM nodes for blob submission and retrieval

**Next steps:** Integrate Lumina's WASM nodes and develop an SDK for seamless mobile framework integration
