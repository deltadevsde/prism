
# ADR: Implementing Checkpoints via Recursive SNARKs

## Context

Prism currently uses Bellman Groth16 zk-SNARKs in a two-layer approach:

1. Individual Merkle proof SNARKs are created for each operation.
2. These SNARKs are aggregated into epoch SNARKs, also using Groth16

The epoch SNARKS are posted to the Celestia DA Layer. This allows for WASM-compatible light clients but faces limitations since Celestia only stores blocks for approximately 4 weeks. For exapmle, it creates a synchronization challenge for new light clients joining after this period. We need a solution for long-term verifiability and efficient syncing for new light clients.

## **Decision**

We will implement a checkpoint system using recursive SNARKs ("checkpoint SNARKs") that prove the validity of multiple previous epoch SNARKs. It will allow new light clients to sync from the latest checkpoint SNARK and the upcoming SNARKs from that point forward. This implementation will be done in two stages:

Stage 1: Implement checkpoint SNARKs using Groth16, leveraging our existing codebase and infrastructure.

Stage 2: Explore and transition to more advanced solutions like Nova or zkVMs (e.g., Nexus with HyperNova backend) for future developments, particularly in preparation for based rollups.

## Status

Proposed

## Consequences

### Positive

1. Enables long-term verifiability without relying on Celestia's limited block storage.
2. Reduces the initial sync time and data requirements for new light clients.
3. Maintains the security guarantees of the original system while extending its timeframe.
4. Stage 1 allows for quick deployment using existing infrastructure.
5. Stage 2 prepares the system for future expansions and optimizations.

### Negative

1. Increased complexity in the proving system.
2. Potential performance overhead in generating recursive SNARKs, especially in Stage 1.

### Risks

1. Recursive SNARK generation is computationally intensive and time-consuming, especially in Stage 1.
2. Potential vulnerabilities in the recursive SNARK implementation could compromise the entire history.
3. Compatibility issues between different SNARK systems used for epochs and checkpoints (Transition to Stage 2 - if not well thought through - may introduce compatibility issues with existing proofs and clients).

## Implementation Details

### Stage 1: Groth16 Checkpoint SNARKs

1. Defining a starting checkpoint interval: every 125 epochs (a pessimistic estimate is that a light client can sync 25 epochs/minute).
2. Develop a recursive Groth16 SNARK circuit that verifies multiple epoch SNARKs.
3. Implement a process to generate and post checkpoint SNARKs to Celestia.
4. Modify light clients to start syncing from the latest checkpoint SNARK.

### Stage 2: Transition to Advanced SNARK Systems

1. Evaluate Nova and zkVM solutions (e.g., Nexus with HyperNova) for compatibility with our use case and future based rollup plans.
2. Develop a prototype implementation using the chosen system.
3. Create a migration strategy in an update to this ADR for existing proofs and clients.
4. Update this ADR with a testing strategy and execute it before deployment.

## Why Nova (SuperNova / HyperNova) could be Beneficial for Us

1. Effiency: By leveraging Nova's efficient folding scheme, we achieve significant reductions in constraint complexity, enhance scalability through efficient proof aggregation, and lower resource requirements. This allows for faster proving times, reduced memory usage, and the ability to operate effectively on less powerful hardware, making our system more efficient and scalable in the long term.

2. Future-proofing: Nova's design aligns well with potential future requirements, such as more complex proof structures or more frequent updates.

## Alternatives Considered

1. Using a different data availability layer with longer-term storage.
2. Exploring other SNARK systems like Plonk or Halo2 (eventhough we do think Nova provides better efficiency for our specific use case of repeated proof aggregation).

## Open Questions

1. How do we handle the transition period where both Groth16 and Nova proofs might coexist?
2. What specific based rollup features will we need to prove in Stage 2, and how do they influence our choice between Nova and a zkVM solution?
3. How can we ensure smooth transition and backwards compatibility when moving from Stage 1 to Stage 2?

## Action Items

1. Implement and test the Groth16-based checkpoint system (Stage 1).
2. Conduct a detailed analysis of Nova and zkVM solutions, considering our based rollup requirements.
3. Develop proof-of-concept implementations for both Nova and a zkVM solution for comparison.
4. Create a detailed migration plan for transitioning from Stage 1 to Stage 2.
