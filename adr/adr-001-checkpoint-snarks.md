
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

1. Recursive SNARK generation might be computationally intensive and time-consuming, especially in Stage 1.
2. Potential vulnerabilities in the recursive SNARK implementation could compromise the entire history (also a ).
3. Compatibility issues between different SNARK systems used for epochs and checkpoints (Transition to Stage 2 - if not well thought through - may introduce compatibility issues with existing proofs and clients).

## Implementation Details

### Stage 1: Groth16 Checkpoint SNARKs

1. Define a checkpoint interval (e.g., every 4 weeks or 1000 epochs).
2. Develop a recursive Groth16 SNARK circuit that verifies multiple epoch SNARKs.
3. Implement a process to generate and post checkpoint SNARKs to Celestia.
4. Modify light clients to start syncing from the latest checkpoint SNARK.
5. Ensure backwards compatibility for existing light clients (necessary rn?).

### Stage 2: Transition to Advanced SNARK Systems

1. Evaluate Nova and zkVM solutions (e.g., Nexus with HyperNova) for compatibility with our use case and future based rollup plans.
2. Develop a prototype implementation using the chosen system.
3. Create a migration strategy for existing proofs and clients.
4. Implement additional proving capabilities required for based rollups (different ADR).
5. Tests for the new system.

## Why Nova (SuperNova / HyperNova) could be Beneficial for Us

1. Efficient Aggregation: We aggregate many proofs into epoch SNARKs. Nova's folding scheme is particularly efficient for this use case, reducing our constraint complexity from possibly millions to tens of thousands.

2. Scalability: As our system grows, the ability to efficiently aggregate proofs becomes crucial. Nova / SuperNova / HyperNova allows us to create "checkpoint SNARKs" more efficiently, enabling better long-term scalability.

3. Reduced Resource Requirements: The dramatic reduction in constraint complexity translates to lower memory usage and faster proving times, allowing us to operate more efficiently and potentially on less powerful hardware.

4. Flexibility: Nova's approach allows for more frequent aggregation and checkpoint creation, giving us more flexibility in how we structure our proof hierarchy.

5. Future-proofing: Nova's design aligns well with potential future requirements, such as more complex proof structures or more frequent updates.

## Alternatives Considered

1. Using a different data availability layer with longer-term storage (@distractedm1nd told me already why not kyve?).
2. Exploring other SNARK systems like Plonk or Halo2 (eventhough we do think Nova provides better efficiency for our specific use case of repeated proof aggregation).

## Future Considerations

While currently using Groth16, we should consider transitioning to more future-proof systems like Nexus zkVM with HyperNova for the following reasons:

1. Based Rollups: The Stage 2 implementation should account for the need to prove additional aspects beyond epoch proofs, such as transaction validity and garbage exclusion in blocks. This aligns with our plans for based rollups (refer to the Based Rollup ADR for more details).
2. zkVMs: While zkVMs introduce overhead and may not be justified for our current specific use case (proving valid Merkle paths), they offer flexibility for future extensions. As we move towards based rollups and more complex proofs, a zkVM like Jolt, SP1, Risc0 or Nexus could provide a unified framework for all our proving needs.
3. Performance vs. Flexibility: We need to carefully balance the performance benefits of specialized systems like Nova with the flexibility offered by zkVMs. Our choice in Stage 2 will depend on the complexity of proofs required for based rollups and other future features.
4. Proving System Ecosystem: We should monitor the development of proving systems like Nova and Nexus, considering factors such as performance improvements, community support, and ease of use when making our Stage 2 decision.

The transition plan should include:

1. Evaluating Nexus zkVM or similar systems for compatibility with our use case.
2. Developing a prototype implementation using the new system.
3. Creating a migration strategy for existing proofs and clients.
4. Thoroughly testing the new system before deployment.

## Open Questions

1. What is the optimal checkpoint interval (checkpoint SNARK frequency) for our system?
2. How do we handle the transition period where both Groth16 and Nova proofs might coexist?
3. What specific based rollup features will we need to prove in Stage 2, and how do they influence our choice between Nova and a zkVM solution?
4. How can we ensure smooth transition and backwards compatibility when moving from Stage 1 to Stage 2?

## Action Items

1. Implement and test the Groth16-based checkpoint system (Stage 1).
2. Conduct a detailed analysis of Nova and zkVM solutions, considering our based rollup requirements.
3. Develop proof-of-concept implementations for both Nova and a zkVM solution for comparison.
4. Create a detailed migration plan for transitioning from Stage 1 to Stage 2.
