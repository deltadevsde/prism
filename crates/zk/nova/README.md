# SuperNova Circuits

This crate implements jmt-based Update and Insert circuits, which get combined together for NIVC using Supernova recursive SNARKs.

They are not currently in use, because after the switch from IMT to JMT the proof size became variable, leading to both the Update and Insert steps no longer being uniform across a batch - only the first few prover steps succeed before a InvalidWitnessLength error occurs.
There is an attempt to alleviate this by padding the JMT proofs to a max depth and using selectors but it is not complete yet.

Performance is a concern, especially during the spartan compression, which takes orders of magnitudes longer than a simple groth16 batch.
