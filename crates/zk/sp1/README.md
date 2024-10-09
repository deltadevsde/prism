# SP1 Proof

After experimenting with Supernova, we decided it makes sense to test a zkVM that will let us keep our small, variable sized JMT merkle proofs without padding.
At first glance, the performance seems okay but we need further benchmarks to confirm.

In the long term, we will likely require a zkVM anyways if we need to prove over Celestia's NMT (for example, that all operations from the last Celestia block were included).
