# Basics of Zero-Knowledge Proofs

In the past, informal section, we tried to approach zero-knowledge proofs via a practical example and to understand a bit of the basic concepts. In the following, we will gradually become a bit more formal and specify the ideas in this way, describing possible applications and outlining how zero-knowledge proofs (or rather zkSNAKRs) are used in our application.

## The first small definitions

So, as we have seen, a zero-knowledge proof is a cryptographic protocol in which a verifier (or group of verifiers) can check the correctness of an assertion without obtaining any information about the proof or the underlying secret. Before we start, we will take a closer look at the definition of Zero Knowledge Proofs, which is based on three fundamental properties: completeness, soundness, and zero knowledgeness.

**Completeness**: If a prover knows the secret, it can convince the verifier of it. This also means that it is always possible to prove something true.

**Soundness**: If a prover does not know the secret (i.e. a fraud), he cannot convince the verifier. This also means that with the Zero Knowledge protocol it is not possible to prove something false.

**Zero Knowledgeness**: The verifier learns nothing in the process except that the secret is true.

## Types of ZKPs

Zero Knowledge protocols have been researched since the early 1980s and are currently evolving at a breathtaking rate. For example, in our detailed explanation of Ali Baba and the 40 Thieves, we saw an interactive Zero Knowledge proof, as the reporter flipped a coin several times and then repeatedly interacted with Mick Ali by requesting a specific return path. This interaction, generally speaking, was repeated until the reporter (the verifier) was convinced of the knowledge of the proof. Also, Mick Ali could not see what the result of the coin toss was, which is a somewhat "stricter" interpretation and has been shown by [Babai](https://dl.acm.org/doi/pdf/10.1145/22145.22192) with the so called _Arthur-Merlin-Games_ to not be mandatory.

In addition to interactive proofs, there are also non-interactive proofs, where there is no real communication between the prover and the verifier. The prover provides all relevant information in a single exchanged message to convince the verifier of correctness (more on this later), but of course the zero-knowledge property described above is still preserved. Moreover, science now presents a great flexibility: we are able to turn interactive proofs with public coin tosses into non-interactive proofs, and as seen earlier [Goldwasser and Sipser showed in 1986](http://www.cs.toronto.edu/tss/files/papers/goldwasser-Sipser.pdf), based on Babai, that we can turn interactive proofs with secret coin tosses into interactive proofs with public coin tosses. Perhaps at this point I may jokingly refer to this as a possible "transitivity of zero-knowledge protocols" _(which is definitely not a term in the literature, at least I have never seen this before!)_.

## Next destination: zkSNARKs

Thus, while interactive proofs in practical applications take place between a prover and one (or perhaps a few) verifiers, it is obvious that for proofs of non-interactive Zero Knowledge Proofs (NIZK) there need not be a restriction on the number of verifiers in practice, since the proof can be verified independently of the prover. This is an interesting and also relevant for our Prism use case. We go into more detail about the Zero Knowledge Proof use of Prism in the next section, but first we look at an extension of NIZKs, so-called SNARKs or zkSNARKs.

The acronym zkSNARK stands for **zero knowledge succinct non-interactive argument of knowledge**. We look at the individual relevant components now more exactly, in the previous sections bases for it are put, which I will not repeat here in detail again.

Let's start with _succinctness:_ this property of proofs literally expresses that the proof should be (very) short, shorter than the simple delivery of the secret itself to the verifier.

We have already discussed _non-interactive_: there is no exchange (certainly not over several rounds) between the prover and the verifier. The prover provides everything the verifier needs for verification in a single message.

Now let's look at the last part, called the _Argument of Knowledge_, for which we can use our previous knowledge to get a basic understanding.

### Proofs, Arguments and Witnesses

We distinguish terminologically between a _Proof_ of Knowledge and an _Argument_ of Knowledge. Both terms should give the verifier a certainty that soundness and completeness are valid (see above). For this purpose we have to distinguish between infinite computational power (a theoretical construct) and finite computational power (the practical, real case). A _proof_ of knowledge is a cryptographic construct where even a (theoretical) prover with infinite computational power is not able to prove a false statement, or to falsely convince a verifier of secret knowledge without actually possessing that knowledge. This would be possible with infinite computational power in the construct of the _Argument_ of Knowledge. If we restrict ourselves to real application cases, which are relevant for practice, no prover has infinite computational power, which is why cryptographic protocol called _Argument_ of Knowledge provide sufficient security and guarantee the relevant properties completeness and soundness.

Now, nevertheless, we have not yet dealt with the concept of _knowledge_, which is obviously meant to ensure the _knowledge_ of the prover behind the proof. The prover must be in possession of a secret _knowledge_ (often called a "witness") and use this _knowledge_ in the process of creating the proof to create a valid proof. In theory, we often use a so-called _extractor_ to show that the prover knows such secret _knowledge_ (witness). The _extractor_, similar to the simulator paradigm, is a purely theoretical construct that has access to the prover and its procedure. If the _extractor_ is able to extract the secret _knowledge_ (the witness) from the creation process of the proof, then it is proven that the prover has such secret knowledge. This sounds trivial at first, but it is an important construct to prove the security properties of zkSNARKs.

## How Prism uses ZKPs

I will go into more detail about the theory behind Zero Knowledge Proofs in the elaboration over the coming months, for now let's look at what they are used for in our application.

As explained earlier, epoch-based cryptographic commitments are published (for example on a blockchain, I will explain later how we use [Celestia](https://celestia.org) for this), which contain the signed Merkle roots. Within an epoch, insert and update operations take place, causing the values within the Merkle tree and thus the Merkle root to constantly change. We use zkSNARKs in Prism to prove that we know a whole set of insert and update operations, in essence a whole set of combined Merkle proofs, that are responsible for the change in commitment from time $t-1$ to time $t$. In mathematical terms, we could say:

$$ \text{Commitment}_{t-1} + (\text{Operation}_{t1}, \text{Operation}_{t2}, ..., \text{Operation}_{tn}) = \text{Commitment}_{t} $$

Where all operations after epoch $t-1$ (i.e. within epoch $t$) are of the form $\text{Operation}_{\text{\#epoch}\text{\#operation}}$. We have already seen that the application-specific policy is satisfied by valid insert and update proofs. Thus, without the SNARK, everyone would have to perform all the resulting Merkle proofs (underlying the insert and update proofs) themselves, resulting in a huge computational overhead. By using SNARKs, anyone can independently (since we are talking about non-interactive protocols) efficiently verify the proof, which is publicly provided by the service (the prover in this case) and thus convince themselves of the honest behavior of the service.
