# Quickstart

This guide will introduce you to the ideas behind _Prism_. We will go through the necessary cryptography and provide further links in many places to deepen the knowledge and not to completely interrupt the reading flow on the topic.

> **Note**: If you have no or only little previous knowledge, you can get a short overview with partly simplified explanations [here](./crypto-intro/intro.md).

## What is a Key Directory?

A key directory serves as a repository or service that stores and distributes user's public keys. It store's public keys associated with users' identities, and allows users to fetch the public keys and corresponding merkle proofs to ensure they can securely send encrypted messages.

Although there have been instances of centralized key directories (see: MIT PGP Public Key Server, Keybase), there are no public key directories with a key transparency solution. This is what this infrastructure layer intends to provide as a rollup on top of Celestia.

## What is Key Transparency?

Key transparency is a security system designed to make the distribution and management of a key directory auditable and verifiable. Signal has no key transparency solution. Other E2EE applications who do have key transparency solutions (Keybase, Whatsapp), have various strong trust assumptions that cancel out the verifiability of these systems. Furthermore, all current E2EE chat applications with key transparency solutions do not actually implement auditing or verifying from the chat client.

We provide the first key-transparency solution to enable automatic verification of the service provider. This is achieved by providing constant size succinct proofs to WASM light clients over Celestia. These WASM light clients are integrated into chat clients to have a direct connection to the DA layer without trusting an RPC.

## What is _Prism_?

From a high level, _Prism_ is simply a trust-minimized service that manages data - more precisely, a label-value-map - that produces evidence that it has acted correctly and honestly. Correct and honest here refer to application-specific policies by which it purports to act. In the following, we are in principle dealing with a system that does not need to be trusted because it is provably honest. Incidentally, the proofs save us some computational effort, but we will come to that later.

## A practical application

Prism originiated as a toy implementation of a paper from [Tzialla et al.](https://eprint.iacr.org/2021/1263.pdf), from which it has significantly diverged. In this paper, _"Keypal"_ is described as a concrete application example, which serves as a POC of an application that could run on _Prism_. _Prism_ can be thought of as a service that manages a two-column table. The first column stores unique identifiers, which we will simplify to just e-mail addresses in this documentation, and the corresponding column on the right stores a hashchain of values. For most Prism applications, the values stored in this hashchain are the public keys associated with the identifier.

## What's next?

Great, we now have an overview of the basic function of _Prism_. The fact that we don't understand any details yet and that everything will only make more sense later, we have to accept for the moment. Here's a quick overview of what we'll look at next:

- [Let's understand the data structures](./datastructures.md)
- [Ready for the first little proofs?](./merkle-proofs.md)
- [Zero knowledge to save time and resources](./zkp-basics.md)
