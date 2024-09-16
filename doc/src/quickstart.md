# Quickstart

This guide will introduce you to the ideas behind Prism.

> **Note**: If you have no or only little previous knowledge, you can get a short overview with partly simplified explanations [here](./crypto-intro/intro.md).

## The E2EE Psyop

Despite being end-to-end encrypted (an essential security feature in every communication protocol), Signal, WhatsApp, iMessage, are not as secure as we've been led to believe.

At its core, E2EE allows gated access for the sender and receiver to read messages inside a conversation, while anyone else, including the app provider, is locked out.

But E2EE isn't perfect. It hinges on the trust assumption you're communicating with the person you think is on the other side - a foundation for backdoors and hacks.

## What is a Key Directory?

A key directory serves as a repository or service that stores and distributes user's public keys. It store's public keys associated with users' identities, and allows users to fetch the public keys and corresponding merkle proofs to ensure they can securely send encrypted messages.

Although there have been instances of centralized key directories (see: MIT PGP Public Key Server, Keybase), there are no public key directories with a key transparency solution. This is what this infrastructure layer intends to provide as a rollup on top of Celestia.


## The 'Trust-Assumption' Virus

Each of these apps uses its own key directory, which typically relies on a single authority to establish channels and ensure the integrity of all communications inside the protocol.

Signal, an example hailed as the gold standard of private communication, can't read users' messages due to end-to-end encryption, but lacks cryptographic guarantees and verifiability through its lack of key transparency. This tradeoff creates a potential vulnerability as the integrity of the key exchange can be compromised without users' immediate knowledge.

Specifically, it makes these systems vulnerable to a 'man-in-the-middle attack' (MITM) - in which an unverified 3rd party intercepts a conversation without either party being aware, by sending messages inside a chat and pretending to be the person on the other side. In case you wonder how close it is to reality - back in 2016, the UK government proposed [GHOST](https://theconversation.com/u-k-proposal-to-bcc-law-enforcement-on-messaging-apps-threatens-global-privacy-118142), a protocol designed to integrate with popular messaging apps, designed to achieve the same goal of a MITM attack.


## The achilles heel of E2EE

To escape criticism around key transparency, apps like Signal and Whatsapp have introduced their own solutions to allow users to verify their contacts by scanning a QR code or comparing numbers from their screen in person or via a phone call.

While this sounds straightforward, in reality, only [14%](https://www.usenix.org/conference/soups2017/technical-sessions/presentation/vaziripour) of users manage to navigate this on their own. Even with guidance, it takes an average of over 7 minutes to complete, with most users still not fully grasping its purpose.

## What is Key Transparency?

Key transparency is a security system designed to make the distribution and management of a key directory auditable and verifiable. Signal has no key transparency solution. Other E2EE applications who do have key transparency solutions (Keybase, Whatsapp), have various strong trust assumptions that cancel out the verifiability of these systems. Furthermore, all current E2EE chat applications with key transparency solutions do not actually implement auditing or verifying from the chat client.

We provide the first key-transparency solution to enable automatic verification of the service provider. This is achieved by providing constant size succinct proofs to WASM light clients over Celestia. These WASM light clients are integrated into chat clients to have a direct connection to the DA layer without trusting an RPC.

## What is Prism?

From a high level, Prism is simply a trust-minimized service that manages data - more precisely, a label-value-map - that produces evidence that it has acted correctly and honestly. Correct and honest here refer to application-specific policies by which it purports to act.

## A practical application

Prism originiated as a toy implementation of a paper from [Tzialla et al.](https://eprint.iacr.org/2021/1263.pdf), from which it has significantly diverged. In this documentation, _"Keypal"_ is described as a concrete application example, which serves as a POC of an application that could run on Prism. Prism can be thought of as a service that simply manages a two-column table. The first column stores unique identifiers, which we will simplify to just e-mail addresses in this documentation, and the corresponding column on the right stores a hashchain of values. For most Prism applications, the values stored in this hashchain are the public keys associated with the identifier.
