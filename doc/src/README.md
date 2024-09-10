# Prism: A Publicly Verifiable Key-Transparency Solution

![Prism Banner](./img/prism_banner.png)

We're excited to announce Prism, the first truly-private messaging platform and an authentication layer for all digital communications. Prism doesn't only enable private chats, it gives users control over their digital identities, and increases security in everyday interactions on the internet.

Prism removes the need for trust in any server or app, giving users the certainty they're interacting with the right person, app, or website through transparent authentication.

## The Encryption Myth

Despite being end-to-end encrypted (an essential security feature in every communication protocol), Signal, WhatsApp, iMessage, are not as secure as we've been led to believe.
At its core, E2EE allows gated access for the sender and receiver to read messages inside a conversation, while anyone else, including the app provider, is locked out (in principle, at least).

But E2EE isn't perfect. It hinges on the trust assumption you're communicating with the person you think is on the other side - a foundation for backdoors and hacks.

## The 'Trust-Assumption' Virus

Each of these apps uses its own key directory, which typically relies on a single authority to establish channels and ensure the integrity of all communications inside the protocol.

Signal, an example hailed as the gold standard of private communication, can't read users' messages due to end-to-end encryption, but lacks cryptographic guarantees and verifiability through its key management method. This tradeoff creates a potential vulnerability as the integrity of the key exchange can be compromised (through a hack, or compliance with government intervention) without users' knowledge.

Specifically, it makes these systems vulnerable to a 'man-in-the-middle attack' (MITM) - in which an unverified 3rd party intercepts a conversation without either party being aware, by sending messages inside a chat and pretending to be the person on the other side. In case you wonder how close it is to reality - back in 2016, the UK government proposed [GHOST](https://theconversation.com/u-k-proposal-to-bcc-law-enforcement-on-messaging-apps-threatens-global-privacy-118142), a protocol designed to integrate with popular messaging apps, designed to achieve the same goal of a MITM attack.

In the physical world, you have control over your identity. You choose what to share, when to share it, and with whom. Online? Your identity is fragmented across dozens of services, each with its own agenda. You're not the user; you're the product. Your digital self is bought, sold, and manipulated without your knowledge or consent. Governments around the world are leveraging the digital revolution to create unprecedented systems of mass surveillance. From China's "Great Firewall" to the NSA's global data collection programs, our online activities are under constant scrutiny. The line between public and private has been blurred beyond recognition.

## The achilles heel of E2EE

To escape criticism around key transparency, Signal and iMessage have introduced their own solutions to allow users to verify their contacts by scanning a QR code or comparing numbers from their screen in person or via a phone call.

While this sounds straightforward, in reality, only [14%](https://www.usenix.org/conference/soups2017/technical-sessions/presentation/vaziripour) of users manage to navigate this on their own. Even with guidance, it takes an average of over 7 minutes to complete, with most users still not fully grasping its purpose.

It's proven - self authentication is a broken user experience.

## Introducing Prism: A New Era for Private Communication

Prism introduces a new standard in key transparency through open-source, verifiable computation.

The Prism tech stack provides robust verifiable encryption through the best of web3. At its core, it leverages zkSNARKs as proofs for key certifications, allowing succinct and verifiable authentication. Prism proofs are posted directly on [Celestia](https://celestia.org)'s decentralized data availability layer, guaranteeing data accessibility and integrity. Light nodes play a crucial role in Prism by verifying proofs at scale, allowing for efficient verification across the network.

Prism is web2 friendly from day 1 with WASM compatibility, allowing existing messaging applications to upgrade their key transparency easily.

## Why you should care

Beyond messaging apps, Prism opens doors to potential improvements in nascent technologies and challenges in today's web. We envision a system for transparent, seamless authentication, where every human, website, app or other digital property is verified on a blockchain.
Prism's verifiable encryption standard opens up possibilities for secure communication across various digital platforms, which can enable exciting use cases like:

1. A user controlled global identity layer
2. Keystore Rollups - allowing users to securely store and manage their cryptographic keys across multiple chains
3. A sandbox environment for testing Trusted Execution Environment (TEE) trust assumptions, ensuring even the most advanced security features are bulletproof.
4. A new trustless, decentralized model for web certificate authority and public key infrastructure (PKI) systems.

Welcome to a new era of digital privacy, where the only person listening is the one you're talking to.

## Getting started

We will introduce some basic concepts of cryptography that are essential for understanding the content. For more information and deeper explanations, we will provide links to relevant literature and texts. If you encounter errors or have suggestions for improvement, please feel free to [open an issue](https://github.com/deltadevsde/prism/issues).
