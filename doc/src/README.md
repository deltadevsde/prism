# What is Prism?

Prism is a new verifiable authentication standard allowing users to *directly* verify the authenticity of cryptographic materials (e.g. keys and certificates) *without a trusted intermediary*.

![Prism Banner](./img/prism_banner.png)

# Why Prism?
Every time you browse a website or send an encrypted message, you're trusting that you're connecting to the right place and the right person. Without transparency systems, however, a malicious actor could secretly show you different security credentials than everyone else sees— allowing them to intercept your sensitive data without detection.

This "split-world" vulnerability affects billions of daily internet interactions, from simply browsing the web to private messaging, making it one of the most fundamental security challenges of the internet.

[Learn More →](./quickstart.md)

# How does it work?
To eliminate the need for centralized key directories, Prism cryptographically verifies the identity behind every interaction by posting validity proofs of the key directory and the corresponding roots to a high-throughput, shared data layer as the first based rollup on Celestia.

User applications embed a light node that downloads and verifies this proof directly from the Celestia network, without any intermediaries.

With Prism, users finally have the infrastructure to create apps needing transparent verification.

As a verification standard, Prism enables a new ecosystem of truly trustless applications: from a shared global identity layer and universal keystore rollups to new TEE remote attestation protocols and advancements in CA and PKI systems.

If you're interested in being a part of the project,
- join our [Discord](https://discord.gg/eNTVVHYSw7)
- follow us on [Twitter](https://x.com/prism_xyz)
- pick up an issue on [Github](https://github.com/deltadevsde/prism)
