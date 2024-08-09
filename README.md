<p align="center">
  <picture>
    <source srcset="./assets/prism-white.png" media="(prefers-color-scheme: dark)">
    <img src="./assets/prism-dark.png" alt="Prism" width="350">
  </picture>
</p>

# prism

[![delta devs](https://img.shields.io/badge/building-in_stealth-0097FF)](https://deltadevs.xyz)
![Dependencies](https://img.shields.io/badge/dependencies-up%20to%20date-0097FF.svg)
[![GitHub Issues](https://img.shields.io/github/issues-raw/deltadevsde/transparency-dictionary?color=0097FF)](https://github.com/deltadevsde/transparency-dictionary/issues)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-0097FF.svg)
[![License](https://img.shields.io/badge/license-MIT-0097FF.svg)](https://opensource.org/licenses/MIT)

**global identity layer enabling automatic verification of end-to-end encrypted services, providing users with trust-minimized security and privacy through transparent key management.**

## What is Prism?

Prism is a decentralized key transparency protocol, strongly inspired by the paper [Tzialla et. al](https://eprint.iacr.org/2021/1263.pdf), leveraging zkSNARKs to enable trust-minimized verification of E2EE services via WASM light clients. This eliminates the possibility for hidden backdoors in E2EE services through a user-verifiable key management system. It uses transparency dictionaries under the hood, offering a generalized solution for managing a label-value map in environments where the service maintaining the map is not completely trusted.

Prism provides the first key-transparency solution to enable automatic verification of the service provider. This is achieved by providing constant size succinct proofs to WASM light clients over a data availbility layer. The system is designed to be efficient, scalable and secure, making it suitable for a wide range of applications.

You can view further information about the project in our [documentation](https://prism.deltadevs.xyz). The project is undergoing rapid development. You can view the current development status [here](https://prism.deltadevs.xyz/state).


## Status

The project is still in the early development phase, has not been audited, and is not yet suitable for use in production environments.

Due to this ongoing development work, changes are still being made that may affect existing functionalities.

## Installation

### Prerequisites

### Install Redis

Redis serves as a powerful in-memory database that is used to store the label-value pairs. Follow these steps to install Redis:

1. Download Redis from [Redis Download Page](https://redis.io/download/).
2. Follow the installation instructions for your operating system.

### Install Celestia

A DA layer such as Celestia is an important component for data security and availability. It stores the cryptographic commitments and parameters of the zkSNARKs and ideally enables them to be verified. Follow the instructions [here](https://github.com/celestiaorg/apollo) to deploy a local testnet.

### Starting the sequencer

If Redis is installed and the local devnet is running, Prism can be started. Prism can be started in two different ways, as a sequencer (service provider and proof generator) or as a light-client (to verify the proofs posted on Celestia using the cryptographic commitments). To start the sequencer, run the following command:

```bash
cargo run sequencer
```

to start the light-client, run the following command:

```bash
cargo run light-client
```

You can then interact with Prism via the interfaces defined in [webserver.rs](https://github.com/deltadevsde/prism/blob/main/src/webserver.rs). Based on the data exchanged or stored via the interface the global indexed merkle tree changes and proofs based on these changes then are created in defined epochs (currently 60 seconds) and cryptographic commitments including the proof parameters are posted in the Celestia namespace.

## Contributions

Contributions are welcome! Please refer to our [contributing guidelines](CONTRIBUTING.md) for information on how to submit pull requests, report issues, and contribute to the codebase.
