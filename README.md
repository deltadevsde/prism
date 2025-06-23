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

**identity layer enabling automatic verification of end-to-end encrypted services, providing users with trust-minimized security and privacy through transparent key management.**

## What is Prism?

Prism is a decentralized key transparency protocol, first inspired by the paper [Tzialla et. al](https://eprint.iacr.org/2021/1263.pdf), leveraging zkSNARKs and DA solutions to enable trust-minimized verification of E2EE services via WASM/Native light clients. This eliminates the possibility for hidden backdoors in E2EE services through a user-verifiable key management system. It uses transparency dictionaries under the hood, offering a generalized solution for managing a label-value map in environments where the service maintaining the map is not completely trusted.

Prism provides the first key-transparency solution to enable automatic verification of the service provider. This is achieved by providing constant size succinct proofs to WASM/Native light clients over a [data availability layer](https://arxiv.org/abs/1809.09044). Alternative DA solutions are in planning, allowing for a less trust-minimized client where a p2p node cannot be embedded.

The system is designed to be efficient, scalable and secure, making it suitable for a wide range of applications.

You can view further information about the project in our [documentation](https://docs.prism.rs/). The project is undergoing rapid development. You can view the current development status [here](https://docs.prism.rs/state.html).


## Status

The project is still in the early development phase, **is pending an audit**, and is not yet suitable for use in production environments.

Due to this ongoing development work, changes are still being made that will affect existing functionality and the API.

## Circuits
Initially, Prism was implemented with handwritten circuits. These legacy circuits for both groth16 and supernova are available in the `zk` crate, but are no longer maintained and will not compile with the latest version of the imported crates.

We have found, against intuition, that the SP1 zkVM provides much better performance than the legacy circuits. It also offers a more secure, auditable implementation that is maintainable by any rust developer. For our explanation as to why a zkVM ends up being more efficient, refer to our [documentation](https://docs.prism.rs/).

## Installation

### Prerequisites

### Install Dependencies

We use [`just`](https://github.com/casey/just?tab=readme-ov-file#packages) as a task runner. Once installed, you can install the rest of the dependencies with:

```bash
just install-deps
```

### Building

To build the project, run:

```bash
just build
```

This will compile the `prism-cli` binary and sp1 `ELF` that are used to run the prover, light-client, and full-node.

### Running a local DA layer

To run a local [Celestia](https://docs.celestia.org/learn/how-celestia-works/overview) network for testing, use:

```bash
just celestia-up
```

### Starting the prover

If the dependencies are installed and the local devnet is running, a prism node can be started.

Prism can be started in three different ways:
1. as a prover (service provider and proof generator)
2. as a light-client (to verify the proofs posted on Celestia using the cryptographic commitments)
3. as a full-node (acts as a service provider, processing all transactions and making the state available to the light-clients)

To start the prover, run:
```bash
prism-cli prover
```

This will output the prover's verifying key in the logs, which you can use along with the light-client and full-node to verify the proofs.

to start the light-client, run the following command:

```bash
prism-cli light-client|full-node --verifying-key <verifying-key>
```

You can then interact with Prism via the interfaces defined in [webserver.rs](https://github.com/deltadevsde/prism/blob/main/crates/node_types/prover/src/webserver.rs).

## Contributions

Contributions are welcome! Please refer to our [contributing guidelines](CONTRIBUTING.md) for information on how to submit pull requests, report issues, and contribute to the codebase.
