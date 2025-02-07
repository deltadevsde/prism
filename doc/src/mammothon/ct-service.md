# Idea 1: Certificate Transparency Browser Extension

## Problem
Certificate transparency (CT) was designed to allow users to directly verify TLS certificates and ensure secure connections. However, the current system relies heavily on the honesty of log operators, introducing vulnerabilities and a lack of trust in end-to-end encryption.

The hackathon track addresses this gap by building a browser extension that restores user trust in TLS verification and enhances online security.

[This](https://x.com/distractedm1nd/status/1842159919082176689) twitter thread highlights the current problems with certificate transparency that your project will aim to solve.

We have already built this internally as a prototype, so please [reach out](https://telegram.me/distractedm1nd) with any questions that come up.
This document intends to only be a rough outline of the architecture and flow of the project.


## Solution
The browser extension consists of two parts:
1. A prism service that monitors the CT logs for new roots and stores them in prism accounts corresponding to each log
2. A browser extension that retrieves the logs' accounts depending on the certificates of the websites visited by the user

### Prism Service

```mermaid
sequenceDiagram
    participant CTS as ct-service
    participant Prism
    participant X2024 as Xenon2024

    CTS->>Prism: RegisterService(xenon2024, pubkey)

    loop
        CTS->>X2024: Poll for new root
        X2024-->>CTS: New root
        CTS->>Prism: SetData(xenon2024, SignedTreeHead)
    end
```

### Browser Extension
```mermaid
sequenceDiagram
    actor Bob
    participant Google as google.com
    participant WLN as Wasm Light Node
    participant CTS as Prism Full Node
    participant X2024 as Xenon2024

    Bob->>Google: HTTPS Request
    activate Bob
    Google-->>Bob: TLS Certificate
    deactivate Bob
    Note left of Bob: contains SignedCertificateTimestamp<br/>from multiple logs

    Bob->>CTS: Request latest account of Xenon2024
    activate Bob
    CTS-->>Bob: AccountResponse for Xenon2024
    deactivate Bob
    Note left of Bob: Contains latest Xenon2024 root as SignedData,<br/>and merkle proof of Account under Prism root

    Bob->>WLN: Request latest verified Prism root
    activate Bob
    WLN-->>Bob: Prism root
    Bob->>Bob: Verify merkle proof against <br/> AccountResponse and Prism root
    deactivate Bob

    Bob->>X2024: Request merkle proof of TLS certificate under root
    activate Bob
    X2024-->>Bob: Merkle proof of TLS certificate under root
    Bob->>Bob: Verify Log merkle proof against <br/>Xenon2024 root from AccountResponse
    deactivate Bob
```

## Resources
- [Rust CTClient](https://docs.rs/ctclient/latest/ctclient/)
