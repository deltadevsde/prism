
# Basic Service Tutorial

## Introduction

This tutorial will guide you through initializing a prism service - not one that does anything useful, but it will give an example for what interacting with prism in a primitive way looks like.

> Note: This tutorial is only a rough outline, and we recommend [reaching out](https://telegram.me/distractedm1nd) with any questions that come up. The sdk/api is in a very early alpha state and is subject to change.

Prism services are the basis for creating new accounts in the prism protocol.
To learn more, see [labels](./labels.md).

We will cover:
1. Starting a [local prism devnet](./architecture.md)
2. Registering a test [service](./labels.md)
3. Creating [accounts](./datastructures.md) from your service
4. Adding keys and data to existing accounts


## Step 1: Create a new project
We will start by using the [prism starter template](https://github.com/deltadevsde/prism-service-example) to create a new project, then walk through the boilerplate code.

Clone the repo [here](https://github.com/deltadevsde/prism-service-example) and install our dependencies using `just`

```bash
just install-deps
```

## Step 2: Starting a local prism devnet
Let's examine the `main.rs` file of the template.

All this code does is start a local prism devnet, using a local in-memory database and in-memory data availability layer. We will add a guide shortly on how to use our devnet.

This prover instance is what we will create a service against, and where we will forward our transactions.

> NOTE: With our [architecture](./architecture.md), you can also submit transactions directly to the DA layer, and they will also be processed.

```rust
mod operations;

use anyhow::{anyhow, Result};
use keystore_rs::{KeyChain, KeyStore};
use log::debug;
use prism_client::SigningKey;
use prism_da::{memory::InMemoryDataAvailabilityLayer, DataAvailabilityLayer};
use prism_storage::inmemory::InMemoryDatabase;
use std::sync::Arc;
use tokio::spawn;

use prism_prover::{webserver::WebServerConfig, Config, Prover};

pub static SERVICE_ID: &str = "test_service";

#[tokio::main]
async fn main() -> Result<()> {
    std::env::set_var(
            "RUST_LOG",
            "DEBUG,ctclient::internal=off,reqwest=off,hyper=off,tracing=off,sp1_stark=info,jmt=off,p3_dft=off,p3_fri=off,sp1_core_executor=info,sp1_recursion_program=info,p3_merkle_tree=off,sp1_recursion_compiler=off,sp1_core_machine=off",
        );
    pretty_env_logger::init();

    let db = InMemoryDatabase::new();
    let (da_layer, _, _) = InMemoryDataAvailabilityLayer::new(5);

    let keystore_sk = KeyChain
        .get_signing_key(SERVICE_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let sk = SigningKey::Ed25519(Box::new(keystore_sk.clone()));

    let cfg = Config {
        prover: true,
        batcher: true,
        webserver: WebServerConfig {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 50524,
        },
        signing_key: sk.clone(),
        verifying_key: sk.verifying_key(),
        start_height: 1,
    };

    let prover = Arc::new(
        Prover::new(
            Arc::new(Box::new(db)),
            Arc::new(da_layer) as Arc<dyn DataAvailabilityLayer>,
            &cfg,
        )
        .unwrap(),
    );

    let runner = prover.clone();
    let runner_handle = spawn(async move {
        debug!("starting prover");
        if let Err(e) = runner.run().await {
            log::error!("Error occurred while running prover: {:?}", e);
        }
    });

    tokio::select! {
        _ = runner_handle => {
            println!("Prover runner task completed");
        }
    }

    Ok(())
}
```

## Step 3: Registering your service
Here is some example code that would handle registering a test service on prism. To learn more about what a service represents, see [labels](./labels.md).

```rust
async fn register_service(prover: Arc<Prover>) -> Result<()> {
    // First, we make sure the service is not already registered.
    if prover.get_account(SERVICE_ID).await?.account.is_some() {
        debug!("Service already registered.");
        return Ok(());
    }

    // Next we use our keystore crate to get/create a new private key for the service.
    // By default, this is stored in the operating system's keychain.
    let keystore_sk = KeyChain
        .get_signing_key(SERVICE_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let sk = SigningKey::Ed25519(Box::new(keystore_sk));
    let vk: VerifyingKey = sk.verifying_key();

    // Now we create the operation to register the service. Under the hood, this
    // creates a prism account that links the service's public key to the
    // service id -- only allowing this keypair to authorize account creations
    // from the service.
    debug!("Submitting transaction to register test service");
    prover
        .register_service(SERVICE_ID.to_string(), vk, &sk)
        .await?
        .wait()
        .await?;

    Ok(())
}
```


## Step 4: Creating accounts from your service

Here we handle creating an account from a test service. You can learn more about accounts [here](./datastructures.md).

In this snippet, we use the request builder syntax instead of the simple
`prover.create_account(&user_id, vk, &sk)`, to demonstrate what to do when the
service cannot pass the user's private key -- which should be the case for the
vast majority of usecases.

This means constructing an unsigned transaction, giving the bytes to the "user" to sign, and then injecting that signature back into the transaction and submitting it to the prover.

> Note: In a real-world scenario, the keypair and user signing would be handled client-side. Also, the service would require the user to prove ownership of a resource before creating an account (see [labels](./labels.md)).

```rust
async fn create_account(user_id: String, prover: Arc<Prover>) -> Result<Account> {
    // First, we make sure the account is not already registered.
    if let Some(account) = prover.get_account(&user_id).await?.account {
        debug!("Account {} exists already", &user_id);
        return Ok(account);
    }

    // We retrieve the test service's private key to authorize the account creation.
    let service_keystore = KeyChain
        .get_signing_key(SERVICE_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let service_sk = SigningKey::Ed25519(Box::new(service_keystore));

    // We retrieve/create the user's keypair to create the account.
    // Note: Obviously, in the real world, the keypair would be handled client side.
    let user_keystore = KeyChain
        .get_signing_key(&format!("{}/{}", user_id, SERVICE_ID))
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;
    let user_sk = SigningKey::Ed25519(Box::new(user_keystore));
    let user_vk: VerifyingKey = user_sk.verifying_key();

    // Here we use the alternative API: The request builder.
    // We do this here to demonstrate the example where you can't pass a signing
    // key from the user - which should be the case for most applications.
    let unsigned_tx = prover
        .build_request()
        .create_account()
        .with_id(user_id.clone())
        .with_key(user_vk.clone())
        .for_service_with_id(SERVICE_ID.to_string())
        .meeting_signed_challenge(&service_sk)?
        .transaction();

    // The user must sign the transaction. In a real world application, these
    // `bytes_to_sign` would be returned to the user for signing.
    let bytes_to_sign = unsigned_tx.encode_to_bytes()?;
    let signed_tx = user_sk.sign(bytes_to_sign);

    let signature_bundle = SignatureBundle {
        verifying_key: user_vk.clone(),
        signature: signed_tx,
    };
    let tx = unsigned_tx.externally_signed(signature_bundle);

    // Because the account is new, we create an empty account to store the transaction.
    let mut account = Account::default();
    account.process_transaction(&tx)?;

    debug!("Submitting transaction to create account {}", &user_id);
    prover.clone().validate_and_queue_update(tx.clone()).await?;

    Ok(account)
}
```

## Step 5: Adding keys and data to existing accounts
Prism has a minimal state machine - the only operations (transaction types) defined are:
1. `RegisterService`
2. `CreateAccount`
3. `AddKey`
4. `AddData`
5. `SetData`
6. `RevokeKey`

In the above sections, we handled `RegisterService` and `CreateAccount`. Here we will handle `AddKey` and `AddData`. You can learn more about these operations [here](./datastructures.md).

```rust
async fn add_key(
    user_id: String,
    prover: Arc<Prover>,
    signing_key: SigningKey,
    new_key: VerifyingKey,
) -> Result<Account> {
    if let Some(account) = prover.get_account(&user_id).await?.account {
        debug!("Submitting transaction to add key to account {}", &user_id);

        let updated_account = prover
            .add_key(&account, new_key, &signing_key)
            .await?
            .wait()
            .await?;

        return Ok(updated_account);
    };

    Err(anyhow!("Account {} not found", &user_id))
}

async fn add_data(
    user_id: String,
    prover: Arc<Prover>,
    signing_key: SigningKey,
    data: Vec<u8>,
    data_signature: SignatureBundle,
) -> Result<Account> {
    if let Some(account) = prover.get_account(&user_id).await?.account {
        // The source of this data can either be signed by one of the user's
        // existing keys, or from an external signer referenced in
        // data_signature.
        debug!("Submitting transaction to add data to account {}", &user_id);
        let updated_account = prover
            .add_data(&account, data, data_signature, &signing_key)
            .await?
            .wait()
            .await?;

        return Ok(updated_account);
    };

    Err(anyhow!("Account {} not found", &user_id))
}
```
