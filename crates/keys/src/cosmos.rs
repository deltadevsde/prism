use anyhow::Result;
use k256::ecdsa::VerifyingKey as Secp256k1VerifyingKey;
use prism_serde::{bech32::ToBech32, raw_or_b64};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct CosmosSignDoc {
    account_number: String,
    chain_id: String,
    fee: CosmosFee,
    memo: String,
    msgs: Vec<CosmosMessage>,
    sequence: String,
}

#[derive(Serialize, Deserialize)]
struct CosmosFee {
    amount: Vec<String>,
    gas: String,
}

#[derive(Serialize, Deserialize)]
struct CosmosMessage {
    #[serde(rename = "type")]
    msg_type: String,
    value: CosmosMessageValue,
}

#[derive(Serialize, Deserialize)]
struct CosmosMessageValue {
    #[serde(with = "raw_or_b64")]
    data: Vec<u8>,
    signer: String,
}

impl CosmosSignDoc {
    fn new(signer: String, data: Vec<u8>) -> CosmosSignDoc {
        CosmosSignDoc {
            chain_id: "".to_string(),
            account_number: "0".to_string(),
            sequence: "0".to_string(),
            fee: CosmosFee {
                gas: "0".to_string(),
                amount: vec![],
            },
            msgs: vec![CosmosMessage {
                msg_type: "sign/MsgSignData".to_string(),
                value: CosmosMessageValue { signer, data },
            }],
            memo: "".to_string(),
        }
    }
}

pub fn cosmos_adr36_hash_message(
    message: impl AsRef<[u8]>,
    verifying_key: &Secp256k1VerifyingKey,
) -> Result<Vec<u8>> {
    // TODO: Support arbitrary address prefixes
    // At the moment we expect users to use "cosmoshub-4" as chainId when
    // signing prism data via `signArbitrary(..)`, resulting in "cosmos" as address prefix
    const ADDRESS_PREFIX: &str = "cosmos";

    let signer = signer_from_key(ADDRESS_PREFIX, verifying_key)?;
    let serialized_sign_doc = create_serialized_adr36_sign_doc(message.as_ref().to_vec(), signer)?;
    let hashed_sign_doc = Sha256::digest(&serialized_sign_doc).to_vec();
    Ok(hashed_sign_doc)
}

fn create_serialized_adr36_sign_doc(data: Vec<u8>, signer: String) -> Result<Vec<u8>> {
    let adr36_sign_doc = CosmosSignDoc::new(signer, data);

    let sign_doc_str = serde_json::to_string(&adr36_sign_doc)?
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026");
    Ok(sign_doc_str.into_bytes())
}

fn signer_from_key(address_prefix: &str, verifying_key: &Secp256k1VerifyingKey) -> Result<String> {
    let verifying_key_bytes = verifying_key.to_sec1_bytes();
    let hashed_key_bytes = Sha256::digest(verifying_key_bytes);
    let cosmos_address = Ripemd160::digest(hashed_key_bytes);

    let signer = cosmos_address.to_bech32(address_prefix)?;
    Ok(signer)
}
