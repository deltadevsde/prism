use alloy_primitives::eip191_hash_message;
use anyhow::Result;
use ed25519_consensus::SigningKey as Ed25519SigningKey;
use k256::ecdsa::{
    signature::{hazmat::PrehashSigner, DigestSigner},
    Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey,
};
use p256::ecdsa::{Signature as Secp256r1Signature, SigningKey as Secp256r1SigningKey};

use sha2::Digest as _;

use crate::{
    cosmos::cosmos_adr36_hash_message, payload::CryptoPayload, CryptoAlgorithm, Signature,
    VerifyingKey,
};

// We have to decide for now if we want to have conditional compilation here or in prism_common etc. because they're relying on SigningKey, thats why we can't comment the whole file out for wasm in the current setup
#[cfg(target_arch = "wasm32")]
fn get_rng() -> impl rand::RngCore + rand::CryptoRng {
    use rand::SeedableRng;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("Failed to get random seed");
    rand::rngs::StdRng::from_seed(seed)
}

#[cfg(not(target_arch = "wasm32"))]
fn get_rng() -> impl rand::RngCore + rand::CryptoRng {
    rand::rngs::OsRng
}

#[derive(Clone, Debug)]
pub enum SigningKey {
    Ed25519(Box<Ed25519SigningKey>),
    Secp256k1(Secp256k1SigningKey),
    Secp256r1(Secp256r1SigningKey),
    Eip191(Secp256k1SigningKey),
    CosmosAdr36(Secp256k1SigningKey),
}

impl SigningKey {
    pub fn new_ed25519() -> Self {
        SigningKey::Ed25519(Box::new(Ed25519SigningKey::new(get_rng())))
    }

    pub fn new_secp256k1() -> Self {
        SigningKey::Secp256k1(Secp256k1SigningKey::random(&mut get_rng()))
    }

    pub fn new_secp256r1() -> Self {
        SigningKey::Secp256r1(Secp256r1SigningKey::random(&mut get_rng()))
    }

    pub fn new_eip191() -> Self {
        SigningKey::Eip191(Secp256k1SigningKey::random(&mut get_rng()))
    }

    pub fn new_cosmos_adr36() -> Self {
        SigningKey::CosmosAdr36(Secp256k1SigningKey::random(&mut get_rng()))
    }

    pub fn new_with_algorithm(algorithm: CryptoAlgorithm) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => Ok(SigningKey::new_ed25519()),
            CryptoAlgorithm::Secp256k1 => Ok(SigningKey::new_secp256k1()),
            CryptoAlgorithm::Secp256r1 => Ok(SigningKey::new_secp256r1()),
            CryptoAlgorithm::Eip191 => Ok(SigningKey::new_eip191()),
            CryptoAlgorithm::CosmosAdr36 => Ok(SigningKey::new_cosmos_adr36()),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.clone().into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(sk) => sk.to_bytes().to_vec(),
            SigningKey::Secp256k1(sk) => sk.to_bytes().to_vec(),
            SigningKey::Secp256r1(sk) => sk.to_bytes().to_vec(),
            SigningKey::Eip191(sk) => sk.to_bytes().to_vec(),
            SigningKey::CosmosAdr36(sk) => sk.to_bytes().to_vec(),
        }
    }

    pub fn from_algorithm_and_bytes(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => Ed25519SigningKey::try_from(bytes)
                .map(|sk| SigningKey::Ed25519(Box::new(sk)))
                .map_err(|e| e.into()),
            CryptoAlgorithm::Secp256k1 => Secp256k1SigningKey::from_slice(bytes)
                .map(SigningKey::Secp256k1)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Secp256r1 => Secp256r1SigningKey::from_slice(bytes)
                .map(SigningKey::Secp256r1)
                .map_err(|e| e.into()),
            CryptoAlgorithm::Eip191 => {
                Secp256k1SigningKey::from_slice(bytes).map(SigningKey::Eip191).map_err(|e| e.into())
            }
            CryptoAlgorithm::CosmosAdr36 => Secp256k1SigningKey::from_slice(bytes)
                .map(SigningKey::CosmosAdr36)
                .map_err(|e| e.into()),
        }
    }

    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            SigningKey::Ed25519(_) => CryptoAlgorithm::Ed25519,
            SigningKey::Secp256k1(_) => CryptoAlgorithm::Secp256k1,
            SigningKey::Secp256r1(_) => CryptoAlgorithm::Secp256r1,
            SigningKey::Eip191(_) => CryptoAlgorithm::Eip191,
            SigningKey::CosmosAdr36(_) => CryptoAlgorithm::CosmosAdr36,
        }
    }

    pub fn sign(&self, message: impl AsRef<[u8]>) -> Result<Signature> {
        match self {
            SigningKey::Ed25519(sk) => Ok(Signature::Ed25519(sk.sign(message.as_ref()))),
            SigningKey::Secp256k1(sk) => {
                let mut digest = sha2::Sha256::new();
                digest.update(message);
                let sig: Secp256k1Signature = sk.try_sign_digest(digest)?;
                Ok(Signature::Secp256k1(sig))
            }
            SigningKey::Secp256r1(sk) => {
                let mut digest = sha2::Sha256::new();
                digest.update(message);
                let sig: Secp256r1Signature = sk.try_sign_digest(digest)?;
                Ok(Signature::Secp256r1(sig))
            }
            SigningKey::Eip191(sk) => {
                let message = eip191_hash_message(message);
                let sig: Secp256k1Signature = sk.sign_prehash(message.as_slice())?;
                Ok(Signature::Secp256k1(sig))
            }
            SigningKey::CosmosAdr36(sk) => {
                let message = cosmos_adr36_hash_message(message, sk.verifying_key())?;
                let sig: Secp256k1Signature = sk.sign_prehash(message.as_slice())?;
                Ok(Signature::Secp256k1(sig))
            }
        }
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SigningKey::Ed25519(a), SigningKey::Ed25519(b)) => a.as_bytes() == b.as_bytes(),
            (SigningKey::Secp256k1(a), SigningKey::Secp256k1(b)) => a == b,
            (SigningKey::Secp256r1(a), SigningKey::Secp256r1(b)) => a == b,
            (SigningKey::Eip191(a), SigningKey::Eip191(b)) => a == b,
            (SigningKey::CosmosAdr36(a), SigningKey::CosmosAdr36(b)) => a == b,
            _ => false,
        }
    }
}

impl TryFrom<CryptoPayload> for SigningKey {
    type Error = anyhow::Error;

    fn try_from(value: CryptoPayload) -> std::result::Result<Self, Self::Error> {
        SigningKey::from_algorithm_and_bytes(value.algorithm, &value.bytes)
    }
}

impl From<SigningKey> for CryptoPayload {
    fn from(signing_key: SigningKey) -> Self {
        CryptoPayload {
            algorithm: signing_key.algorithm(),
            bytes: signing_key.to_bytes(),
        }
    }
}
