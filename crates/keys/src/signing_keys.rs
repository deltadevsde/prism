use anyhow::Result;
use ed25519_consensus::SigningKey as Ed25519SigningKey;
use p256::ecdsa::{
    signature::DigestSigner, Signature as Secp256r1Signature, SigningKey as Secp256r1SigningKey,
};
use rand::rngs::OsRng;
use secp256k1::{Message as Secp256k1Message, SecretKey as Secp256k1SigningKey, SECP256K1};

use sha2::Digest as _;

use crate::{payload::CryptoPayload, CryptoAlgorithm, Signature, VerifyingKey};

#[derive(Clone, Debug)]
pub enum SigningKey {
    Ed25519(Box<Ed25519SigningKey>),
    Secp256k1(Secp256k1SigningKey),
    Secp256r1(Secp256r1SigningKey),
}

impl SigningKey {
    pub fn new_ed25519() -> Self {
        SigningKey::Ed25519(Box::new(Ed25519SigningKey::new(OsRng)))
    }

    pub fn new_secp256k1() -> Self {
        SigningKey::Secp256k1(Secp256k1SigningKey::new(&mut OsRng))
    }

    pub fn new_secp256r1() -> Self {
        SigningKey::Secp256r1(Secp256r1SigningKey::random(&mut OsRng))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.clone().into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(sk) => sk.to_bytes().to_vec(),
            SigningKey::Secp256k1(sk) => sk.secret_bytes().to_vec(),
            SigningKey::Secp256r1(sk) => sk.to_bytes().to_vec(),
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
        }
    }

    pub fn algorithm(&self) -> CryptoAlgorithm {
        match self {
            SigningKey::Ed25519(_) => CryptoAlgorithm::Ed25519,
            SigningKey::Secp256k1(_) => CryptoAlgorithm::Secp256k1,
            SigningKey::Secp256r1(_) => CryptoAlgorithm::Secp256r1,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            SigningKey::Ed25519(sk) => Signature::Ed25519(sk.sign(message)),
            SigningKey::Secp256k1(sk) => {
                let digest = sha2::Sha256::digest(message);
                let message = Secp256k1Message::from_digest(digest.into());
                let signature = SECP256K1.sign_ecdsa(&message, sk);
                Signature::Secp256k1(signature)
            }
            SigningKey::Secp256r1(sk) => {
                let mut digest = sha2::Sha256::new();
                digest.update(message);
                let sig: Secp256r1Signature = sk.sign_digest(digest);
                Signature::Secp256r1(sig)
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
