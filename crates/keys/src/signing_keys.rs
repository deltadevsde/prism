use crate::{CryptoError, Result, SignatureError, errors::ParseError};
use alloy_primitives::eip191_hash_message;
use ed25519::{
    PublicKeyBytes as Ed25519PublicKeyBytes, pkcs8::KeypairBytes as Ed25519KeypairBytes,
};
use ed25519_consensus::SigningKey as Ed25519SigningKey;
use k256::ecdsa::{
    Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey,
    signature::{DigestSigner, hazmat::PrehashSigner},
};
use p256::ecdsa::{Signature as Secp256r1Signature, SigningKey as Secp256r1SigningKey};
use pkcs8::{
    Document, EncodePrivateKey, LineEnding, PrivateKeyInfo, SecretDocument,
    der::{Decode, pem::PemLabel},
};
use std::path::Path;

use sha2::Digest as _;

use crate::{
    CryptoAlgorithm, Signature, VerifyingKey, cosmos::cosmos_adr36_hash_message,
    payload::CryptoPayload,
};

// We have to decide for now if we want to have conditional compilation here or in prism_common etc.
// because they're relying on SigningKey, that's why we can't comment the whole file out for wasm in
// the current setup
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
    Ed25519(Ed25519SigningKey),
    Secp256k1(Secp256k1SigningKey),
    Secp256r1(Secp256r1SigningKey),
    Eip191(Secp256k1SigningKey),
    CosmosAdr36(Secp256k1SigningKey),
}

impl SigningKey {
    pub fn new_ed25519() -> Self {
        SigningKey::Ed25519(Ed25519SigningKey::new(get_rng()))
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

    fn to_pkcs8_der_doc(&self) -> Result<SecretDocument> {
        match self {
            SigningKey::Ed25519(sk) => {
                let keypair_bytes = Ed25519KeypairBytes {
                    secret_key: sk.to_bytes(),
                    public_key: Some(Ed25519PublicKeyBytes(sk.verification_key().to_bytes())),
                };
                keypair_bytes.to_pkcs8_der()
            }
            SigningKey::Secp256k1(sk) => sk.to_pkcs8_der(),
            SigningKey::Secp256r1(sk) => sk.to_pkcs8_der(),
            SigningKey::Eip191(sk) => sk.to_pkcs8_der(),
            SigningKey::CosmosAdr36(sk) => sk.to_pkcs8_der(),
        }
        .map_err(|_| ParseError::DerCreationError.into())
    }

    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        Ok(self.to_pkcs8_der_doc()?.as_bytes().to_vec())
    }

    pub fn to_pkcs8_pem_file(&self, filename: impl AsRef<Path>) -> Result<()> {
        self.to_pkcs8_der_doc()?
            .write_pem_file(filename, PrivateKeyInfo::PEM_LABEL, LineEnding::LF)
            .map_err(|e| ParseError::PemCreationError(e.to_string()))?;
        Ok(())
    }

    pub fn from_algorithm_and_bytes(algorithm: CryptoAlgorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            CryptoAlgorithm::Ed25519 => Ed25519SigningKey::try_from(bytes)
                .map(SigningKey::Ed25519)
                .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()).into()),
            CryptoAlgorithm::Secp256k1 => Secp256k1SigningKey::from_slice(bytes)
                .map(SigningKey::Secp256k1)
                .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()).into()),
            CryptoAlgorithm::Secp256r1 => Secp256r1SigningKey::from_slice(bytes)
                .map(SigningKey::Secp256r1)
                .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()).into()),
            CryptoAlgorithm::Eip191 => Secp256k1SigningKey::from_slice(bytes)
                .map(SigningKey::Eip191)
                .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()).into()),
            CryptoAlgorithm::CosmosAdr36 => Secp256k1SigningKey::from_slice(bytes)
                .map(SigningKey::CosmosAdr36)
                .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()).into()),
        }
    }

    pub fn from_pkcs8_der_doc(doc: &Document) -> Result<Self> {
        let value = doc.as_bytes();
        let pk_info = PrivateKeyInfo::try_from(value).map_err(|_| ParseError::DerParseError)?;
        let algorithm =
            CryptoAlgorithm::try_from(pk_info.algorithm).map_err(|_| ParseError::DerParseError)?;

        match algorithm {
            CryptoAlgorithm::Ed25519 => {
                let ed25519_key_pair_bytes = Ed25519KeypairBytes::try_from(pk_info)
                    .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()))?;
                let ed25519_signing_key =
                    Ed25519SigningKey::from(ed25519_key_pair_bytes.secret_key);
                Ok(SigningKey::Ed25519(ed25519_signing_key))
            }
            CryptoAlgorithm::Secp256k1 => Secp256k1SigningKey::try_from(pk_info)
                .map(SigningKey::Secp256k1)
                .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()).into()),
            CryptoAlgorithm::Secp256r1 => Secp256r1SigningKey::try_from(pk_info)
                .map(SigningKey::Secp256r1)
                .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()).into()),
            CryptoAlgorithm::Eip191 => Secp256k1SigningKey::try_from(pk_info)
                .map(SigningKey::Eip191)
                .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()).into()),
            CryptoAlgorithm::CosmosAdr36 => Secp256k1SigningKey::try_from(pk_info)
                .map(SigningKey::CosmosAdr36)
                .map_err(|e| ParseError::InvalidKeyBytes(e.to_string()).into()),
        }
    }

    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self> {
        let document = pkcs8::Document::from_der(bytes).map_err(|_| ParseError::DerParseError)?;
        Self::from_pkcs8_der_doc(&document)
    }

    pub fn from_pkcs8_pem_file(file_path: impl AsRef<Path>) -> Result<Self> {
        let (label, document) =
            pkcs8::Document::read_pem_file(file_path).map_err(|_| ParseError::DerParseError)?;
        PrivateKeyInfo::validate_pem_label(&label).map_err(|_| ParseError::PemLabelError)?;

        Self::from_pkcs8_der_doc(&document)
    }

    pub fn from_pkcs8_pem_path_or_create_ed25519(file_path: impl AsRef<Path>) -> Result<Self> {
        let path = file_path.as_ref();

        if path.exists() {
            Self::from_pkcs8_pem_file(path)
        } else {
            // Ensure parent directory exists
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| ParseError::PemCreationError(e.to_string()))?;
            }
            let signing_key = SigningKey::new_ed25519();
            signing_key.to_pkcs8_pem_file(path)?;
            Ok(signing_key)
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
                let sig: Secp256k1Signature = sk
                    .try_sign_digest(digest)
                    .map_err(|e| SignatureError::SigningError(e.to_string()))?;
                Ok(Signature::Secp256k1(sig))
            }
            SigningKey::Secp256r1(sk) => {
                let mut digest = sha2::Sha256::new();
                digest.update(message);
                let sig: Secp256r1Signature = sk
                    .try_sign_digest(digest)
                    .map_err(|e| SignatureError::SigningError(e.to_string()))?;
                Ok(Signature::Secp256r1(sig))
            }
            SigningKey::Eip191(sk) => {
                let message = eip191_hash_message(message);
                let sig: Secp256k1Signature = sk
                    .sign_prehash(message.as_slice())
                    .map_err(|e| SignatureError::SigningError(e.to_string()))?;
                Ok(Signature::Secp256k1(sig))
            }
            SigningKey::CosmosAdr36(sk) => {
                let message = cosmos_adr36_hash_message(message, sk.verifying_key())
                    .map_err(|e| SignatureError::SigningError(e.to_string()))?;
                let sig: Secp256k1Signature = sk
                    .sign_prehash(message.as_slice())
                    .map_err(|e| SignatureError::SigningError(e.to_string()))?;
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
    type Error = CryptoError;

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
