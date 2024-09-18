#![no_main]
sp1_zkvm::entrypoint!(main);

use ed25519_consensus::VerificationKeyBytes;
use prism_common::{
    operation::PublicKey,
    tree::{Batch, Digest, Proof},
};
use secp256k1::{ecdsa, Message, PublicKey as Secp256k1PublicKey, Secp256k1};

fn is_key_revoked(key: &PublicKey, revoked_keys: &[PublicKey]) -> bool {
    revoked_keys.contains(key)
}

pub fn verify_signature<T: SignedContent>(item: &T) -> bool {
    let content = item.get_plaintext()?;
    let signature = item.get_signature()?;
    let public_key = item.get_public_key()?;

    match public_key {
        PublicKey::Secp256k1(key_bytes) => {
            let secp = Secp256k1::verification_only();
            let public_key =
                Secp256k1PublicKey::from_slice(&key_bytes).expect("Invalid public key");
            let sig = ecdsa::Signature::from_compact(&signature).expect("Invalid signature");
            assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
        }
        PublicKey::Ed25519(key_bytes) => {
            let public_key = VerificationKeyBytes::try_from(key_bytes).expect("Invalid public key");
        }
        PublicKey::Curve25519(key_bytes) => {
            // TODO
        }
    }

    Ok(content)
}

pub fn main() {
    println!("cycle-tracker-start: setup");
    let batch = sp1_zkvm::io::read::<Batch>();
    let mut current = batch.prev_root;
    sp1_zkvm::io::commit_slice(&current.to_bytes());

    println!("cycle-tracker-end: setup");

    println!("cycle-tracker-start: proof-iteration");
    for proof in batch.proofs.iter() {
        match proof {
            Proof::Update(p) => {
                assert_eq!(current, Digest::new(p.old_root.into()));
                println!("cycle-tracker-start: update");
                assert!(p.verify().is_ok());
                println!("cycle-tracker-end: update");
                current = Digest::new(p.new_root.into());
            }
            Proof::Insert(p) => {
                assert_eq!(current, p.non_membership_proof.root);
                println!("cycle-tracker-start: insert");
                assert!(p.verify().is_ok());
                println!("cycle-tracker-end: insert");
                current = p.new_root;
            }
        }
    }
    println!("cycle-tracker-end: proof-iteration");

    sp1_zkvm::io::commit_slice(&current.to_bytes());
}
