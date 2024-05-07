use std::sync::Mutex;

use crate::{
    error::{DeimosError, GeneralError, ProofError},
    storage::{ChainEntry, Operation},
};
use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use ed25519::Signature;
use ed25519_dalek::{Verifier, VerifyingKey as Ed25519VerifyingKey};
use indexed_merkle_tree::tree::{InsertProof, NonMembershipProof, Proof, UpdateProof};
use jolt::Proof as JoltProof;
use once_cell::sync::Lazy;

pub static PROVER: Lazy<Mutex<JoltProver>> = Lazy::new(|| Mutex::new(JoltProver::new()));

pub struct JoltProver {
    pub epoch_proof: Box<dyn Fn([u8; 32], [u8; 32], Vec<Proof>) -> (bool, JoltProof) + Sync + Send>,
    pub epoch_verify: Box<dyn Fn(JoltProof) -> bool + Sync + Send>,
    pub insert_proof: Box<dyn Fn(InsertProof) -> (bool, jolt::Proof) + Sync + Send>,
    pub insert_verify: Box<dyn Fn(JoltProof) -> bool + Sync + Send>,
    pub update_proof: Box<dyn Fn(UpdateProof) -> (bool, jolt::Proof) + Sync + Send>,
    pub update_verify: Box<dyn Fn(JoltProof) -> bool + Sync + Send>,
}

impl JoltProver {
    pub fn new() -> Self {
        let (epoch_proof, epoch_verify) = guest::build_proof_epoch();
        let (insert_proof, insert_verify) = guest::build_proof_of_insert();
        let (update_proof, update_verify) = guest::build_proof_of_update();
        JoltProver {
            epoch_proof: Box::new(epoch_proof),
            epoch_verify: Box::new(epoch_verify),
            insert_proof: Box::new(insert_proof),
            insert_verify: Box::new(insert_verify),
            update_proof: Box::new(update_proof),
            update_verify: Box::new(update_verify),
        }
    }

    pub fn get_epoch_proof(
        &self,
    ) -> &Box<dyn Fn([u8; 32], [u8; 32], Vec<Proof>) -> (bool, JoltProof) + Sync + Send> {
        &self.epoch_proof
    }

    pub fn get_epoch_verify(&self) -> &Box<dyn Fn(JoltProof) -> bool + Sync + Send> {
        &self.epoch_verify
    }
}

/// Checks if a given public key in the list of `ChainEntry` objects has been revoked.
///
/// # Arguments
///
/// * `entries` - list of `ChainEntry` objects to be searched.
/// * `value` - The value (public key) to be checked.
///
/// # Returns
///
/// `true` if the value was not revoked, otherwise `false`.
/// TODO(@distractedm1nd): is_revoked > is_not_revoked, for readability
pub fn is_not_revoked(entries: &[ChainEntry], value: String) -> bool {
    for entry in entries {
        if entry.value == value && matches!(entry.operation, Operation::Revoke) {
            return false;
        }
    }
    true
}

pub fn parse_json_to_proof(json_str: &str) -> Result<Proof, Box<dyn std::error::Error>> {
    let proof: Proof = serde_json::from_str(json_str)?;

    Ok(proof)
}

pub fn decode_public_key(pub_key_str: &String) -> Result<Ed25519VerifyingKey, GeneralError> {
    // decode the public key from base64 string to bytes
    let public_key_bytes = engine.decode(pub_key_str).map_err(|e| {
        GeneralError::DecodingError(format!("Error while decoding hex string: {}", e))
    })?;

    let public_key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        GeneralError::ParsingError("Error while converting Vec<u8> to [u8; 32]".to_string())
    })?;

    let public_key = Ed25519VerifyingKey::from_bytes(&public_key_array).map_err(|_| {
        GeneralError::DecodingError("Unable to decode ed25519 verifying key".to_string())
    })?;

    Ok(public_key)
}
// TODO: Verification of single proofs?!
pub fn validate_proof(proof_value: String) -> Result<bool, DeimosError> {
    let prover = PROVER.lock().unwrap();
    if let Ok((non_membership_proof, first_proof, second_proof)) =
        serde_json::from_str::<(NonMembershipProof, UpdateProof, UpdateProof)>(&proof_value)
    {
        let insertion_proof = InsertProof {
            non_membership_proof,
            first_proof,
            second_proof,
        };
        if insertion_proof.verify() {
            let (output, proof) = (prover.insert_proof)(insertion_proof);
            let is_valid = (prover.insert_verify)(proof);
            Ok(output && is_valid)
        } else {
            Err(DeimosError::Proof(ProofError::VerificationError))
        }
    } else if let Ok(update_proof) = serde_json::from_str::<UpdateProof>(&proof_value) {
        if update_proof.verify() {
            let (output, proof) = (prover.update_proof)(update_proof);
            let is_valid = (prover.update_verify)(proof);
            Ok(output && is_valid)
        } else {
            Err(DeimosError::Proof(ProofError::VerificationError))
        }
    } else {
        Err(DeimosError::Proof(ProofError::InvalidFormatError))
    }
}
/*
 */
// TODO: creation and verification of snarks now handled by jolt
/* pub fn create_and_verify_snark(
    circuit: ProofVariantCircuit,
    scalars: Vec<Scalar>,
) -> Result<(groth16::Proof<Bls12>, VerifyingKey<Bls12>), DeimosError> {
    let rng = &mut OsRng;

    trace!("Creating parameters with BLS12-381 pairing-friendly elliptic curve construction....");
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng)
        .map_err(|_| DeimosError::Proof(ProofError::ProofUnpackError))?;

    trace!("Creating proof for zkSNARK...");
    let proof = groth16::create_random_proof(circuit, &params, rng)
        .map_err(|_| DeimosError::Proof(ProofError::GenerationError))?;

    trace!("Preparing verifying key for zkSNARK...");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    groth16::verify_proof(&pvk, &proof, &scalars)
        .map_err(|_| DeimosError::Proof(ProofError::VerificationError))?;

    Ok((proof, params.vk))
} */

pub fn validate_epoch(
    previous_commitment: &String,
    current_commitment: &String,
    proof: JoltProof,
) -> Result<bool, DeimosError> {
    debug!("validate_epoch: preparing verifying key for zkSNARK");
    let (_proof_epoch, verify_epoch) = guest::build_proof_epoch();
    // TODO: this is just the validation of the snarks! doesnt mean that the merkle proof themselves are also corret

    debug!("validate_epoch: verifying zkSNARK proof...");
    let epoch_is_valid = verify_epoch(proof);
    debug!(
        "validate_epoch: zkSNARK with groth16 random parameters for epoch between commitment {} and {} was successfully verified!",
        previous_commitment, current_commitment // commitments are in the verifying function only necessary for debug
    );
    Ok(epoch_is_valid)
}

pub trait Signable {
    fn get_signature(&self) -> Result<Signature, DeimosError>;
    fn get_content_to_sign(&self) -> Result<String, DeimosError>;
    fn get_public_key(&self) -> Result<String, DeimosError>;
}

// verifies the signature of a given signable item and returns the content of the item if the signature is valid
pub fn verify_signature<T: Signable>(
    item: &T,
    optional_public_key: Option<String>,
) -> Result<String, DeimosError> {
    let public_key_str = match optional_public_key {
        Some(key) => key,
        None => item.get_public_key()?,
    };

    let public_key = decode_public_key(&public_key_str)
        .map_err(|_| DeimosError::General(GeneralError::InvalidPublicKey))?;

    let content = item.get_content_to_sign()?;
    let signature = item.get_signature()?;

    if public_key.verify(content.as_bytes(), &signature).is_ok() {
        Ok(content)
    } else {
        Err(DeimosError::General(GeneralError::InvalidSignature))
    }
}

#[cfg(test)]
mod tests {
    use indexed_merkle_tree::{node::Node, sha256, tree::IndexedMerkleTree};

    use super::*;

    #[test]
    fn test_decode_public_key_valid() {
        let valid_pub_key_str = "CosRXOoSLG7a8sCGx78KhtfLEuiyNY7L4ksFt78mp2M=";
        assert!(decode_public_key(&valid_pub_key_str.to_string()).is_ok());
    }

    #[test]
    fn test_decode_public_key_invalid_base64() {
        let invalid_pub_key_str =
            "f3e58f3ac316b5b34b9e5a9488733a0870a4225f41f3969f53a66a110edd25b5";
        assert!(decode_public_key(&invalid_pub_key_str.to_string()).is_err());
    }

    #[test]
    fn test_decode_public_key_invalid_length() {
        let invalid_length_pub_key_str = "CosRXOoSLG7a8sCGx78KhtfLEuiyNY7L4ksFt78mp";
        assert!(decode_public_key(&invalid_length_pub_key_str.to_string()).is_err());
    }

    #[test]
    fn test_validate_epoch_valid_proof() {
        let mut tree = IndexedMerkleTree::new_with_size(4).unwrap();
        let prev_commitment = tree.get_commitment().unwrap();

        let ryan = sha256(&"Ryan".as_bytes());
        let ford = sha256(&"Ford".as_bytes());
        let sebastian = sha256(&"Sebastian".as_bytes());
        let pusch = sha256(&"Pusch".as_bytes());

        let ryans_node = Node::new_leaf(true, true, ryan, ford, Node::TAIL);
        let sebastians_node = Node::new_leaf(true, true, sebastian, pusch, Node::TAIL);

        let first_insert_proof = tree.insert_node(&ryans_node).unwrap();
        let second_insert_proof = tree.insert_node(&sebastians_node).unwrap();

        let first_insert_zk_snark = Proof::Insert(first_insert_proof);
        let second_insert_zk_snark = Proof::Insert(second_insert_proof);

        let proofs = vec![first_insert_zk_snark, second_insert_zk_snark];
        let current_commitment = tree.get_commitment().unwrap();

        let (proof_epoch, _verify_epoch) = guest::build_proof_epoch();
        let (output, proof) = proof_epoch(prev_commitment, current_commitment, proofs);

        let result = validate_epoch(
            &hex::encode(prev_commitment),
            &hex::encode(current_commitment),
            proof,
        );

        assert!(result.is_ok());
        assert_eq!(output, true);
    }
}
