use crate::{
    error::{DeimosError, GeneralError, ProofError},
    storage::{ChainEntry, Operation},
    zk_snark::{
        hex_to_scalar, BatchMerkleProofCircuit, InsertMerkleProofCircuit, ProofVariantCircuit,
        UpdateMerkleProofCircuit,
    },
};
use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use bellman::groth16::{self, VerifyingKey};
use bls12_381::{Bls12, Scalar};
use ed25519::Signature;
use ed25519_dalek::{Verifier, VerifyingKey as Ed25519VerifyingKey};
use indexed_merkle_tree::tree::{IndexedMerkleTree, InsertProof, MerkleProof, Proof, UpdateProof};
use rand::rngs::OsRng;

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

fn parse_option_to_scalar(option_input: Option<String>) -> Result<Scalar, GeneralError> {
    let input_str = option_input
        .ok_or_else(|| GeneralError::ParsingError("Could not parse input".to_string()))?;

    hex_to_scalar(&input_str)
        .map_err(|_| GeneralError::ParsingError("Could not convert input to scalar".to_string()))
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

pub fn validate_proof(proof_value: String) -> Result<(), DeimosError> {
    if let Ok((non_membership_proof, first_proof, second_proof)) =
        serde_json::from_str::<(MerkleProof, UpdateProof, UpdateProof)>(&proof_value)
    {
        let insertion_proof = InsertProof {
            non_membership_proof,
            first_proof,
            second_proof,
        };
        if insertion_proof.verify() {
            let insertion_circuit = InsertMerkleProofCircuit::new(&insertion_proof)?;
            insertion_circuit.create_and_verify_snark()?;
            Ok(())
        } else {
            Err(DeimosError::Proof(ProofError::VerificationError))
        }
    } else if let Ok(proof) = serde_json::from_str::<UpdateProof>(&proof_value) {
        if proof.verify() {
            let update_circuit = UpdateMerkleProofCircuit::new(&proof)?;
            update_circuit.create_and_verify_snark()?;
            Ok(())
        } else {
            Err(DeimosError::Proof(ProofError::VerificationError))
        }
    } else {
        Err(DeimosError::Proof(ProofError::InvalidFormatError))
    }
}

pub fn create_and_verify_snark(
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
}

pub fn validate_epoch(
    previous_commitment: &String,
    current_commitment: &String,
    proof: groth16::Proof<Bls12>,
    verifying_key: VerifyingKey<Bls12>,
) -> Result<groth16::Proof<Bls12>, DeimosError> {
    debug!("validate_epoch: preparing verifying key for zkSNARK");
    let pvk = groth16::prepare_verifying_key(&verifying_key);

    let scalars: Result<Vec<Scalar>, _> = vec![
        hex_to_scalar(&previous_commitment.as_str()),
        hex_to_scalar(&current_commitment.as_str()),
    ]
    .into_iter()
    .collect();

    let scalars = scalars.map_err(|_| {
        DeimosError::General(GeneralError::ParsingError(format!(
            "unable to parse public input parameters"
        )))
    })?;

    debug!("validate_epoch: verifying zkSNARK proof...");
    groth16::verify_proof(&pvk, &proof, &scalars)
        .map_err(|_| DeimosError::Proof(ProofError::VerificationError))?;

    debug!(
        "validate_epoch: zkSNARK with groth16 random parameters for epoch between commitment {} and {} was successfully verified!",
        previous_commitment, current_commitment
    );
    Ok(proof)
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
    use indexed_merkle_tree::{node::LeafNode, node::Node, sha256};

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

        let ryan = sha256(&"Ryan".to_string());
        let ford = sha256(&"Ford".to_string());
        let sebastian = sha256(&"Sebastian".to_string());
        let pusch = sha256(&"Pusch".to_string());

        let ryans_node = Node::new_leaf(true, true, ryan, ford, Node::TAIL.to_string());
        let sebastians_node = Node::new_leaf(true, true, sebastian, pusch, Node::TAIL.to_string());

        let first_insert_proof = tree.insert_node(&ryans_node).unwrap();
        let second_insert_proof = tree.insert_node(&sebastians_node).unwrap();

        let first_insert_zk_snark = Proof::Insert(first_insert_proof);
        let second_insert_zk_snark = Proof::Insert(second_insert_proof);

        let proofs = vec![first_insert_zk_snark, second_insert_zk_snark];
        let current_commitment = tree.get_commitment().unwrap();

        let batched_proof =
            BatchMerkleProofCircuit::new(&prev_commitment, &current_commitment, proofs).unwrap();

        let rng = &mut OsRng;
        let params =
            groth16::generate_random_parameters::<Bls12, _, _>(batched_proof.clone(), rng).unwrap();
        let proof = groth16::create_random_proof(batched_proof.clone(), &params, rng).unwrap();

        let result = validate_epoch(
            &prev_commitment,
            &current_commitment,
            proof.clone(),
            params.vk,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), proof);
    }
}
