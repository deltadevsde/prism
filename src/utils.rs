use crate::{
    storage::ChainEntry,
    zk_snark::{hex_to_scalar, BatchMerkleProofCircuit, InsertMerkleProofCircuit},
    Operation, error::{ProofError, DeimosError, GeneralError},
};
use ed25519::Signature;
use indexed_merkle_tree::{IndexedMerkleTree, MerkleProof, ProofVariant, UpdateProof};
use bellman::groth16::{self, VerifyingKey};
use bls12_381::{Bls12, Scalar};
use rand::rngs::OsRng;
use ed25519_dalek::{VerifyingKey as Ed25519VerifyingKey, Verifier};
use base64::{engine::general_purpose::STANDARD as engine, Engine as _};

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

pub fn parse_json_to_proof(json_str: &str) -> Result<ProofVariant, Box<dyn std::error::Error>> {
    let proof: ProofVariant = serde_json::from_str(json_str)?;

    Ok(proof)
}

fn parse_option_to_scalar(
    option_input: Option<String>,
) -> Result<Scalar, GeneralError> { 
    let input_str = option_input.ok_or_else(|| 
        GeneralError::ParsingError("Could not parse input".to_string())
    )?;

    hex_to_scalar(&input_str).map_err(|_| 
        GeneralError::ParsingError("Could not convert input to scalar".to_string())
    )
}

pub fn decode_public_key(pub_key_str: &String) -> Result<Ed25519VerifyingKey, GeneralError> {
    // decode the public key from base64 string to bytes
    let public_key_bytes = engine.decode(pub_key_str)
        .map_err(|e| GeneralError::DecodingError(format!("Error while decoding hex string: {}", e)))?;

    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| GeneralError::ParsingError("Error while converting Vec<u8> to [u8; 32]".to_string()))?;

    let public_key = Ed25519VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| GeneralError::DecodingError("Unable to decode ed25519 verifying key".to_string()))?;

    Ok(public_key)
}

pub fn validate_snark(
    non_membership_proof: MerkleProof,
    first_proof: UpdateProof,
    second_proof: UpdateProof,
) -> Result<(), DeimosError> {
    let circuit = match InsertMerkleProofCircuit::create(&(
        non_membership_proof.clone(),
        first_proof.clone(),
        second_proof.clone(),
    )) {
        Ok(circuit) => circuit,
        Err(e) => {
            return Err(e);
        }
    };

    let rng = &mut OsRng;

    // debug!("Creating parameters with BLS12-381 pairing-friendly elliptic curve construction....");
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).map_err(|_| DeimosError::Proof(ProofError::ProofUnpackError))?;

    // debug!("Creating proof for zkSNARK...");
    let proof = groth16::create_random_proof(circuit.clone(), &params, rng).map_err(|_| DeimosError::Proof(ProofError::GenerationError))?;

    // debug!("Prepare verifying key for zkSNARK...");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    let scalars: Result<Vec<Scalar>, _> = vec![
        parse_option_to_scalar(non_membership_proof.0),
        parse_option_to_scalar(first_proof.0.0),
        parse_option_to_scalar(first_proof.1.0),
        parse_option_to_scalar(second_proof.0.0),
        parse_option_to_scalar(second_proof.1.0),
    ].into_iter().collect();

    // check if all scalars are valid
    let scalars = scalars.map_err(|_| DeimosError::General(GeneralError::ParsingError(format!("unable to parse public input parameters"))))?;

    // debug!("Verifying zkSNARK proof...");
    groth16::verify_proof(
        &pvk,
        &proof,
        &scalars,
    )
    .map_err(|_| DeimosError::Proof(ProofError::VerificationError))?;

    // debug!("zkSNARK with groth16 random parameters was successfully verified!");
    Ok(())
}

pub fn validate_proof(proof_value: String) -> Result<(), DeimosError> {
    if let Ok((non_membership_proof, first_proof, second_proof)) =
        serde_json::from_str::<(MerkleProof, UpdateProof, UpdateProof)>(&proof_value)
    {
        if IndexedMerkleTree::verify_insert_proof(
            &non_membership_proof,
            &first_proof,
            &second_proof,
        ) {
            validate_snark(non_membership_proof, first_proof, second_proof)
        } else {
            Err(DeimosError::Proof(ProofError::VerificationError))
        }
    } else if let Ok(proof) = serde_json::from_str::<UpdateProof>(&proof_value) {
        if IndexedMerkleTree::verify_update_proof(&proof) {
            Ok(())
        } else {
            Err(DeimosError::Proof(ProofError::VerificationError))
        }
    } else {
        Err(DeimosError::Proof(ProofError::InvalidFormatError))
    }
}

// TODO: better naming
// TODO: DRY with validate_snark Function()?!
pub fn validate_epoch_from_proof_variants(
    previous_commitment: &String,
    current_commitment: &String,
    proofs: &Vec<ProofVariant>,
) -> Result<(groth16::Proof<Bls12>, VerifyingKey<Bls12>), DeimosError> {
    let circuit = match BatchMerkleProofCircuit::create(
        previous_commitment,
        current_commitment,
        proofs.clone(),
    ) {
        Ok(circuit) => circuit,
        Err(e) => {
            return Err(e);
        }
    };

    let rng = &mut OsRng;

    debug!("validate_epoch: creating parameters with BLS12-381 pairing-friendly elliptic curve construction");
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).map_err(|_| DeimosError::Proof(ProofError::ProofUnpackError))?;

    debug!("validate_epoch: creating proof for zkSNARK");
    let proof = groth16::create_random_proof(circuit.clone(), &params, rng).map_err(|_| DeimosError::Proof(ProofError::GenerationError))?;

    debug!("validate_epoch: preparing verifying key for zkSNARK");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    // let public_parameters = extract_public_parameters(&parsed_proofs);

    let scalars: Result<Vec<Scalar>, _> = vec![
        hex_to_scalar(&previous_commitment.as_str()),
        hex_to_scalar(&current_commitment.as_str()),
    ].into_iter().collect();

    let scalars = scalars.map_err(|_| DeimosError::General(GeneralError::ParsingError(format!("unable to parse public input parameters"))))?;


    debug!("validate_epoch: verifying zkSNARK proof...");
    groth16::verify_proof(
        &pvk,
        &proof,
        &scalars,
    )
    .map_err(|_| DeimosError::Proof(ProofError::VerificationError))?;

    debug!(
        "{}",
        "validate_epoch: zkSNARK with groth16 random parameters was successfully verified!"
    );
    Ok((proof, params.vk))
}

// TODO: DRY with validate_epoch_from_proof_variants Function()?!
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
    ].into_iter().collect();

    let scalars = scalars.map_err(|_| DeimosError::General(GeneralError::ParsingError(format!("unable to parse public input parameters"))))?;

    debug!("validate_epoch: verifying zkSNARK proof...");
    groth16::verify_proof(
        &pvk,
        &proof,
        &scalars,
    )
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
    use indexed_merkle_tree::{sha256, Node};

    use super::*;
    use bellman::groth16;
    use bls12_381::Bls12;

    #[test]
    fn test_decode_public_key_valid() {
        let valid_pub_key_str = "CosRXOoSLG7a8sCGx78KhtfLEuiyNY7L4ksFt78mp2M="; 
        assert!(decode_public_key(&valid_pub_key_str.to_string()).is_ok());
    }

    #[test]
    fn test_decode_public_key_invalid_base64() {
        let invalid_pub_key_str = "f3e58f3ac316b5b34b9e5a9488733a0870a4225f41f3969f53a66a110edd25b5";
        assert!(decode_public_key(&invalid_pub_key_str.to_string()).is_err());
    }

    #[test]
    fn test_decode_public_key_invalid_length() {
        let invalid_length_pub_key_str = "CosRXOoSLG7a8sCGx78KhtfLEuiyNY7L4ksFt78mp";
        assert!(decode_public_key(&invalid_length_pub_key_str.to_string()).is_err());
    }

    #[test]
    fn test_validate_epoch_valid_proof() {
        let active_node = Node::initialize_leaf(
            true,
            true,
            Node::EMPTY_HASH.to_string(),
            Node::EMPTY_HASH.to_string(),
            Node::TAIL.to_string(),
        );
        let inactive_node = Node::initialize_leaf(
            false,
            true,
            Node::EMPTY_HASH.to_string(),
            Node::EMPTY_HASH.to_string(),
            Node::TAIL.to_string(),
        );

        let mut tree = IndexedMerkleTree::new(vec![
            active_node,
            inactive_node.clone(),
            inactive_node.clone(),
            inactive_node,
        ]).unwrap();
        let prev_commitment = tree.get_commitment().unwrap();

        let ryan = sha256(&"Ryan".to_string());
        let ford = sha256(&"Ford".to_string()); 
        let sebastian = sha256(&"Sebastian".to_string()); 
        let pusch = sha256(&"Pusch".to_string()); 
        let ryans_node = Node::initialize_leaf(true, true, ryan, ford, Node::TAIL.to_string());
        let sebastians_node = 
            Node::initialize_leaf(true, true, sebastian, pusch, Node::TAIL.to_string());

        let first_insert_proof = tree.generate_proof_of_insert(&ryans_node).unwrap();
        let second_insert_proof = tree.generate_proof_of_insert(&sebastians_node).unwrap();

        let first_insert_zk_snark = ProofVariant::Insert(
            first_insert_proof
        );
        let second_insert_zk_snark = ProofVariant::Insert(
            second_insert_proof
        );

        let proofs = vec![first_insert_zk_snark, second_insert_zk_snark];
        let current_commitment = tree.get_commitment().unwrap();

        let batched_proof =
            BatchMerkleProofCircuit::create(&prev_commitment, &current_commitment, proofs).unwrap();

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
