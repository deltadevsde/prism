use crate::{
    error::{GeneralError, PrismError, ProofError},
    tree::Digest,
};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use bellman::groth16::{self, VerifyingKey};
use bls12_381::{Bls12, Scalar};
use ed25519::Signature;
use ed25519_dalek::{Verifier, VerifyingKey as Ed25519VerifyingKey};
use indexed_merkle_tree::tree::Proof;
use rand::rngs::OsRng;

pub fn parse_json_to_proof(json_str: &str) -> Result<Proof, Box<dyn std::error::Error>> {
    let proof: Proof = serde_json::from_str(json_str)?;

    Ok(proof)
}

pub fn decode_public_key(pub_key_str: &String) -> Result<Ed25519VerifyingKey> {
    // decode the public key from base64 string to bytes
    let public_key_bytes = engine
        .decode(pub_key_str)
        .map_err(|e| GeneralError::DecodingError(format!("base64 string: {}", e)))?;

    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| GeneralError::ParsingError("Vec<u8> to [u8; 32]".to_string()))?;

    Ed25519VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| GeneralError::DecodingError("ed25519 verifying key".to_string()).into())
}

pub fn validate_epoch(
    previous_commitment: &Digest,
    current_commitment: &Digest,
    proof: groth16::Proof<Bls12>,
    verifying_key: VerifyingKey<Bls12>,
) -> Result<groth16::Proof<Bls12>, PrismError> {
    trace!("validate_epoch: preparing verifying key for zkSNARK");
    let pvk = groth16::prepare_verifying_key(&verifying_key);

    let scalars: Result<Vec<Scalar>, _> = vec![
        (*previous_commitment).try_into(),
        (*current_commitment).try_into(),
    ]
    .into_iter()
    .collect();

    let scalars = scalars.map_err(|e| {
        PrismError::General(GeneralError::ParsingError(format!(
            "unable to parse public input parameters: {}",
            e
        )))
    })?;

    trace!("validate_epoch: verifying zkSNARK proof...");
    groth16::verify_proof(&pvk, &proof, &scalars)
        .map_err(|e| PrismError::Proof(ProofError::VerificationError(e.to_string())))?;

    Ok(proof)
}

pub trait SignedContent {
    fn get_signature(&self) -> Result<Signature>;
    fn get_plaintext(&self) -> Result<Vec<u8>>;
    fn get_public_key(&self) -> Result<String>;
}

// verifies the signature of a given signable item and returns the content of the item if the signature is valid
pub fn verify_signature<T: SignedContent>(
    item: &T,
    optional_public_key: Option<String>,
) -> Result<Vec<u8>> {
    let public_key_str = match optional_public_key {
        Some(key) => key,
        None => item.get_public_key()?,
    };

    let public_key = decode_public_key(&public_key_str)
        .map_err(|_| PrismError::General(GeneralError::InvalidPublicKey))?;

    let content = item.get_plaintext()?;
    let signature = item.get_signature()?;

    match public_key.verify(content.as_slice(), &signature) {
        Ok(_) => Ok(content),
        Err(e) => Err(GeneralError::InvalidSignature(e).into()),
    }
}

#[cfg(test)]
mod tests {

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

    /*

    TODO: rewrite with supernova

    #[test]
    fn test_validate_epoch_valid_proof() {
        let mut tree = IndexedMerkleTree::new_with_size(8).unwrap();
        let prev_commitment = tree.get_commitment().unwrap();

        let ryan = sha256_mod(b"Ryan");
        let ford = sha256_mod(b"Ford");
        let sebastian = sha256_mod(b"Sebastian");
        let pusch = sha256_mod(b"Pusch");
        let ethan = sha256_mod(b"Ethan");
        let triple_zero = sha256_mod(b"000");

        let mut ryans_node = Node::new_leaf(false, ryan, ford, Node::TAIL);
        let mut sebastians_node = Node::new_leaf(true, sebastian, pusch, Node::TAIL);
        let mut ethans_node = Node::new_leaf(false, ethan, triple_zero, Node::TAIL);

        let first_insert_proof = tree.insert_node(&mut ryans_node).unwrap();
        let second_insert_proof = tree.insert_node(&mut sebastians_node).unwrap();
        let third_insert_proof = tree.insert_node(&mut ethans_node).unwrap();

        let first_insert_zk_snark = Proof::Insert(first_insert_proof);
        let second_insert_zk_snark = Proof::Insert(second_insert_proof);
        let third_insert_zk_snark = Proof::Insert(third_insert_proof);

        let updated_seb = sha256_mod(b"Sebastian");
        sebastians_node = Node::new_leaf(true, sebastian, updated_seb, Node::TAIL);
        let index = tree.find_node_index(&sebastians_node).unwrap();
        let update_proof = tree.update_node(index, sebastians_node).unwrap();

        let update_zk_snark = Proof::Update(update_proof);

        let proofs = vec![
            first_insert_zk_snark,
            second_insert_zk_snark,
            third_insert_zk_snark,
            update_zk_snark,
        ];
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
    } */
}
