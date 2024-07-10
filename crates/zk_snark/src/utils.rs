use deimos_errors::errors::{DeimosError, DeimosResult, GeneralError,ProofError};
use crate::zk_snark::{
    hex_to_scalar, InsertMerkleProofCircuit, UpdateMerkleProofCircuit
};
use bellman::groth16::{self, VerifyingKey};
use bls12_381::{Bls12, Scalar};
use indexed_merkle_tree::tree::{InsertProof, NonMembershipProof, UpdateProof};
use serde_json::{self};


pub fn validate_proof(proof_value: String) -> DeimosResult<()> {
    if let Ok((non_membership_proof, first_proof, second_proof)) =
        serde_json::from_str::<(NonMembershipProof, UpdateProof, UpdateProof)>(&proof_value)
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
            // TODO: could insertion_proof.verify() maybe return a more detailed error to use?
            Err(
                ProofError::VerificationError("insertion proof could not be verified".to_string())
                    .into(),
            )
        }
    } else if let Ok(proof) = serde_json::from_str::<UpdateProof>(&proof_value) {
        if proof.verify() {
            let update_circuit = UpdateMerkleProofCircuit::new(&proof)?;
            update_circuit.create_and_verify_snark()?;
            Ok(())
        } else {
            Err(
                ProofError::VerificationError("update proof could not be verified".to_string())
                    .into(),
            )
        }
    } else {
        Err(ProofError::InvalidFormatError.into())
    }
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
        .map_err(|e| DeimosError::Proof(ProofError::VerificationError(e.to_string())))?;

    debug!(
        "validate_epoch: zkSNARK with groth16 random parameters for epoch between commitment {} and {} was successfully verified!",
        previous_commitment, current_commitment
    );

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use crate::zk_snark::BatchMerkleProofCircuit;
    use indexed_merkle_tree::tree::{IndexedMerkleTree, Proof};

    use deimos_types::types::decode_public_key;
    use indexed_merkle_tree::{node::Node, sha256};

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
