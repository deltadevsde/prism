use crate::{
    indexed_merkle_tree::{IndexedMerkleTree, MerkleProof, ProofVariant, UpdateProof},
    storage::ChainEntry,
    zk_snark::{hex_to_scalar, BatchMerkleProofCircuit, InsertMerkleProofCircuit},
    Operation,
};
use bellman::groth16::{self, VerifyingKey};
use bls12_381::Bls12;
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

pub fn parse_json_to_proof(json_str: &str) -> Result<ProofVariant, Box<dyn std::error::Error>> {
    let proof: ProofVariant = serde_json::from_str(json_str)?;

    Ok(proof)
}

pub fn validate_snark(
    non_membership_proof: MerkleProof,
    first_proof: UpdateProof,
    second_proof: UpdateProof,
) -> Result<(), &'static str> {
    let circuit = match InsertMerkleProofCircuit::create(&(
        non_membership_proof.clone(),
        first_proof.clone(),
        second_proof.clone(),
    )) {
        Ok(circuit) => circuit,
        Err(_e) => {
            // error!("Error creating circuit: {}", e);
            return Err("Could not create circuit");
        }
    };

    let rng = &mut OsRng;

    // debug!("Creating parameters with BLS12-381 pairing-friendly elliptic curve construction....");
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).unwrap();

    // debug!("Creating proof for zkSNARK...");
    let proof = groth16::create_random_proof(circuit.clone(), &params, rng).unwrap();

    // debug!("Prepare verifying key for zkSNARK...");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    // debug!("Verifying zkSNARK proof...");
    groth16::verify_proof(
        &pvk,
        &proof,
        &[
            hex_to_scalar(non_membership_proof.0.unwrap().as_str()),
            hex_to_scalar(first_proof.0 .0.unwrap().as_str()),
            hex_to_scalar(first_proof.1 .0.unwrap().as_str()),
            hex_to_scalar(second_proof.0 .0.unwrap().as_str()),
            hex_to_scalar(second_proof.1 .0.unwrap().as_str()),
        ],
    )
    .unwrap();

    // debug!("zkSNARK with groth16 random parameters was successfully verified!");
    Ok(())
}

pub fn validate_proof(proof_value: String) -> Result<(), &'static str> {
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
            Err("Proof is invalid")
        }
    } else if let Ok(proof) = serde_json::from_str::<UpdateProof>(&proof_value) {
        if IndexedMerkleTree::verify_update_proof(&proof) {
            Ok(())
        } else {
            Err("Proof is invalid")
        }
    } else {
        Err("Invalid proof format")
    }
}

//TODO: better naming
pub fn validate_epoch_from_proof_variants(
    previous_commitment: &String,
    current_commitment: &String,
    proofs: &Vec<ProofVariant>,
) -> Result<(groth16::Proof<Bls12>, VerifyingKey<Bls12>), String> {
    let circuit = match BatchMerkleProofCircuit::create(
        previous_commitment,
        current_commitment,
        proofs.clone(),
    ) {
        Ok(circuit) => circuit,
        Err(e) => {
            return Err(format!("Could not create circuit: {}", e));
        }
    };

    let rng = &mut OsRng;

    debug!("validate_epoch: creating parameters with BLS12-381 pairing-friendly elliptic curve construction");
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).unwrap();

    debug!("validate_epoch: creating proof for zkSNARK");
    let proof = groth16::create_random_proof(circuit.clone(), &params, rng).unwrap();

    // println!("{}: {:?}", "PROOF".red(), proof);

    debug!("validate_epoch: preparing verifying key for zkSNARK");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    // println!("{}", "Extracting public parameters for zkSNARK...".yellow());
    // let public_parameters = extract_public_parameters(&parsed_proofs);

    debug!("validate_epoch: verifying zkSNARK proof...");
    groth16::verify_proof(
        &pvk,
        &proof,
        &[
            hex_to_scalar(&previous_commitment.as_str()),
            hex_to_scalar(&current_commitment.as_str()),
        ],
    )
    .unwrap();

    debug!(
        "{}",
        "validate_epoch: zkSNARK with groth16 random parameters was successfully verified!"
    );
    Ok((proof, params.vk))
}

pub fn validate_epoch(
    previous_commitment: &String,
    current_commitment: &String,
    proof: groth16::Proof<Bls12>,
    verifying_key: VerifyingKey<Bls12>,
) -> Result<groth16::Proof<Bls12>, String> {
    debug!("validate_epoch: preparing verifying key for zkSNARK");
    let pvk = groth16::prepare_verifying_key(&verifying_key);

    // println!("{}", "Extracting public parameters for zkSNARK...".yellow());
    // let public_parameters = extract_public_parameters(&parsed_proofs);

    debug!("validate_epoch: verifying zkSNARK proof...");
    groth16::verify_proof(
        &pvk,
        &proof,
        &[
            hex_to_scalar(&previous_commitment.as_str()),
            hex_to_scalar(&current_commitment.as_str()),
        ],
    )
    .unwrap();

    debug!(
        "{}",
        "validate_epoch: zkSNARK with groth16 random parameters was successfully verified!"
    );
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use crate::{
        indexed_merkle_tree::{sha256, Node},
    };

    use super::*;
    use bellman::{groth16};
    use bls12_381::{Bls12};

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
        ]);
        let prev_commitment = tree.get_commitment();
        let ryan = sha256(&"Ryan".to_string());
        let ford = sha256(&"Ford".to_string());
        let sebastian = sha256(&"Sebastian".to_string());
        let pusch = sha256(&"Pusch".to_string());
        let ryans_node = Node::initialize_leaf(true, true, ryan, ford, Node::TAIL.to_string());
        let sebastians_node =
            Node::initialize_leaf(true, true, sebastian, pusch, Node::TAIL.to_string());

        let first_insert_proof = tree.generate_proof_of_insert(&ryans_node);
        let second_insert_proof = tree.generate_proof_of_insert(&sebastians_node);

        let first_insert_zk_snark = ProofVariant::Insert(
            first_insert_proof.0,
            first_insert_proof.1,
            first_insert_proof.2,
        );
        let second_insert_zk_snark = ProofVariant::Insert(
            second_insert_proof.0,
            second_insert_proof.1,
            second_insert_proof.2,
        );

        let proofs = vec![first_insert_zk_snark, second_insert_zk_snark];
        let current_commitment = tree.get_commitment();

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
