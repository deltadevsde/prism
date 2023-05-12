use bellman::groth16;
use bls12_381::{Bls12, Scalar};
use rand::rngs::OsRng;
use serde_json::Value;
use crate::indexed_merkle_tree::{IndexedMerkleTree, InsertProof, MerkleProof, ProofVariant, UpdateProof};
use crate::storage::ChainEntry;
use crate::zk_snark::{hex_to_scalar, InsertMerkleProofCircuit, BatchMerkleProofCircuit};
use crate::Operation;

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


pub fn validate_snark(non_membership_proof: MerkleProof, first_proof: UpdateProof, second_proof: UpdateProof) -> Result<(), &'static str> {
    let circuit = match InsertMerkleProofCircuit::create_from_update_proof(&(non_membership_proof.clone(), first_proof.clone(), second_proof.clone())) {
        Ok(circuit) => circuit,
        Err(e) => {
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
            hex_to_scalar(first_proof.0.0.unwrap().as_str()),
            hex_to_scalar(first_proof.1.0.unwrap().as_str()),
            hex_to_scalar(second_proof.0.0.unwrap().as_str()),
            hex_to_scalar(second_proof.1.0.unwrap().as_str()),
        ],
    ).unwrap();

    // info!("zkSNARK with groth16 random parameters was successfully verified!");
    Ok(())
}

pub fn validate_proof(proof_value: String) -> Result<(), &'static str> {
    if let Ok((non_membership_proof, first_proof, second_proof)) = serde_json::from_str::<(MerkleProof, UpdateProof, UpdateProof)>(&proof_value) {
        if IndexedMerkleTree::verify_insert_proof(&non_membership_proof, &first_proof, &second_proof) {
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


pub fn validate_epoch(previous_commitment: &String, current_commitment: &String, proofs: &Vec<ProofVariant>) -> Result <groth16::Proof<Bls12>, String> {
    let circuit = match BatchMerkleProofCircuit::create(hex_to_scalar(previous_commitment.as_str()), hex_to_scalar(current_commitment.as_str()), proofs.clone()) {
        Ok(circuit) => circuit,
        Err(e) => {
            return Err(format!("Could not create circuit: {}", e));
        }
    };

    let rng = &mut OsRng;

    // println!("{}", "Creating parameters with BLS12-381 pairing-friendly elliptic curve construction....".red().on_blue());
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).unwrap();

    // println!("{}", "Creating proof for zkSNARK...".yellow());
    let proof = groth16::create_random_proof(circuit.clone(), &params, rng).unwrap();

    // println!("{}: {:?}", "PROOF".red(), proof);

    // println!("{}", "Prepare verifying key for zkSNARK...".yellow());
    let pvk = groth16::prepare_verifying_key(&params.vk);

    // println!("{}", "Extracting public parameters for zkSNARK...".yellow());

    // let public_parameters = extract_public_parameters(&parsed_proofs);

    // println!("{}", "Verifying zkSNARK proof...".yellow());
    groth16::verify_proof(
        &pvk,
        &proof,
        &[
            hex_to_scalar(&previous_commitment.as_str()),
            hex_to_scalar(&current_commitment.as_str())
        ],
    ).unwrap();

    // println!("{}", "zkSNARK with groth16 random parameters was successfully verified!".green());
    Ok(proof)
}

