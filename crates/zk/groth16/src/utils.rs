use crate::ProofVariantCircuit;
use anyhow::{anyhow, Result};
use bellman::groth16::{self, VerifyingKey};
use bls12_381::{Bls12, Scalar};
use indexed_merkle_tree::{node::Node, sha256_mod, tree::MerkleProof, Hash};
use prism_errors::{GeneralError, PrismError, ProofError};
use rand::rngs::OsRng;

pub fn create_and_verify_snark(
    circuit: ProofVariantCircuit,
    scalars: Vec<Scalar>,
) -> Result<(groth16::Proof<Bls12>, VerifyingKey<Bls12>)> {
    let rng = &mut OsRng;

    trace!("creating parameters with BLS12-381 pairing-friendly elliptic curve construction....");
    let params =
        groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).map_err(|e| {
            PrismError::Proof(ProofError::ProofUnpackError(format!(
                "generating random params: {}",
                e
            )))
        })?;

    trace!("creating proof for zkSNARK...");
    let proof = groth16::create_random_proof(circuit, &params, rng)
        .map_err(|e| PrismError::Proof(ProofError::GenerationError(e.to_string())))?;

    trace!("preparing verifying key for zkSNARK...");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    groth16::verify_proof(&pvk, &proof, &scalars)
        .map_err(|e| PrismError::Proof(ProofError::VerificationError(e.to_string())))?;

    Ok((proof, params.vk))
}

pub fn unpack_and_process(proof: &MerkleProof) -> Result<(Scalar, &Vec<Node>)> {
    if !proof.path.is_empty() {
        let root: Scalar = proof.root_hash.try_into()?;
        Ok((root, &proof.path))
    } else {
        Err(anyhow!(ProofError::ProofUnpackError(format!(
            "proof path is empty for root hash {}",
            proof.root_hash
        ))))
    }
}

pub fn validate_epoch(
    previous_commitment: &Hash,
    current_commitment: &Hash,
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

pub fn recalculate_hash_as_scalar(path: &[Node]) -> Result<Scalar> {
    let mut current_hash = path[0].get_hash();
    for node in path.iter().skip(1) {
        let combined = if node.is_left_sibling() {
            [node.get_hash().as_ref(), current_hash.as_ref()].concat()
        } else {
            [current_hash.as_ref(), node.get_hash().as_ref()].concat()
        };
        current_hash = sha256_mod(&combined);
    }
    current_hash.try_into()
}
