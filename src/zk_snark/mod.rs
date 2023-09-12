use crate::{
    indexed_merkle_tree::{sha256, MerkleProof, Node, ProofVariant, UpdateProof},
    storage::ChainEntry,
};
use base64;
use bellman::{groth16::Proof, Circuit, ConstraintSystem, SynthesisError};
use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};
use serde::{Deserialize, Serialize};

fn vec_to_96_array(vec: Vec<u8>) -> Result<[u8; 96], &'static str> {
    let mut array = [0u8; 96];
    if vec.len() != 96 {
        return Err("Length mismatch");
    }
    array.copy_from_slice(&vec);
    Ok(array)
}

fn vec_to_192_array(vec: Vec<u8>) -> Result<[u8; 192], &'static str> {
    let mut array = [0u8; 192];
    if vec.len() != 192 {
        return Err("Length mismatch");
    }
    array.copy_from_slice(&vec);
    Ok(array)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Bls12Proof {
    pub a: String,
    pub b: String,
    pub c: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct VerifyingKey {
    pub alpha_g1: String,
    pub beta_g1: String,
    pub beta_g2: String,
    pub delta_g1: String,
    pub delta_g2: String,
    pub gamma_g2: String,
    pub ic: String,
}

pub fn serialize_proof(proof: &Proof<Bls12>) -> Bls12Proof {
    Bls12Proof {
        a: base64::encode(&proof.a.to_uncompressed().as_ref()),
        b: base64::encode(&proof.b.to_uncompressed().as_ref()),
        c: base64::encode(&proof.c.to_uncompressed().as_ref()),
    }
}

pub fn deserialize_proof(proof: &Bls12Proof) -> Result<Proof<Bls12>, &'static str> {
    let a =
        G1Affine::from_uncompressed(&vec_to_96_array(base64::decode(&proof.a).unwrap())?).unwrap();
    let b =
        G2Affine::from_uncompressed(&vec_to_192_array(base64::decode(&proof.b).unwrap())?).unwrap();
    let c =
        G1Affine::from_uncompressed(&vec_to_96_array(base64::decode(&proof.c).unwrap())?).unwrap();

    Ok(Proof { a, b, c })
}

pub fn serialize_verifying_key_to_custom(
    verifying_key: &bellman::groth16::VerifyingKey<Bls12>,
) -> VerifyingKey {
    VerifyingKey {
        alpha_g1: base64::encode(&verifying_key.alpha_g1.to_uncompressed().as_ref()),
        beta_g1: base64::encode(&verifying_key.beta_g1.to_uncompressed().as_ref()),
        beta_g2: base64::encode(&verifying_key.beta_g2.to_uncompressed().as_ref()),
        delta_g1: base64::encode(&verifying_key.delta_g1.to_uncompressed().as_ref()),
        delta_g2: base64::encode(&verifying_key.delta_g2.to_uncompressed().as_ref()),
        gamma_g2: base64::encode(&verifying_key.gamma_g2.to_uncompressed().as_ref()),
        ic: verifying_key
            .ic
            .iter()
            .map(|x| base64::encode(&x.to_uncompressed().as_ref()))
            .collect::<Vec<String>>()
            .join(","),
    }
}

pub fn deserialize_custom_to_verifying_key(
    custom_vk: &VerifyingKey,
) -> Result<bellman::groth16::VerifyingKey<Bls12>, &'static str> {
    let alpha_g1 = G1Affine::from_uncompressed(&vec_to_96_array(
        base64::decode(&custom_vk.alpha_g1).unwrap(),
    )?)
    .unwrap();
    let beta_g1 = G1Affine::from_uncompressed(&vec_to_96_array(
        base64::decode(&custom_vk.beta_g1).unwrap(),
    )?)
    .unwrap();
    let beta_g2 = G2Affine::from_uncompressed(&vec_to_192_array(
        base64::decode(&custom_vk.beta_g2).unwrap(),
    )?)
    .unwrap();
    let delta_g1 = G1Affine::from_uncompressed(&vec_to_96_array(
        base64::decode(&custom_vk.delta_g1).unwrap(),
    )?)
    .unwrap();
    let delta_g2 = G2Affine::from_uncompressed(&vec_to_192_array(
        base64::decode(&custom_vk.delta_g2).unwrap(),
    )?)
    .unwrap();
    let gamma_g2 = G2Affine::from_uncompressed(&vec_to_192_array(
        base64::decode(&custom_vk.gamma_g2).unwrap(),
    )?)
    .unwrap();
    let ic = custom_vk
        .ic
        .split(",")
        .map(|s| {
            let decoded = base64::decode(s).unwrap();
            let array = vec_to_96_array(decoded).unwrap();
            let ct_option = G1Affine::from_uncompressed(&array).unwrap();
            ct_option
        })
        .collect();

    Ok(bellman::groth16::VerifyingKey {
        alpha_g1,
        beta_g1,
        beta_g2,
        gamma_g2,
        delta_g1,
        delta_g2,
        ic,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        indexed_merkle_tree::{sha256, IndexedMerkleTree, Node},
        zk_snark::{deserialize_proof, Bls12Proof},
    };

    use super::*;
    use bellman::groth16;
    use bls12_381::Bls12;
    use rand::rngs::OsRng;

    #[test]
    fn test_serialize_and_deserialize_proof() {
        // Initial setup
        let empty_hash = Node::EMPTY_HASH.to_string();
        let tail = Node::TAIL.to_string();
        let active_node = Node::initialize_leaf(
            true,
            true,
            empty_hash.clone(),
            empty_hash.clone(),
            tail.clone(),
        );
        let inactive_node = Node::initialize_leaf(
            false,
            true,
            empty_hash.clone(),
            empty_hash.clone(),
            tail.clone(),
        );

        // build a tree with 4 nodes
        let mut tree = IndexedMerkleTree::new(vec![
            active_node,
            inactive_node.clone(),
            inactive_node.clone(),
            inactive_node,
        ]);
        let prev_commitment = tree.get_commitment();

        // create two nodes to insert
        let ryan = sha256(&"Ryan".to_string());
        let ford = sha256(&"Ford".to_string());
        let sebastian = sha256(&"Sebastian".to_string());
        let pusch = sha256(&"Pusch".to_string());
        let ryans_node = Node::initialize_leaf(true, true, ryan, ford, tail.clone());
        let sebastians_node = Node::initialize_leaf(true, true, sebastian, pusch, tail.clone());

        // generate proofs for the two nodes
        let first_insert_proof = tree.generate_proof_of_insert(&ryans_node);
        let second_insert_proof = tree.generate_proof_of_insert(&sebastians_node);

        // create zkSNARKs for the two proofs
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

        let serialized_proof = serialize_proof(&proof);
        let deserialized_proof_result = deserialize_proof(&serialized_proof);
        assert!(deserialized_proof_result.is_ok(), "Deserialization failed");

        let deserialized_proof = deserialized_proof_result.unwrap();
        assert_eq!(proof.a, deserialized_proof.a);
        assert_eq!(proof.b, deserialized_proof.b);
        assert_eq!(proof.c, deserialized_proof.c);
    }

    /* #[test]
    fn test_deserialize_invalid_proof() {
        // Erstellen Sie ein ungültiges Bls12Proof-Objekt
        let invalid_proof = Bls12Proof {
            a: "blubbubs".to_string(),
            b: "FTV0oqNyecdbzY9QFPe5gfiQbSn1E0t+QHn+l+Ey6G2Dk0UZFm1wMsnRbIp5HCneDC+jf6rHCADL1NQ9FIF9o5Td8jObATCRm/YoIoeXY1yFY1rCEoJWFZU0zPeOR7XfBEmccqdMATwb8yznOj6Hn9XqZIr7E3C0XBtzk9GiahLopjP+SN9v/KLEpnLm3dn5FeAp7TcJ0gibi4nNT3u2vziKRNiDIKl71bp6tNC6grCdGOazpkrFSxiYi3QHJOYI".to_string(),
            c: "BEKZboEyoJ3l+DLIF8IMjUR2kJQ9aq2kuXTZR8YizcQMg7zTH0xLO9JtTueneS3JFx1KlK6e2NkFZamiQERujx6bhmwIDgY8ZPCJ8iG//4E3eS0CZ25CJfnOucLeotyr".to_string(),
        };

        // Versuchen Sie, das ungültige Objekt zu deserialisieren
        let deserialized_proof_result = deserialize_proof(&invalid_proof);

        // Überprüfen Sie, ob die Deserialisierung fehlgeschlagen ist
        assert!(deserialized_proof_result.is_err());
    } */
}

#[derive(Clone)]
pub struct HashChainEntryCircuit {
    pub value: Scalar,
    pub chain: Vec<Scalar>,
}

#[derive(Clone)]
pub struct UpdateMerkleProofCircuit {
    pub old_root: Scalar,
    pub old_path: Vec<Node>,
    pub updated_root: Scalar,
    pub updated_path: Vec<Node>,
}

#[derive(Clone)]
pub struct InsertMerkleProofCircuit {
    pub non_membership_root: Scalar,
    pub non_membership_path: Vec<Node>,
    pub first_merkle_proof: UpdateMerkleProofCircuit,
    pub second_merkle_proof: UpdateMerkleProofCircuit,
}

#[derive(Clone)]
pub enum ProofVariantCircuit {
    Update(UpdateMerkleProofCircuit),
    Insert(InsertMerkleProofCircuit),
}

#[derive(Clone)]
pub struct BatchMerkleProofCircuit {
    pub old_commitment: Scalar,
    pub new_commitment: Scalar,
    pub proofs: Vec<ProofVariantCircuit>,
}

pub fn hex_to_scalar(hex_string: &str) -> Scalar {
    let byte_array: [u8; 32] = hex::decode(hex_string).unwrap().try_into().unwrap();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&byte_array); // Fill 0s in front of it, then the value remains the same
    Scalar::from_bytes_wide(&wide)
}

pub fn recalculate_hash_as_scalar(path: &[Node]) -> Scalar {
    let mut current_hash = path[0].get_hash();
    for i in 1..(path.len()) {
        let sibling = &path[i];
        if sibling.is_left_sibling() {
            current_hash = sha256(&format!("H({} || {})", &sibling.get_hash(), current_hash));
        } else {
            current_hash = sha256(&format!("H({} || {})", current_hash, &sibling.get_hash()));
        }
    }
    hex_to_scalar(&current_hash.as_str())
}

fn proof_of_update<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    old_root: Scalar,
    old_path: &[Node],
    new_root: Scalar,
    new_path: &[Node],
) -> Result<Scalar, SynthesisError> {
    let root_with_old_pointer =
        cs.alloc(|| "first update root with old pointer", || Ok(old_root))?;
    let root_with_new_pointer =
        cs.alloc(|| "first update root with new pointer", || Ok(new_root))?;

    // update the root hash for old and new path
    let recalculated_root_with_old_pointer = recalculate_hash_as_scalar(&old_path);
    let recalculated_root_with_new_pointer = recalculate_hash_as_scalar(&new_path);

    // Allocate variables for the calculated roots of the old and new nodes
    let allocated_recalculated_root_with_old_pointer = cs.alloc(
        || "recalculated first update proof old root",
        || Ok(recalculated_root_with_old_pointer),
    )?;
    let allocated_recalculated_root_with_new_pointer = cs.alloc(
        || "recalculated first update proof new root",
        || Ok(recalculated_root_with_new_pointer),
    )?;

    // Überprüfe, ob der resultierende Hash der Wurzel-Hash des alten Baums entspricht
    cs.enforce(
        || "first update old root equality",
        |lc| lc + allocated_recalculated_root_with_old_pointer,
        |lc| lc + CS::one(),
        |lc| lc + root_with_old_pointer,
    );
    // lc stands for the current linear combination and we add variables to this linear combination to create a new linear combination altogether, which is then used as argument for the enforce method.
    // Check that the resulting hash is the root hash of the new tree.
    cs.enforce(
        || "first update new root equality",
        |lc| lc + allocated_recalculated_root_with_new_pointer,
        |lc| lc + CS::one(),
        |lc| lc + root_with_new_pointer,
    );

    Ok(recalculated_root_with_new_pointer)
}

fn proof_of_non_membership<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    non_membership_root: Scalar,
    non_membership_path: &[Node],
) -> Result<(), SynthesisError> {
    let allocated_root = cs.alloc(|| "non_membership_root", || Ok(non_membership_root))?;
    let recalculated_root = recalculate_hash_as_scalar(non_membership_path);
    let allocated_recalculated_root = cs.alloc(
        || "recalculated non-membership root",
        || Ok(recalculated_root),
    )?;

    cs.enforce(
        || "non-membership root check",
        |lc| lc + allocated_root,
        |lc| lc + CS::one(),
        |lc| lc + allocated_recalculated_root,
    );

    Ok(())
}

impl Circuit<Scalar> for InsertMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Proof of Non-Membership
        match proof_of_non_membership(cs, self.non_membership_root, &self.non_membership_path) {
            Ok(_) => (),
            Err(_) => return Err(SynthesisError::AssignmentMissing),
        }

        // Proof of Update for old and new node
        let first_proof = proof_of_update(
            cs,
            self.first_merkle_proof.old_root,
            &self.first_merkle_proof.old_path,
            self.first_merkle_proof.updated_root,
            &self.first_merkle_proof.updated_path,
        );
        let second_update = proof_of_update(
            cs,
            first_proof.unwrap(),
            &self.second_merkle_proof.old_path,
            self.second_merkle_proof.updated_root,
            &self.second_merkle_proof.updated_path,
        );

        match second_update {
            Ok(_) => Ok(()),
            Err(_) => return Err(SynthesisError::Unsatisfiable),
        }
    }
}

impl Circuit<Scalar> for UpdateMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Proof of Update for the old and new node
        match proof_of_update(
            cs,
            self.old_root,
            &self.old_path,
            self.updated_root,
            &self.updated_path,
        ) {
            Ok(_) => Ok(()),
            Err(_) => return Err(SynthesisError::Unsatisfiable),
        }
    }
}

impl Circuit<Scalar> for BatchMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if &self.proofs.len() == &0 {
            let provided_old_commitment =
                cs.alloc_input(|| "provided old commitment", || Ok(self.old_commitment))?;
            let provided_new_commitment =
                cs.alloc_input(|| "provided new commitment", || Ok(self.new_commitment))?;
            cs.enforce(
                || "old commitment check",
                |lc| lc + provided_old_commitment,
                |lc| lc + CS::one(),
                |lc| lc + provided_new_commitment,
            );

            return Ok(());
        }

        // before the calculations make sure that the old root is that of the first proof
        let old_root = match &self.proofs[0] {
            ProofVariantCircuit::Update(update_proof_circuit) => update_proof_circuit.old_root,
            ProofVariantCircuit::Insert(insert_proof_circuit) => {
                insert_proof_circuit.non_membership_root
            }
        };

        println!("old root: {:?}", old_root);
        println!("old commitment: {:?}", self.old_commitment);

        let provided_old_commitment =
            cs.alloc_input(|| "provided old commitment", || Ok(self.old_commitment))?;
        let old_commitment_from_proofs =
            cs.alloc(|| "old commitment from proofs", || Ok(old_root))?;

        cs.enforce(
            || "old commitment check",
            |lc| lc + old_commitment_from_proofs,
            |lc| lc + CS::one(),
            |lc| lc + provided_old_commitment,
        );

        let mut new_commitment: Option<Scalar> = None;
        for proof_variant in self.proofs {
            match proof_variant {
                ProofVariantCircuit::Update(update_proof_circuit) => {
                    new_commitment = Some(proof_of_update(
                        cs,
                        update_proof_circuit.old_root,
                        &update_proof_circuit.old_path,
                        update_proof_circuit.updated_root,
                        &update_proof_circuit.updated_path,
                    )?);
                }
                ProofVariantCircuit::Insert(insert_proof_circuit) => {
                    // Proof of Non-Membership
                    match proof_of_non_membership(
                        cs,
                        insert_proof_circuit.non_membership_root,
                        &insert_proof_circuit.non_membership_path,
                    ) {
                        Ok(_) => (),
                        Err(_) => return Err(SynthesisError::AssignmentMissing),
                    }

                    // Proof of Update for the old and new node
                    let calculated_root_from_first_proof = proof_of_update(
                        cs,
                        insert_proof_circuit.first_merkle_proof.old_root,
                        &insert_proof_circuit.first_merkle_proof.old_path,
                        insert_proof_circuit.first_merkle_proof.updated_root,
                        &insert_proof_circuit.first_merkle_proof.updated_path,
                    )
                    .expect("first proof of update in insert proof failed");
                    new_commitment = Some(
                        proof_of_update(
                            cs,
                            calculated_root_from_first_proof,
                            &insert_proof_circuit.second_merkle_proof.old_path,
                            insert_proof_circuit.second_merkle_proof.updated_root,
                            &insert_proof_circuit.second_merkle_proof.updated_path,
                        )
                        .expect("second proof of update in insert proof failed"),
                    );
                }
            }
        }

        println!("new commitment: {:?}", self.new_commitment);
        println!("new commitment calculated: {:?}", new_commitment.unwrap());

        let provided_new_commitment =
            cs.alloc_input(|| "provided commitment", || Ok(self.new_commitment))?;
        let recalculated_new_commitment =
            cs.alloc(|| "recalculated commitment", || Ok(new_commitment.unwrap()))?;

        cs.enforce(
            || "new commitment check",
            |lc| lc + recalculated_new_commitment,
            |lc| lc + CS::one(),
            |lc| lc + provided_new_commitment,
        );

        Ok(())
    }
}

impl Circuit<Scalar> for HashChainEntryCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if &self.chain.len() == &0 {
            return Err(SynthesisError::AssignmentMissing);
        }

        let provided_value = cs.alloc_input(|| "provided hashed value", || Ok(self.value))?;

        for entry in self.chain {
            if entry == self.value {
                let found_value = cs.alloc(|| "found hashed value", || Ok(entry))?;
                cs.enforce(
                    || "found value check",
                    |lc| lc + found_value,
                    |lc| lc + CS::one(),
                    |lc| lc + provided_value,
                );
                return Ok(());
            }
        }
        return Err(SynthesisError::Unsatisfiable);
    }
}

// create the circuit based on the given Merkle proof
impl InsertMerkleProofCircuit {
    pub fn create(
        proof: &(MerkleProof, UpdateProof, UpdateProof),
    ) -> Result<InsertMerkleProofCircuit, &'static str> {
        // Unwrap proof values and handle possible errors
        let (non_membership_root, non_membership_path) = match &proof.0 {
            (Some(non_membership_root), Some(non_membership_path)) => {
                (hex_to_scalar(non_membership_root), non_membership_path)
            }
            _ => return Err("Failed to unwrap the old root and old path"),
        };

        let (first_update_old_root, first_update_old_path) = match &proof.1 .0 {
            (Some(first_update_old_root), Some(first_update_old_path)) => {
                (hex_to_scalar(first_update_old_root), first_update_old_path)
            }
            _ => return Err("Failed to unwrap the first update oldroot and the old path"),
        };

        let (first_update_new_root, first_update_new_path) = match &proof.1 .1 {
            (Some(first_update_new_root), Some(first_update_new_path)) => {
                (hex_to_scalar(first_update_new_root), first_update_new_path)
            }
            _ => return Err("Failed to unwrap the first update newroot and the new path"),
        };

        let (second_update_old_root, second_update_old_path) = match &proof.2 .0 {
            (Some(second_update_old_root), Some(second_update_old_path)) => (
                hex_to_scalar(second_update_old_root),
                second_update_old_path,
            ),
            _ => return Err("Failed to unwrap the second update oldroot and the old path"),
        };

        let (second_update_new_root, second_update_new_path) = match &proof.2 .1 {
            (Some(second_update_new_root), Some(second_update_new_path)) => (
                hex_to_scalar(second_update_new_root),
                second_update_new_path,
            ),
            _ => return Err("Failed to unwrap the second update newroot and the new path"),
        };

        let first_merkle_proof_circuit = UpdateMerkleProofCircuit {
            old_root: first_update_old_root,
            old_path: first_update_old_path.clone(),
            updated_root: first_update_new_root,
            updated_path: first_update_new_path.clone(),
        };

        let second_merkle_proof_circuit = UpdateMerkleProofCircuit {
            old_root: second_update_old_root,
            old_path: second_update_old_path.clone(),
            updated_root: second_update_new_root,
            updated_path: second_update_new_path.clone(),
        };

        // Erstelle die MerkleProofCircuit-Instanz
        Ok(InsertMerkleProofCircuit {
            non_membership_root,
            non_membership_path: non_membership_path.clone(),
            first_merkle_proof: first_merkle_proof_circuit,
            second_merkle_proof: second_merkle_proof_circuit,
        })
    }
}

impl BatchMerkleProofCircuit {
    pub fn create(
        old_commitment: &String,
        new_commitment: &String,
        proofs: Vec<ProofVariant>,
    ) -> Result<BatchMerkleProofCircuit, &'static str> {
        let parsed_old_commitment = hex_to_scalar(&old_commitment.as_str());
        let parsed_new_commitment = hex_to_scalar(&new_commitment.as_str());
        let mut proof_circuit_array: Vec<ProofVariantCircuit> = vec![];
        for proof in proofs {
            match proof {
                ProofVariant::Update(update_proof) => {
                    proof_circuit_array
                        .push(BatchMerkleProofCircuit::create_from_update(&update_proof).unwrap());
                }
                ProofVariant::Insert(merkle_proof, first_update, second_update) => {
                    proof_circuit_array.push(
                        BatchMerkleProofCircuit::create_from_insert(&(
                            merkle_proof,
                            first_update,
                            second_update,
                        ))
                        .unwrap(),
                    );
                }
            }
        }
        Ok(BatchMerkleProofCircuit {
            old_commitment: parsed_old_commitment,
            new_commitment: parsed_new_commitment,
            proofs: proof_circuit_array,
        })
    }

    pub fn create_from_update(
        ((old_root, old_path), (updated_root, updated_path)): &UpdateProof,
    ) -> Result<ProofVariantCircuit, &'static str> {
        // Unwrap proof values and handle possible errors
        let old_root = hex_to_scalar(&old_root.clone().unwrap().as_str());
        let updated_root = hex_to_scalar(&updated_root.clone().unwrap().as_str());

        let merkle_proof_circuit = UpdateMerkleProofCircuit {
            old_root,
            old_path: old_path.clone().unwrap().clone(),
            updated_root,
            updated_path: updated_path.clone().unwrap().clone(),
        };

        // Create the MerkleProofCircuit-Instance
        Ok(ProofVariantCircuit::Update(merkle_proof_circuit))
    }

    pub fn create_from_insert(
        proofs: &(MerkleProof, UpdateProof, UpdateProof),
    ) -> Result<ProofVariantCircuit, &'static str> {
        let (
            non_membership_proof,
            (first_update_old, first_update_new),
            (second_update_old, second_update_new),
        ) = proofs;

        // Unwrap proof values and handle possible errors
        let (non_membership_root, non_membership_path) = match &non_membership_proof {
            (Some(non_membership_root), Some(non_membership_path)) => {
                (hex_to_scalar(non_membership_root), non_membership_path)
            }
            _ => return Err("Failed to unwrap the old root and old path"),
        };

        let (first_update_old_root, first_update_old_path) = match &first_update_old {
            (Some(first_update_old_root), Some(first_update_old_path)) => {
                (hex_to_scalar(first_update_old_root), first_update_old_path)
            }
            _ => return Err("Failed to unwrap the first update oldroot and the old path"),
        };

        let (first_update_new_root, first_update_new_path) = match &first_update_new {
            (Some(first_update_new_root), Some(first_update_new_path)) => {
                (hex_to_scalar(first_update_new_root), first_update_new_path)
            }
            _ => return Err("Failed to unwrap the first update newroot and the new path"),
        };

        let (second_update_old_root, second_update_old_path) = match &second_update_old {
            (Some(second_update_old_root), Some(second_update_old_path)) => (
                hex_to_scalar(second_update_old_root),
                second_update_old_path,
            ),
            _ => return Err("Failed to unwrap the second update oldroot and the old path"),
        };

        let (second_update_new_root, second_update_new_path) = match &second_update_new {
            (Some(second_update_new_root), Some(second_update_new_path)) => (
                hex_to_scalar(second_update_new_root),
                second_update_new_path,
            ),
            _ => return Err("Failed to unwrap the second update newroot and the new path"),
        };

        let first_merkle_proof_circuit = UpdateMerkleProofCircuit {
            old_root: first_update_old_root,
            old_path: first_update_old_path.clone(),
            updated_root: first_update_new_root,
            updated_path: first_update_new_path.clone(),
        };

        let second_merkle_proof_circuit = UpdateMerkleProofCircuit {
            old_root: second_update_old_root,
            old_path: second_update_old_path.clone(),
            updated_root: second_update_new_root,
            updated_path: second_update_new_path.clone(),
        };

        let insert_proof_circuit = InsertMerkleProofCircuit {
            non_membership_root,
            non_membership_path: non_membership_path.clone(),
            first_merkle_proof: first_merkle_proof_circuit,
            second_merkle_proof: second_merkle_proof_circuit,
        };

        // Create the MerkleProofCircuit-Instance
        Ok(ProofVariantCircuit::Insert(insert_proof_circuit))
    }
}

impl HashChainEntryCircuit {
    pub fn create(
        value: &String,
        hashchain: Vec<ChainEntry>,
    ) -> Result<HashChainEntryCircuit, &'static str> {
        // hash the clear text and parse it to scalar
        let hashed_value = sha256(&value);
        let parsed_value = hex_to_scalar(&hashed_value);
        let mut parsed_hashchain: Vec<Scalar> = vec![];
        for entry in hashchain {
            parsed_hashchain.push(hex_to_scalar(entry.value.as_str()))
        }
        Ok(HashChainEntryCircuit {
            value: parsed_value,
            chain: parsed_hashchain,
        })
    }

    pub fn create_public_parameter(value: &String) -> Scalar {
        let hashed_value = sha256(&value);
        hex_to_scalar(&hashed_value)
    }
}
