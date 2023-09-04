use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bls12_381::{Scalar, Bls12};
use bellman::groth16::{Proof};
use serde::{Serialize, Deserialize};
use crate::indexed_merkle_tree::{MerkleProof, UpdateProof, ProofVariant};
use crate::indexed_merkle_tree::{Node};
use crate::indexed_merkle_tree::{sha256};
use crate::storage::ChainEntry;

#[derive(Clone, Serialize, Deserialize)]
pub struct Bls12Proof {
    a: String,
    b: String,
    c: String,
}

pub fn convert_proof_to_custom(proof: &Proof<Bls12>) -> Bls12Proof {
    Bls12Proof {
        a: proof.a.to_string(),
        b: proof.b.to_string(),
        c: proof.c.to_string(),
    }
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
    let byte_array: [u8; 32]  = hex::decode(hex_string).unwrap().try_into().unwrap();
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
        let root_with_old_pointer = cs.alloc(|| "first update root with old pointer", || Ok(old_root))?;
        let root_with_new_pointer = cs.alloc(|| "first update root with new pointer", || Ok(new_root))?;

        // update the root hash for old and new path
        let recalculated_root_with_old_pointer = recalculate_hash_as_scalar(&old_path);
        let recalculated_root_with_new_pointer = recalculate_hash_as_scalar(&new_path);

        // Allocate variables for the calculated roots of the old and new nodes
        let allocated_recalculated_root_with_old_pointer = cs.alloc(|| "recalculated first update proof old root", || Ok(recalculated_root_with_old_pointer))?;
        let allocated_recalculated_root_with_new_pointer = cs.alloc(|| "recalculated first update proof new root", || Ok(recalculated_root_with_new_pointer))?;
        
        // Überprüfe, ob der resultierende Hash der Wurzel-Hash des alten Baums entspricht
        cs.enforce(|| "first update old root equality", |lc| lc + allocated_recalculated_root_with_old_pointer, |lc| lc + CS::one(), |lc| lc + root_with_old_pointer);
        // lc stands for the current linear combination and we add variables to this linear combination to create a new linear combination altogether, which is then used as argument for the enforce method.
        // Check that the resulting hash is the root hash of the new tree.
        cs.enforce(|| "first update new root equality", |lc| lc + allocated_recalculated_root_with_new_pointer, |lc| lc + CS::one(), |lc| lc + root_with_new_pointer);

        Ok(recalculated_root_with_new_pointer)
}

fn proof_of_non_membership<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    non_membership_root: Scalar,
    non_membership_path: &[Node],
) -> Result<(), SynthesisError> {
    let allocated_root = cs.alloc(|| "non_membership_root", || Ok(non_membership_root))?;
    let recalculated_root = recalculate_hash_as_scalar(non_membership_path);
    let allocated_recalculated_root = cs.alloc(|| "recalculated non-membership root", || Ok(recalculated_root))?;

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
        let first_proof = proof_of_update(cs, self.first_merkle_proof.old_root, &self.first_merkle_proof.old_path, self.first_merkle_proof.updated_root, &self.first_merkle_proof.updated_path);
        let second_update = proof_of_update(cs, first_proof.unwrap(), &self.second_merkle_proof.old_path, self.second_merkle_proof.updated_root, &self.second_merkle_proof.updated_path);
        
        match second_update {
            Ok(_) => Ok(()),
            Err(_) => return Err(SynthesisError::Unsatisfiable),
        }
    }
}


impl Circuit<Scalar> for UpdateMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Proof of Update for the old and new node
        match proof_of_update(cs, self.old_root, &self.old_path, self.updated_root, &self.updated_path) {
            Ok(_) => Ok(()),
            Err(_) => return Err(SynthesisError::Unsatisfiable),
        }
    }
}

impl Circuit<Scalar> for BatchMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if &self.proofs.len() == &0 {
            let provided_old_commitment = cs.alloc_input(|| "provided old commitment", || Ok(self.old_commitment))?;
            let provided_new_commitment = cs.alloc_input(|| "provided new commitment", || Ok(self.new_commitment))?;
            cs.enforce(
                || "old commitment check",
                |lc| lc + provided_old_commitment,
                |lc| lc + CS::one(),
                |lc| lc + provided_new_commitment,
            );

            return Ok(())
        }

        // before the calculations make sure that the old root is that of the first proof
        let old_root = match &self.proofs[0] {
            ProofVariantCircuit::Update(update_proof_circuit) => update_proof_circuit.old_root,
            ProofVariantCircuit::Insert(insert_proof_circuit) => insert_proof_circuit.non_membership_root,
        };

        println!("old root: {:?}", old_root);
        println!("old commitment: {:?}", self.old_commitment);
        
        let provided_old_commitment = cs.alloc_input(|| "provided old commitment", || Ok(self.old_commitment))?;
        let old_commitment_from_proofs = cs.alloc(||"old commitment from proofs", || Ok(old_root))?;

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
                    match proof_of_non_membership(cs, insert_proof_circuit.non_membership_root, &insert_proof_circuit.non_membership_path) {
                        Ok(_) => (),
                        Err(_) => return Err(SynthesisError::AssignmentMissing),
                    }

                    // Proof of Update for the old and new node
                    let calculated_root_from_first_proof = proof_of_update(cs, insert_proof_circuit.first_merkle_proof.old_root, &insert_proof_circuit.first_merkle_proof.old_path, insert_proof_circuit.first_merkle_proof.updated_root, &insert_proof_circuit.first_merkle_proof.updated_path).expect("first proof of update in insert proof failed");
                    new_commitment =  Some(proof_of_update(cs, calculated_root_from_first_proof, &insert_proof_circuit.second_merkle_proof.old_path, insert_proof_circuit.second_merkle_proof.updated_root, &insert_proof_circuit.second_merkle_proof.updated_path).expect("second proof of update in insert proof failed"));
                }
            }
        }

        println!("new commitment: {:?}", self.new_commitment);
        println!("new commitment calculated: {:?}", new_commitment.unwrap());

        let provided_new_commitment = cs.alloc_input(|| "provided commitment", || Ok(self.new_commitment))?;
        let recalculated_new_commitment = cs.alloc(||"recalculated commitment", || Ok(new_commitment.unwrap()))?;

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
                return Ok(())
            }
        }
        return Err(SynthesisError::Unsatisfiable);
    }
}

// create the circuit based on the given Merkle proof
impl InsertMerkleProofCircuit {
    pub fn create(proof: &(MerkleProof, UpdateProof, UpdateProof)) -> Result<InsertMerkleProofCircuit, &'static str> {
        // Unwrap proof values and handle possible errors
        let (non_membership_root, non_membership_path) = match &proof.0 {
            (Some(non_membership_root), Some(non_membership_path)) => (hex_to_scalar(non_membership_root), non_membership_path),
            _ => return Err("Failed to unwrap the old root and old path"),
        };

        let (first_update_old_root, first_update_old_path) = match &proof.1.0 {
            (Some(first_update_old_root), Some(first_update_old_path)) => (hex_to_scalar(first_update_old_root), first_update_old_path),
            _ => return Err("Failed to unwrap the first update oldroot and the old path"),
        };
        
        let (first_update_new_root, first_update_new_path) = match &proof.1.1 {
            (Some(first_update_new_root), Some(first_update_new_path)) => (hex_to_scalar(first_update_new_root), first_update_new_path),
            _ => return Err("Failed to unwrap the first update newroot and the new path"),
        };
        
        let (second_update_old_root, second_update_old_path) = match &proof.2.0 {
            (Some(second_update_old_root), Some(second_update_old_path)) => (hex_to_scalar(second_update_old_root), second_update_old_path),
            _ => return Err("Failed to unwrap the second update oldroot and the old path"),
        };

        let (second_update_new_root, second_update_new_path) = match &proof.2.1 {
            (Some(second_update_new_root), Some(second_update_new_path)) => (hex_to_scalar(second_update_new_root), second_update_new_path),
            _ => return Err("Failed to unwrap the second update newroot and the new path"),
        };

        let first_merkle_proof_circuit = UpdateMerkleProofCircuit {
            old_root: first_update_old_root,
            old_path: first_update_old_path.clone(),
            updated_root: first_update_new_root,
            updated_path: first_update_new_path.clone()
        };
  
        let second_merkle_proof_circuit = UpdateMerkleProofCircuit {
            old_root: second_update_old_root,
            old_path: second_update_old_path.clone(),
            updated_root: second_update_new_root,
            updated_path: second_update_new_path.clone()
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
    pub fn create(old_commitment: &String, new_commitment: &String, proofs: Vec<ProofVariant>) -> Result<BatchMerkleProofCircuit, &'static str> {
        let parsed_old_commitment = hex_to_scalar(&old_commitment.as_str());
        let parsed_new_commitment = hex_to_scalar(&new_commitment.as_str());
        let mut proof_circuit_array: Vec<ProofVariantCircuit> = vec![];
        for proof in proofs {
            match proof {
                ProofVariant::Update(update_proof) => {
                    proof_circuit_array.push(BatchMerkleProofCircuit::create_from_update(&update_proof).unwrap());
                },
                ProofVariant::Insert(merkle_proof, first_update, second_update) => {
                    proof_circuit_array.push(BatchMerkleProofCircuit::create_from_insert(&(merkle_proof, first_update, second_update)).unwrap());
                }
            }
        }
        Ok(BatchMerkleProofCircuit {
            old_commitment: parsed_old_commitment,
            new_commitment: parsed_new_commitment,
            proofs: proof_circuit_array,
        })
    }

    pub fn create_from_update(((old_root, old_path), (updated_root, updated_path)): &UpdateProof) -> Result<ProofVariantCircuit, &'static str> {
        // Unwrap proof values and handle possible errors
       let old_root = hex_to_scalar(&old_root.clone().unwrap().as_str());
       let updated_root = hex_to_scalar(&updated_root.clone().unwrap().as_str());

       let merkle_proof_circuit = UpdateMerkleProofCircuit {
           old_root,
           old_path: old_path.clone().unwrap().clone(),
           updated_root,
           updated_path: updated_path.clone().unwrap().clone()
       };

       // Create the MerkleProofCircuit-Instance
       Ok(ProofVariantCircuit::Update(merkle_proof_circuit))
   }

   pub fn create_from_insert(proofs: &(MerkleProof, UpdateProof, UpdateProof)) -> Result<ProofVariantCircuit, &'static str> {
    let (non_membership_proof, (first_update_old, first_update_new), (second_update_old, second_update_new)) = proofs;

       // Unwrap proof values and handle possible errors
       let (non_membership_root, non_membership_path) = match &non_membership_proof {
           (Some(non_membership_root), Some(non_membership_path)) => (hex_to_scalar(non_membership_root), non_membership_path),
           _ => return Err("Failed to unwrap the old root and old path"),
       };

      let (first_update_old_root, first_update_old_path) = match &first_update_old {
          (Some(first_update_old_root), Some(first_update_old_path)) => (hex_to_scalar(first_update_old_root), first_update_old_path),
          _ => return Err("Failed to unwrap the first update oldroot and the old path"),
      };
      
      let (first_update_new_root, first_update_new_path) = match &first_update_new {
          (Some(first_update_new_root), Some(first_update_new_path)) => (hex_to_scalar(first_update_new_root), first_update_new_path),
          _ => return Err("Failed to unwrap the first update newroot and the new path"),
      };
      
      let (second_update_old_root, second_update_old_path) = match &second_update_old {
          (Some(second_update_old_root), Some(second_update_old_path)) => (hex_to_scalar(second_update_old_root), second_update_old_path),
          _ => return Err("Failed to unwrap the second update oldroot and the old path"),
      };

      let (second_update_new_root, second_update_new_path) = match &second_update_new {
          (Some(second_update_new_root), Some(second_update_new_path)) => (hex_to_scalar(second_update_new_root), second_update_new_path),
          _ => return Err("Failed to unwrap the second update newroot and the new path"),
      };

      let first_merkle_proof_circuit = UpdateMerkleProofCircuit {
          old_root: first_update_old_root,
          old_path: first_update_old_path.clone(),
          updated_root: first_update_new_root,
          updated_path: first_update_new_path.clone()
      };

      let second_merkle_proof_circuit = UpdateMerkleProofCircuit {
          old_root: second_update_old_root,
          old_path: second_update_old_path.clone(),
          updated_root: second_update_new_root,
          updated_path: second_update_new_path.clone()
      };

      let insert_proof_circuit = InsertMerkleProofCircuit {
            non_membership_root,
            non_membership_path: non_membership_path.clone(),
            first_merkle_proof: first_merkle_proof_circuit,
            second_merkle_proof: second_merkle_proof_circuit
      };

      // Create the MerkleProofCircuit-Instance
      Ok(ProofVariantCircuit::Insert(insert_proof_circuit))
  }
}

impl HashChainEntryCircuit {
    pub fn create(value: &String, hashchain: Vec<ChainEntry>) -> Result<HashChainEntryCircuit, &'static str> {
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
