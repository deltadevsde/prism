use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bls12_381::{Scalar, Bls12};
use bellman::groth16::{Proof};
use serde::{Serialize, Deserialize};
use crate::indexed_merkle_tree::{MerkleProof, UpdateProof, ProofVariant};
use crate::indexed_merkle_tree::{Node};
use crate::indexed_merkle_tree::{sha256};

#[derive(Clone, Serialize, Deserialize)]
pub struct CustomProof {
    a: String,
    b: String,
    c: String,
}

pub fn convert_proof_to_custom(proof: &Proof<Bls12>) -> CustomProof {
    CustomProof {
        a: proof.a.to_string(),
        b: proof.b.to_string(),
        c: proof.c.to_string(),
    }
}


// TODO: WICHTIG!
// Ich konvertiere im Code zum SNARK Strings häufig hin und her und berechnen wie auch in der Anwendung die Hashwerte angelehnt ans Paper in der folgenden Form: H({} || {}).
// In der Praxis ist es ziemlich sicher besser, die Datenstrukturen und Algorithmen in der Anwendung und im Schaltkreis so zu gestalten, dass sie direkt mit skalaren Werten oder 
// Byte-Repräsentationen arbeiten, anstatt mit formatierten Strings. Dann würde das ganze nicht mehr auf der Konvertierung zwischen verschiedenen Darstellung basieren.

// theoretically we could refactor this to only one merkleproof circuit, and repeat it twice for updates and five (one merkle proof (non-membership), two update proofs) times for inserts
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


// funktioniert nicht ohne from_bytes_wide, da ansonsten die Modulo Operation fehlschlägt (Wert scheint dann ggf. zu groß)
pub fn hex_to_scalar(hex_string: &str) -> Scalar {
    let byte_array: [u8; 32]  = hex::decode(hex_string).unwrap().try_into().unwrap();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&byte_array); // 0en davor füllen, dann bleibt der Wert gleich
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
    // Proof of Update für den alten und neuen Knoten
        // Proof of Update für den Knoten, für den zuvor ein Proof of Non-Membership durchgeführt wurde mit der Next-Pointer Aktualisierung
        let root_with_old_pointer = cs.alloc(|| "first update root with old pointer", || Ok(old_root))?;
        let root_with_new_pointer = cs.alloc(|| "first update root with new pointer", || Ok(new_root))?;

        // Aktueller Hash für den alten und neuen Pfad
        let recalculated_root_with_old_pointer = recalculate_hash_as_scalar(&old_path);
        let recalculated_root_with_new_pointer = recalculate_hash_as_scalar(&new_path);

        // Alloziere Variablen für die berechneten Wurzeln der alten und neuen Knoten
        let allocated_recalculated_root_with_old_pointer = cs.alloc(|| "recalculated first update proof old root", || Ok(recalculated_root_with_old_pointer))?;
        let allocated_recalculated_root_with_new_pointer = cs.alloc(|| "recalculated first update proof new root", || Ok(recalculated_root_with_new_pointer))?;
        
        // Überprüfe, ob der resultierende Hash der Wurzel-Hash des alten Baums entspricht
        cs.enforce(|| "first update old root equality", |lc| lc + allocated_recalculated_root_with_old_pointer, |lc| lc + CS::one(), |lc| lc + root_with_old_pointer);
        // Zum Thema |lc| lc + ... : In der Lambda-Funktion steht lc für die aktuelle lineare Kombination und wir fügen Variablen zu dieser Linearkombination hinzu, um insgesamt eine neue lineare Kombination zu erstellen, die dann als Argument für die enforce-Methode verwendet wird.
        // Überprüfe, ob der resultierende Hash der Wurzel-Hash des neuen Baums entspricht
        cs.enforce(|| "first update new root equality", |lc| lc + allocated_recalculated_root_with_new_pointer, |lc| lc + CS::one(), |lc| lc + root_with_new_pointer);

        // Schließe die Funktion erfolgreich ab
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

// TODO: zkSNARK muss für den Insert-Beweis...
// ... 1. den Proof of Non-Membership für den Knoten an der zu erwartenden Stelle erstellen.
// ... 2 den Proof of Update für den Knoten an der zu erwartenden Stelle erstellen, welcher aus folgenden Teilen besteht:
// ... 2.1. den Proof of Membership für den unaktualisierten Next-Pointer des Knotens an der zu erwartenden Stelle erstellen.
// ... 2.2. den Proof of Membership für den unaktualisierten Next-Pointer des Knotens an der zu erwartenden Stelle erstellen.
// ... 3 den Proof of Update für den neuen Knoten, welcher aus folgenden Teilen besteht:
// ... 3.1. den Proof of Membership für den unaktualisierten neuen Knoten an der zu erwartenden Stelle erstellen (mit aktualisiertem Pointer).
// ... 3.2. den Proof of Membership für den aktualisierten neuen Knoten an der zu erwartenden Stelle erstellen (mit aktualisiertem Pointer).
impl Circuit<Scalar> for InsertMerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {

        // Proof of Non-Membership
        match proof_of_non_membership(cs, self.non_membership_root, &self.non_membership_path) {
            Ok(_) => (),
            Err(_) => return Err(SynthesisError::AssignmentMissing),
        }


        // Proof of Update für den alten und neuen Knoten
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
        // Proof of Update für den alten und neuen Knoten
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

        // vor den Berechnungen sicherstellen, dass die alte Wurzel die des ersten Beweises ist
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
                    // Hier müssen Sie eine proof_of_insert Funktion erstellen, die ähnlich wie proof_of_update funktioniert,
                    // aber auch den Non-Membership-Beweis berücksichtigt.
                     // Proof of Non-Membership
                    match proof_of_non_membership(cs, insert_proof_circuit.non_membership_root, &insert_proof_circuit.non_membership_path) {
                        Ok(_) => (),
                        Err(_) => return Err(SynthesisError::AssignmentMissing),
                    }

                    // Proof of Update für den alten und neuen Knoten
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

       // Erstelle die MerkleProofCircuit-Instanz
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

      // Erstelle die MerkleProofCircuit-Instanz
      Ok(ProofVariantCircuit::Insert(insert_proof_circuit))
  }
}

// Die Funktion, um den Schaltkreis basierend auf dem gegebenen Merkle-Beweis zu erstellen
impl InsertMerkleProofCircuit {
    pub fn create_from_update_proof(proof: &(MerkleProof, UpdateProof, UpdateProof)) -> Result<InsertMerkleProofCircuit, &'static str> {
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