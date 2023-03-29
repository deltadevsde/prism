/* /* use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::{Engine};
use bls12_381::{Bls12};
use bls12_381::Scalar as Fr; // Scalar als konkreter Fr Typ, der mit der elliptischen Kurve Bls12_381 assoziiert ist (in Engine ist das abstrakt)
use rand::Rng;
use std::convert::TryFrom;
use std::str::FromStr;

use crate::indexed_merkle_tree::MerkleProof;

pub struct MerkleCircuit<E: Engine> {
    // E::Fr repräsentiert das skalare Feld, das mit der elliptischen Kurve E assoziiert ist. (Wir wollen über endlichen Felder arbeiten)
    old_root: E::Fr,
    new_root: E::Fr,
    merkle_proofs: Vec<MerkleProof>,
    path_indices: Vec<usize>,
    new_values: Vec<E::Fr>,
}

impl<E: Engine> Circuit<E::Fr> for MerkleCircuit<E> {
    fn synthesize<CS: ConstraintSystem<E::Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let old_root_var = cs.alloc(|| "old root", || Ok(self.old_root))?;
        let new_root_var = cs.alloc(|| "new root", || Ok(self.new_root))?;
        let mut cur_path_var = vec![];

        for (i, (_, proof)) in self.merkle_proofs.iter().enumerate() {
            let cur_path = cs.alloc(|| format!("path element {}", i), || Ok(proof.unwrap().0))?;
            cur_path_var.push(cur_path);
        }

        // Implementiere hier die Logik für den Merkle-Beweis

        // Beispiel: Überprüfen Sie, ob die alte Wurzel gleich der neuen Wurzel ist.
        // In der Praxis sollten Sie die Merkle-Beweis-Logik implementieren, um die Gültigkeit der Beweise und der Wurzeln zu überprüfen.
        cs.enforce(
            || "old root equals new root",
            |lc| lc + old_root_var,
            |lc| lc + CS::one(),
            |lc| lc + new_root_var,
        );

        Ok(())
    }
} 

impl MerkleCircuit<Bls12> {
    fn hex_string_to_fr(hex_string: &str) -> Option<Fr> {
        let bytes = hex::decode(hex_string).ok()?;
        let fr_repr = bls12_381::Scalar::from_bytes(&<[u8; 32]>::try_from(bytes.as_slice()).ok()?);
        Some(fr_repr.unwrap())
       
    }

    pub fn create_merkle_circuit (old_root: &str, new_root: &str, merkle_proofs: Vec<MerkleProof>, path_indices: Vec<usize>, new_values: Vec<Fr>) -> MerkleCircuit<Bls12> {
        let parsed_old_root = MerkleCircuit::<Bls12>::hex_string_to_fr(old_root).unwrap();
        let parsed_new_root = MerkleCircuit::<Bls12>::hex_string_to_fr(new_root).unwrap();

        
        MerkleCircuit {
            old_root: parsed_old_root,
            new_root: parsed_new_root,
            merkle_proofs,
            path_indices,
            new_values,
        }
    }

}

// Hauptfunktion zum Erstellen und Verwenden eines SNARK
fn main() {
    // Erstelle Merkle-Bäume und speichere die alten und neuen Wurzeln
    // Generiere die Merkle-Beweise und die Pfade
    // Erstelle den Schaltkreis und generiere die SNARK-Parameter
    // Beweise und verifiziere den Beweis
} */


use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::gadgets::num::AllocatedNum;
use bellman::gadgets::AllocGadget;
use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::multipack;
use ff::{Field, PrimeField};
use bls12_381::{Bls12, Scalar as Fr};
use pairing::{Engine};

use crate::indexed_merkle_tree::{Node, MerkleProof, UpdateProof, sha256};
use bellman::gadgets::sha256::sha256 as bellman_sha256;

pub struct MerkleProofCircuit {
    pub old_root: Fr,
    pub old_path: Vec<Node>,
    pub new_root: Fr,
    pub new_path: Vec<Node>,
}

fn hex_to_scalar(hex_string: &str) -> Fr {
    let byteArray: [u8; 32]  = hex::decode(hex_string).unwrap().try_into().unwrap();
    Fr::from_bytes(&byteArray).unwrap()
}

fn circuit_sha256<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    input1: &AllocatedNum<Fr>,
    input2: &AllocatedNum<Fr>,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    // Konvertiere die Eingangsnummern in Booleans
    let input1_bits = input1.to_bits_le(cs.namespace(|| "input1_bits"))?;
    let input2_bits = input2.to_bits_le(cs.namespace(|| "input2_bits"))?;

    // Kombiniere die beiden Eingaben mit "H(" und " || " dazwischen
    let h_string = b"H(";
    let separator_string = b" || ";
    let close_parenthesis_string = b")";

    let h_bits = h_string.iter().flat_map(|byte| (0..8).rev().map(move |i| Boolean::constant((byte >> i) & 1 == 1)));
    let separator_bits = separator_string.iter().flat_map(|byte| (0..8).rev().map(move |i| Boolean::constant((byte >> i) & 1 == 1)));
    let close_parenthesis_bits = close_parenthesis_string.iter().flat_map(|byte| (0..8).rev().map(move |i| Boolean::constant((byte >> i) & 1 == 1)));

    let mut input_bits = Vec::new();
    input_bits.extend(h_bits);
    input_bits.extend(input1_bits);
    input_bits.extend(separator_bits);
    input_bits.extend(input2_bits);
    input_bits.extend(close_parenthesis_bits);

    // Wende die Bellman SHA256 Funktion auf die Booleans an
    let result_bits = bellman_sha256(cs.namespace(|| "sha256"), &input_bits)?;

    // Konvertiere das Ergebnis zurück in eine AllocatedNum
    let result = AllocatedNum::pack_bits_to_element(cs.namespace(|| "result_num"), &result_bits)?;

    Ok(result)
}

// TODO: man muss hier nochmal bedenken, dass es möglich ist, dass der alte Pfad nicht von der selben Länge ist wie der neue Pfad
// Dies ist dann der Fall, wenn der Baum im alten Pfad voll war und dann die Kapazität verdoppelt wird. Dann ist der neue Pfad um ein Element länger
impl Circuit<Fr> for MerkleProofCircuit {
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Alloziere Variablen für die Wurzeln des alten und neuen Baums
        let commitment1_var = cs.alloc(|| "commitment1", || Ok(self.old_root))?;
        let commitment2_var = cs.alloc(|| "commitment2", || Ok(self.new_root))?;
        
        // Alloziere Eingabevariablen für die Hashes der alten und neuen Knoten
        let mut old_hash_var = cs.alloc_input(|| format!("old_input"), || Ok(hex_to_scalar(&self.old_path[0].hash)))?;
        let mut new_hash_var = cs.alloc_input(|| format!("new_input"), ||  Ok(hex_to_scalar(&self.new_path[0].hash)))?;


       for i in 1..(self.old_path.len() - 1) {
            // Gehe durch alle Geschwisterknoten der alten und neuen Knoten
            let old_sibling = &self.old_path[i];
            let new_sibling = &self.new_path[i];    
            
            // Alloziere Variablen für die Geschwisterknoten der alten und neuen Knoten
            let old_sibling_var = cs.alloc(|| format!("old_sibling_{}", i), || Ok(hex_to_scalar(&old_sibling.hash)))?;
            let new_sibling_var = cs.alloc(|| format!("new_sibling_{}", i), || Ok(hex_to_scalar(&new_sibling.hash)))?;
            
            // Überprüfe, ob der aktuelle Knoten der linke oder rechte Nachbar ist
            if old_sibling.is_left_sibling.unwrap() {
                // Wenn es ein linker Nachbar ist, bilde den neuen Hash basierend auf
                // linker Nachbar + aktueller Hash
                old_hash_var = sha256(cs.namespace(|| format!("H({} || {})", &old_sibling_var, old_hash_var)));
                new_hash_var = sha256(cs.namespace(|| format!("new_sha256_{}", i)), &new_sibling_var, &new_hash_var)?;
            } else {
                // Wenn es ein rechter Nachbar ist, bilde den neuen Hash basierend auf
                // aktueller Hash + rechter Nachbar
                old_hash_var = sha256(cs.namespace(|| format!("old_sha256_{}", i)), &old_hash_var, &old_sibling_var)?;
                new_hash_var = sha256(cs.namespace(|| format!("new_sha256_{}", i)), &new_hash_var, &new_sibling_var)?;
            }
        }

        // Überprüfe, ob der resultierende Hash der Wurzel-Hash des alten Baums entspricht
        cs.enforce(|| format!("check_old_root_{}", i), |lc| lc + old_hash_var, |lc| lc + CS::one(), |lc| lc + commitment1_var);
        // Überprüfe, ob der resultierende Hash der Wurzel-Hash des neuen Baums entspricht
        cs.enforce(|| format!("check_new_root_{}", i), |lc| lc + new_hash_var, |lc| lc + CS::one(), |lc| lc + commitment2_var);


        Ok(())
    }
}

// Die Funktion, um den Schaltkreis basierend auf dem gegebenen Merkle-Beweis zu erstellen
fn create_circuit(proof: &UpdateProof) -> MerkleProofCircuit {
    // Konvertiere `proof.old_root` und `proof.new_root` von `String` in `Fr`
    let ((old_root, old_path), (new_root, new_path)) = proof;
    let old_hex_root: [u8; 32]  = hex::decode(old_root.unwrap()).unwrap().try_into().unwrap();
    let new_hex_root: [u8; 32]  = hex::decode(new_root.unwrap()).unwrap().try_into().unwrap();
    let old_root = Fr::from_bytes(&old_hex_root).unwrap();
    let new_root = Fr::from_bytes(&new_hex_root).unwrap();

    // Erstelle die MerkleProofCircuit-Instanz
    MerkleProofCircuit {
        old_root,
        old_path: old_path.unwrap().clone(),
        new_root,
        new_path: new_path.unwrap().clone(),
    }
} */