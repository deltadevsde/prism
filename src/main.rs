pub mod indexed_merkle_tree;
pub mod zk_snark;

use redis::{Commands, RedisError, Connection};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier, SecretKey};
use base64::{Engine as _, engine::general_purpose};
use rand::rngs::OsRng;
use rand07::rngs::OsRng as OsRng07;
use actix_cors::Cors;
use actix_web::{get, rt::{spawn}, post, App, HttpResponse, HttpServer, Responder};
use crypto_hash::{Algorithm, hex_digest};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use indexed_merkle_tree::{IndexedMerkleTree, MerkleProof, UpdateProof, InsertProof, Node, ProofVariant};
use indexed_merkle_tree::{sha256};
use zk_snark::{InsertMerkleProofCircuit, BatchMerkleProofCircuit, hex_to_scalar}; 
use std::{time::Duration};
use tokio::time::sleep;
use reqwest::Client;
use num::{BigInt, Num};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::env;
use dotenv::dotenv;
use bellman::{groth16};
use bls12_381::{Bls12, Scalar};
use colored::*;
use std::fmt::Display;

use crate::zk_snark::convert_proof_to_custom;

// Enums and structs

pub struct RedisConnections {
    pub main_dict: redis::Connection, // clear text key with hashchain
    pub derived_dict: redis::Connection, // hashed key with last hashchain entry hash
    pub input_order: redis::Connection, // input order of the hashchain keys
    pub app_state: redis::Connection, // app state (just epoch counter for now)
    pub merkle_proofs: redis::Connection, // merkle proofs (in the form: epoch_{epochnumber}_{commitment})
    pub commitments: redis::Connection, // epoch commitments 
}


#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum Operation {
    Add,
    Revoke,
}


impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Operation::Add => write!(f, "Add"),
            Operation::Revoke => write!(f, "Revoke"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ChainEntry {
    pub hash: String,
    pub previous_hash: String,
    pub operation: Operation,
    pub value: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Entry {
    pub id: String,
    pub value: Vec<ChainEntry>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DerivedEntry {
    pub id: String,
    pub value: String,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingEntry {
    pub id: String,
    pub public_key: String,
}


/// This function takes no arguments, creates and return new redis connections.
/// 
/// ## Returns the RedisConnections struct
/// 
pub fn create_redis_clients() -> RedisConnections {
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let derived_client = redis::Client::open("redis://127.0.0.1/1").unwrap();
    let input_order = redis::Client::open("redis://127.0.0.1/2").unwrap();
    let app_state = redis::Client::open("redis://127.0.0.1/3").unwrap();
    let merkle_proos = redis::Client::open("redis://127.0.0.1/4").unwrap();
    let commitments = redis::Client::open("redis://127.0.0.1/5").unwrap();

    RedisConnections {
        main_dict: client.get_connection().unwrap(),
        derived_dict: derived_client.get_connection().unwrap(),
        input_order: input_order.get_connection().unwrap(),
        app_state: app_state.get_connection().unwrap(),
        merkle_proofs: merkle_proos.get_connection().unwrap(),
        commitments: commitments.get_connection().unwrap(),
    }
}


/// This function takes no arguments, creates and returns a new Ed25519 key pair with cryptographically secure randomness from the operating system.
/// 
/// ## Returns a new `Keypair` with the generated `SecretKey` and `PublicKey` struct of the following form
/// pub struct Keypair {
///     pub secret: SecretKey,
///     pub public: PublicKey,
/// }
/// 
fn create_keypair() -> Keypair {
    // A random number generator that retrieves randomness from from the operating system. (no pseudo random numbers)
    let mut csprng = OsRng07::default();
    Keypair::generate(&mut csprng)
}


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
pub fn is_not_revoked(entries: &[ChainEntry], value: String) -> bool {
    for entry in entries {
        if entry.value == value && matches!(entry.operation, Operation::Revoke) {
            return false;
        }
    }
    true
}


/// Checks if a signature is valid for a given incoming entry.
/// 
/// This function takes two arguments, an IncomingEntry and a Signature, and returns a boolean.
/// It checks if there is an entry for the id of the incoming entry in the redis database and 
/// if there is, it checks if any public key in the hashchain can verify the signature.
/// 
/// Returns true if there is a public key for the id which can verify the signature
/// Returns false if there is no public key for the id or if no public key can verify the signature
/// 
/// 
/// 
/// 
fn signature_is_valid(incoming_entry: &IncomingEntry, signature: Signature, con: &mut Connection) -> bool {
    // try to extract the value of the id from the incoming entry from the redis database
    // if the id does not exist, there is no id registered for the incoming entry and so the signature is invalid
    let value: String = match con.get(&incoming_entry.id) {
        Ok(value) => value,
        Err(_) => return false, // if the id does not exist, return false
    };
    
    // parse hashchain from redis for the found id and store it in a vector
    let current_chain: Vec<ChainEntry> = serde_json::from_str(&value).unwrap();
    
    // iterate over the parsed hashchain and check if any non-revoked public key can verify the signature
    current_chain.iter().any(|entry| {
        if !is_not_revoked(&current_chain, entry.value.clone()) {
            return false;
        }

        // decode the base64 encoded public key
        let public_key = PublicKey::from_bytes(&general_purpose::STANDARD_NO_PAD.decode(&entry.value.as_bytes()).unwrap()).unwrap();
        
        // try to verify verify the signature
        public_key.verify(incoming_entry.public_key.as_bytes(), &signature).is_ok()
    })
}


/// Updates an entry in the Redis database based on the given operation, incoming entry, and the signature from the user.
///
/// # Arguments
///
/// * `operation` - An `Operation` enum variant representing the type of operation to be performed (Add or Revoke).
/// * `incoming_entry` - A reference to an `IncomingEntry` struct containing the key and the entry data to be updated.
/// * `signature` - A `Signature` struct representing the signature.
/// * `redis_connections` - A `RedisConnections` struct containing the Redis database connections.
///
/// # Returns
///
/// * `true` if the operation was successful and the entry was updated.
/// * `false` if the operation was unsuccessful, e.g., due to an invalid signature or other errors.
///
fn update_entry(operation: Operation, incoming_entry: &IncomingEntry, signature: Signature, redis_connections: &mut RedisConnections,) -> bool {
    let mut con = &mut redis_connections.main_dict;
    let derived_con = &mut redis_connections.derived_dict;
    let input_order = &mut redis_connections.input_order;

    // add a new key to an existing id  ( type for the value retrieved from the Redis database explicitly set to string)
    if let Ok(value) = con.get::<&String, String>(&incoming_entry.id) {
        // hashchain already exists

        if !signature_is_valid(incoming_entry, signature, &mut con) {
            return false;
        }

        let mut current_chain: Vec<ChainEntry> = serde_json::from_str(&value).unwrap();

        let new_chain_entry = ChainEntry {
            hash: hex_digest(Algorithm::SHA256, format!("{}, {}, {}", operation, &incoming_entry.public_key, &current_chain.last().unwrap().hash).as_bytes()),
            previous_hash: current_chain.last().unwrap().hash.clone(),
            operation: operation,
            value: incoming_entry.public_key.clone(),
        };

        current_chain.push(new_chain_entry.clone());
        con.set::<&String, String, String>(&incoming_entry.id, serde_json::to_string(&current_chain).unwrap()).unwrap();

        let hashed_key = sha256(&incoming_entry.id);
        derived_con.set::<&String, String, String>(&hashed_key, new_chain_entry.hash).unwrap();

        true
    } else {
        let new_chain = vec![ChainEntry {
            hash: hex_digest(Algorithm::SHA256, format!("{}, {}, {}", Operation::Add, &incoming_entry.public_key, Node::EMPTY_HASH.to_string()).as_bytes()),
            previous_hash: Node::EMPTY_HASH.to_string(),
            operation: operation,
            value: incoming_entry.public_key.clone(),
        }];

        con.set::<&String, String, String>(&incoming_entry.id, serde_json::to_string(&new_chain).unwrap()).unwrap();
        let hashed_key = hex_digest(Algorithm::SHA256, incoming_entry.id.as_bytes());
        derived_con.set::<&String, String, String>(&hashed_key, new_chain.last().unwrap().hash.clone()).unwrap();
        input_order.rpush::<&'static str, String, u32>("input_order", hashed_key).unwrap();

        true
    }
}


/// The function takes an IncomingEntry and a private key as arguments and returns a Signature.
/// 
/// The function creates a secret key from the private key string sent by the frontend, then it creates a keypair from the secret key,
/// and finally it signs a message (the new public key of the incoming entry) with the keypair and returns the signature.
/// 
fn sign_incoming_entry(incoming_entry: &IncomingEntry, private_key: &str) -> Signature {
    // create secret key from string
    let secret_key_bytes = general_purpose::STANDARD_NO_PAD.decode(private_key.as_bytes()).unwrap();
    let secret_key = SecretKey::from_bytes(&secret_key_bytes).unwrap();

    // create keypair from secret key
    let public_key: PublicKey = (&secret_key).into();
    let keypair = Keypair { secret: secret_key, public: public_key };

    // sign message and return signature
    keypair.sign(incoming_entry.public_key.as_bytes())
}


/// Updates or inserts an entry in the dictionary and generates a Merkle proof.
///
/// # Arguments
///
/// * `req_body` - A JSON string containing the information needed to update or insert an entry in the dictionary.
///   The JSON string should have the following fields:
///     - `operation`: An `Operation` enum indicating whether the operation is an add or revoke operation.
///     - `incoming_entry`: An `IncomingEntry` object containing the id and the public key.
///     - `private_key`: A string representing the private key used to sign the incoming entry. (TODO! bessere Lösung finden)
///
/// # Returns
///
/// * `HttpResponse::Ok` with a success message if the update or insertion was successful.
/// * `HttpResponse::BadRequest` with an error message if the update or insertion fails.
///
#[post("/update-entry")]
async fn update(req_body: String) -> impl Responder {
    let mut redis_connections = create_redis_clients();

    let epoch: u32 = redis_connections.app_state.get("epoch").unwrap();
    let epoch_operation: u32 = redis_connections.app_state.get("epoch_operation").unwrap();
    
    // incoming entry with private key object
    #[derive(Deserialize)]
    struct EntryWithKey {
        operation: Operation,
        incoming_entry: IncomingEntry,
        private_key: String,
    }
    
    let tree = IndexedMerkleTree::create_tree_from_redis(&mut redis_connections.derived_dict, &mut redis_connections.input_order);
    let entry_with_key: EntryWithKey = serde_json::from_str(&req_body).unwrap();
    let result: Result<String, RedisError> = redis_connections.main_dict.get(&entry_with_key.incoming_entry.id);
    // wenn der eintrag bereits vorliegt, muss ein update durchgeführt werden, sonst insert
    let update_proof = match result {
        // add a new key to an existing id 
        Ok(_) => true,
        Err(_) => false,
    };
    let signature = sign_incoming_entry(&entry_with_key.incoming_entry, &entry_with_key.private_key);
    let update_successful = update_entry(entry_with_key.operation, &entry_with_key.incoming_entry, signature, &mut redis_connections);
    

    if update_successful {
        let new_tree = IndexedMerkleTree::create_tree_from_redis(&mut redis_connections.derived_dict, &mut redis_connections.input_order);
        let hashed_id = sha256(&entry_with_key.incoming_entry.id);
        let node = new_tree.find_leaf_by_label(&hashed_id).unwrap();

        let proofs = if update_proof {
            let new_index = tree.clone().find_node_index(&node).unwrap();
            let (proof_of_update, _) = &tree.clone().generate_proof_of_update(new_index, node);
            let pre_processed_string = serde_json::to_string(proof_of_update).unwrap();
            format!(r#"{{"Update":{}}}"#, pre_processed_string)

        } else {
            let pre_processed_string = serde_json::to_string(&tree.clone().generate_proof_of_insert(&node)).unwrap();
            format!(r#"{{"Insert":{}}}"#, pre_processed_string)
        };
        let _: () =  redis_connections.merkle_proofs.set(format!("epoch_{}_{}_{}", epoch, epoch_operation, tree.get_commitment()), proofs).unwrap();
        redis_connections.app_state.set::<&'static str, String, String>("epoch_operation", (epoch_operation + 1).to_string()).unwrap();
        HttpResponse::Ok().body("Updated entry successfully")
    } else {
        HttpResponse::BadRequest().body("Could not update entry")
    }
}


/// The generate-key endpoint returns a public and private key pair.
/// 
/// The function creates an ed25519 keypair, encodes the public and private key with base64 and returns them as a json object like the following:
/// {
///    "publicKey": base64encodedpublickey,
///    "privateKey": base64encodedprivatekey
/// }
/// 
#[get("/generate-key")]
async fn generate_key() -> impl Responder {
    let keypair = create_keypair();
    let public_key_string = general_purpose::STANDARD_NO_PAD.encode(keypair.public.as_bytes());
    let private_key_string = general_purpose::STANDARD_NO_PAD.encode(keypair.secret.as_bytes());

    let json_response = serde_json::to_string(&json!({
        "publicKey": public_key_string,
        "privateKey": private_key_string
    }))
    .unwrap();

    HttpResponse::Ok().body(json_response)
}


/// The /calculate-values endpoint calculates the non-revoked values associated with an ID.
///
/// This endpoint takes a JSON request body containing an ID, for example:
/// {
/// "id": "bob@dom.org"
/// }
///
/// The function retrieves the hashchain associated with the provided ID from the Redis database. It then iterates through the hashchain to find all
/// the non-revoked keys. The resulting list of non-revoked keys is returned as a JSON object like the following:
/// {
/// "values": [public_key1, public_key2, ...]
/// }
///
/// If the ID is not found in the database, the endpoint will return a BadRequest response with the message "Could not calculate values".
///
#[post("/calculate-values")] // all active values for a given id
async fn calculate_values(req_body: String) -> impl Responder {
    let redis_connections = create_redis_clients();
    let mut con = redis_connections.main_dict;

    let incoming_id: String = serde_json::from_str(&req_body).unwrap();

    // 
    match con.get::<_, String>(&incoming_id) {
        // id exists, calculate values
        Ok(value) => {
            // parse hashchain
            let current_chain: Vec<ChainEntry> = serde_json::from_str(&value).unwrap();
            let chain_copy = current_chain.clone();
            let mut values = vec![];

            // add all non-revoked keys to values vector 
            for entry in current_chain {
                if is_not_revoked(&chain_copy, entry.value.clone()) {
                    values.push(entry.value);
                }
            }

            let json_response = serde_json::to_string(&json!({
                "values": values
            })).unwrap();
            // return values
            HttpResponse::Ok().body(json_response)
        },
        Err(_) => {
            HttpResponse::BadRequest().body("Could calculate values")
        }
    }
}


/// The `/get-dictionaries` endpoint retrieves both main and derived dictionaries from the Redis database.
///
/// The function returns a JSON object containing two fields: `dict` and `derived_dict`. Each field contains a list of dictionary entries.
///
#[get("/get-dictionaries")]
async fn get_dictionaries() -> impl Responder {
    let redis_connections = create_redis_clients();
    let mut con = redis_connections.main_dict;
    let mut derived_con = redis_connections.derived_dict;

    let redis_keys: Vec<String> = con.keys("*").unwrap();
    let derived_redis_keys: Vec<String> = derived_con.keys("*").unwrap();

    #[derive(Serialize, Deserialize)]
    struct Response {
        dict: Vec<Entry>,
        derived_dict: Vec<DerivedEntry>,
    }

    let mut resp = Response {
        dict: Vec::new(),
        derived_dict: Vec::new(),
    };
    for id in redis_keys {
        let value: String = con.get(id.clone()).unwrap();
        let chain: Vec<ChainEntry> = serde_json::from_str(&value).unwrap();
        resp.dict.push(Entry {
            id: id,
            value: chain
        });
    }

    for id in derived_redis_keys {
        let value: String = derived_con.get(id.clone()).unwrap();
        resp.derived_dict.push(DerivedEntry {
            id,
            value: value
        });
    }
    HttpResponse::Ok().body(serde_json::to_string(&resp).unwrap())
}


/// A helper function for verifying and validating Merkle proofs.
///
/// This function takes a string representation of a proof and attempts to deserialize it as either a
/// tuple containing a `MerkleProof` and two `UpdateProof`s (proof of insert), or as a single `UpdateProof`.
///
/// If the input is a tuple containing a `MerkleProof` and two `UpdateProof`s, the function checks
/// whether the proof is valid using the `IndexedMerkleTree::verify_insert_proof()` function.
/// If the proof is valid, a zkSNARK circuit is created, a Groth16 proof is generated and verified.
///
/// If the input is a single `UpdateProof`, the function checks whether the proof is valid using the
/// `IndexedMerkleTree::verify_update_proof()` function.
///
/// # Arguments
///
/// * `value` - A `String` containing the proof as a JSON serialized string.
///
/// # Returns
///
/// * A `Result<String, String>` where the `Ok` variant indicates that the proof is valid, and the
///   `Err` variant contains an error message.
///
/// # Errors
///
/// This function may return an error if the proof cannot be deserialized or is not in the correct format,
/// or if the zkSNARK circuit creation or proof verification fails.
async fn verify_and_validate_proof(value: String) -> Result<String, String> {
    if let Ok((non_membership_proof, first_proof, second_proof)) = serde_json::from_str::<(MerkleProof, UpdateProof, UpdateProof)>(&value) {
        if IndexedMerkleTree::verify_insert_proof(&non_membership_proof, &first_proof, &second_proof) {
            
            // Create zkSNARK circuit, eventuell auch in eine eigene Funktion auslagern
            let circuit = match InsertMerkleProofCircuit::create_from_update_proof(&(non_membership_proof.clone(), first_proof.clone(), second_proof.clone())) {
                Ok(circuit) => circuit,
                Err(e) => {
                    println!("{}", format!("Error creating circuit: {}", e).red());
                    return  Err("Could not create circuit".to_string());
                }
            };

            let rng = &mut OsRng;

            println!("{}", "Creating parameters with BLS12-381 pairing-friendly elliptic curve construction....".red().on_blue());
            let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).unwrap();

            println!("{}", "Creating proof for zkSNARK...".yellow());
            let proof = groth16::create_random_proof(circuit.clone(), &params, rng).unwrap();

            println!("{}", "Prepare verifying key for zkSNARK...".yellow());
            let pvk = groth16::prepare_verifying_key(&params.vk);

            println!("{}", "Verifying zkSNARK proof...".yellow());
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

            println!("{}", "zkSNARK with groth16 random parameters was successfully verified!".green());

            
            Ok("Proof is valid".to_string())
        } else {
            Err("Proof is not valid".to_string())
        }
    } else if let Ok(proof) = serde_json::from_str::<UpdateProof>(&value) {
        if IndexedMerkleTree::verify_update_proof(&proof) {
            Ok("Proof is valid".to_string())
        } else {
            Err("Proof is not valid".to_string())
        }
    } else {
        Err("Invalid proof format".to_string())
    }
}


/// Endpoint: /validate-proof
/// Validates a Merkle proof and returns whether it is valid or not.
///
/// This function receives a `proof_id` within the request body, which corresponds to the ID of a proof
/// stored in Redis. The proof can be either a single `UpdateProof` or a tuple containing a `MerkleProof`
/// and two `UpdateProof`s (which is an insert Proof).
///
/// For a single `UpdateProof`, this function checks whether the proof is valid using the
/// `IndexedMerkleTree::verify_update_proof()` function.
///
/// For a tuple containing a `MerkleProof` and two `UpdateProof`s, the function checks whether the proof
/// is valid using the `IndexedMerkleTree::verify_insert_proof()` function. If the proof is valid,
/// a zkSNARK circuit is created and a Groth16 proof is generated and verified.
/// TODO: das muss noch anders gemacht werden. Der SNARK wird anderweitig genutzt
///
/// The function returns an HTTP response with a body indicating whether the proof is valid or not.
///
/// # Arguments
///
/// * `req_body` - A `String` containing the request body, which should contain the `proof_id`.
///
/// # Returns
///
/// * An implementation of the `Responder` trait, which generates an HTTP response.
#[post("/validate-proof")]
async fn validate_proof(req_body: String) -> impl Responder {
    let redis_connections = create_redis_clients();
    let mut proof_con = redis_connections.merkle_proofs;
    
    // proof id aus redis holen
    let proof_id: String = match serde_json::from_str(&req_body) {
        Ok(proof_id) => proof_id,
        Err(_) => return HttpResponse::BadRequest().body("Invalid proof ID"),
    };
    let value: String = match proof_con.get(&proof_id) {
        Ok(value) => value,
        Err(_) => return HttpResponse::BadRequest().body("Could not find proof"),
    };

    //(is valid right now, edit it for purpose of testing) 
    /* let invalid_proof: (Option<String>, Option<Vec<Node>>) = (Some("3c89423740820e7ead04026a47a43503dfd680c9dbdb45b03d7988ba44178ac0".to_string()),
    Some(vec![
        Node {
            hash: "0eab3ff4edb5fe61a369b5803afa5ec04f7a0ee59c425c6eb8ffe372f138fca7".to_string(),
            is_left_sibling: Some(true),
            left: None,
            right: None,
            active: Some(Box::new(true)),
            value: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
            label: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
            next: Some(Box::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string())),
        },
        Node {
            hash: "3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f".to_string(),
            is_left_sibling: Some(false),
            left: None,
            right: None,
            active: Some(Box::new(false)),
            value: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
            label: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
            next: Some(Box::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string())),
        },
        Node {
            hash: "ccf3a891faa147d5a7077fd099f0ef5783466f48527caaa2db7556928d474f9d".to_string(),
            is_left_sibling: Some(false),
            left: Some(Box::new(Node {
                hash: "3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f".to_string(),
                is_left_sibling: Some(true),
                left: None,
                right: None,
                active: Some(Box::new(false)),
                value: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                label: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                next: Some(Box::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string())),
            })),
            right: Some(Box::new(Node {
                hash: "3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f".to_string(),
                is_left_sibling: Some(false),
                left: None,
                right: None,
                active: Some(Box::new(false)),
                value: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                label: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                next: Some(Box::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string())),
            })),
            active: None,
        value: None,
        label: Some(Box::new("H(3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f || 3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f)".to_string())),
        next: None,
        },
        Node {
        hash: "45dd7a5e04c669f84134d4d61d8216d9fdf67848ee2022c2e3f7e8de93535359".to_string(),
        is_left_sibling: Some(false),
        left: Some(Box::new(Node {
            hash: "ccf3a891faa147d5a7077fd099f0ef5783466f48527caaa2db7556928d474f9d".to_string(),
            is_left_sibling: Some(true),
            left: Some(Box::new(Node {
                hash: "3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f".to_string(),
                is_left_sibling: Some(true),
                left: None,
                right: None,
                active: Some(Box::new(false)),
                value: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                label: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                next: Some(Box::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string())),
            })),
            right: Some(Box::new(Node {
                hash: "3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f".to_string(),
                is_left_sibling: Some(false),
                left: None,
                right: None,
                active: Some(Box::new(false)),
                value: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                label: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                next: Some(Box::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string())),
            })),
            active: None,
            value: None,
            label: Some(Box::new("H(3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f || 3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f)".to_string())),
            next: None,
        })),
        right: Some(Box::new(Node {
            hash: "ccf3a891faa147d5a7077fd099f0ef5783466f48527caaa2db7556928d474f9d".to_string(),
            is_left_sibling: Some(false),
            left: Some(Box::new(Node {
                hash: "3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f".to_string(),
                is_left_sibling: Some(true),
                left: None,
                right: None,
                active: Some(Box::new(false)),
                value: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                label: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                next: Some(Box::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string())),
                })),
                right: Some(Box::new(Node {
                hash: "3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f".to_string(),
                is_left_sibling: Some(false),
                left: None,
                right: None,
                active: Some(Box::new(false)),
                value: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                label: Some(Box::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())),
                next: Some(Box::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string())),
                })),
                active: None,
                value: None,
                label: Some(Box::new("H(3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f || 3aeb938c7016cd9eea6211d4a8dcd4cc547e8834426b52159b8d329df111961f)".to_string())),
                next: None,
                })),
                active: None,
                value: None,
                label: Some(Box::new("H(ccf3a891faa147d5a7077fd099f0ef5783466f48527caaa2db7556928d474f9d || ccf3a891faa147d5a7077fd099f0ef5783466f48527caaa2db7556928d474f9d)".to_string())),
                next: None,
                }
            ]));   */

    // proof verifizieren und validieren, zkSNARK erstellen
    match verify_and_validate_proof(value).await {
        Ok(response) => HttpResponse::Ok().body(response),
        Err(err) => HttpResponse::BadRequest().body(err),
    }
}


fn parse_json_to_proof(json_str: &str) -> Result<ProofVariant, Box<dyn std::error::Error>> {
    let json_value: Value = serde_json::from_str(json_str)?;

    if json_value.get("Update").is_some() {
        let update_proof: UpdateProof = serde_json::from_value(json_value["Update"].clone()).unwrap();
        Ok(ProofVariant::Update(update_proof))
    } else if json_value.get("Insert").is_some() {
        let insert_proof: InsertProof = serde_json::from_value(json_value["Insert"].clone())?;
        Ok(ProofVariant::Insert(insert_proof.0, insert_proof.1, insert_proof.2))
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid JSON input, expected Update or Insert",
        )))
    }
}


pub fn extract_public_parameters(proofs: &[ProofVariant]) -> Vec<Scalar> {
    let mut public_parameters = Vec::new();
    for proof in proofs {
        match proof {
            ProofVariant::Update(update_proof) => {
                if let (Some(unupdated_root), Some(updated_root)) = (&update_proof.0.0, &update_proof.1.0) {
                    public_parameters.push(hex_to_scalar(unupdated_root.as_str()));
                    public_parameters.push(hex_to_scalar(updated_root.as_str()));
                }
            }
            ProofVariant::Insert(non_membership_proof, first_update, second_update) => {
                if let Some(non_membership_root) = &non_membership_proof.0 {
                    public_parameters.push(hex_to_scalar(non_membership_root.as_str()));
                }
                if let (Some(unupdated_first_root), Some(updated_first_root)) = (&first_update.0.0, &first_update.1.0) {
                    public_parameters.push(hex_to_scalar(unupdated_first_root.as_str()));
                    public_parameters.push(hex_to_scalar(updated_first_root.as_str()));
                }
                if let (Some(unupdated_second_root), Some(updated_second_root)) = (&second_update.0.0, &second_update.1.0) {
                    public_parameters.push(hex_to_scalar(unupdated_second_root.as_str()));
                    public_parameters.push(hex_to_scalar(updated_second_root.as_str()));
                }
            }
        }
    }
    public_parameters
}


// get prev commitment, current commitments and proofs in between
pub fn get_epochs_and_proofs(epoch: &str) -> Result<(u64, String, String, Vec<ProofVariant>), Box<dyn std::error::Error>> {
    let redis_connections = create_redis_clients();
    let mut proof_connection = redis_connections.merkle_proofs;
    let mut epoch_connection = redis_connections.commitments;

    if epoch == "0" {
        // TODO: eventually recalcualte the empty tree root and compare it to the one in the database
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Epoch 0 does not have a previous commitment",
        )));
    }

    // Parse epoch as u64
    let epoch_number: u64 = match epoch.parse::<u64>() {
        Ok(value) => value,
        Err(_) => return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Could not parse epoch number",
        ))),
    };

    // Calculate the previous epoch
    let previous_epoch = epoch_number - 1;
    
    // Get current commitment from database
    let current_commitment: String = match epoch_connection.get::<&str, String>(&format!("epoch_{}", epoch_number)) {
        Ok(value) => {
            let trimmed_value = value.trim_matches('"').to_string();
            trimmed_value
        },
        Err(_) => return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find current commitment",
        )))
    };
    
    // Get previous commitment from database
    let previous_commitment: String = match epoch_connection.get::<&str, String>(&format!("epoch_{}", previous_epoch)) {
        Ok(value) => {
            let trimmed_value = value.trim_matches('"').to_string();
            trimmed_value
        },
        Err(_) => return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find previous commitment",
        )))
    };

    let mut epoch_proofs: Vec<String> = match proof_connection.keys::<&String, Vec<String>>(&format!("epoch_{}*", previous_epoch)) {
        Ok(value) => value,
        Err(_) => return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find proofs",
        )))
    };

     // Sort epoch_proofs by extracting epoch number and number within the epoch
     epoch_proofs.sort_by(|a, b| {
        let a_parts: Vec<&str> = a.split('_').collect();
        let b_parts: Vec<&str> = b.split('_').collect();
        
        // zweite Zahl nutzen, da: epoch_1_1, epoch_1_2, epoch_1_3 usw. dann ist die zweite Zahl die Nummer innerhalb der Epoche
        let a_number: u64 = a_parts[2].parse().unwrap_or(0);
        let b_number: u64 = b_parts[2].parse().unwrap_or(0);

        // Compare first by epoch number, then by number within the epoch
        a_number.cmp(&b_number)
    });

    // Parse the proofs from JSON to ProofVariant
    let parsed_proofs: Vec<ProofVariant> = epoch_proofs
        .iter()
        .filter_map(|proof| {
            proof_connection.get::<&str, String>(proof)
                .ok()
                .and_then(|proof_str| parse_json_to_proof(&proof_str).ok())
        })
        .collect();

    Ok((epoch_number, previous_commitment, current_commitment, parsed_proofs))
}


// TODO: better documentation needed
// This function validates an epoch by creating and verifying zkSNARK evidence for all
// transactions in the epoch and verifying them.
//
// req_body: A string containing the epoch number to be validated.
// 
// Returns an HTTP response containing either a confirmation of successful 
// validation or an error.
#[post("/validate-epoch")]
async fn validate_epoch(req_body: String) -> impl Responder {
    let epoch: String = match serde_json::from_str(&req_body) {
        Ok(epoch) => epoch,
        Err(_) => return HttpResponse::BadRequest().body("Invalid epoch"),
    };
    
    let (epoch_number , previous_commitment, current_commitment, proofs) = match get_epochs_and_proofs(&epoch.as_str()) {
        Ok(value) => value,
        Err(err) => { 
            println!("{}", format!("Error getting proofs for epoch {}: {}", epoch, err).red());
            return HttpResponse::BadRequest().body("Something went wrong while getting the proofs");
        },
    };

    println!("found {:?} proofs in epoch {}", proofs.len(), epoch);

    if proofs.len() == 0 {
        println!("{}", format!("No proofs found for epoch {}", epoch).red());
        return HttpResponse::BadRequest().body("No proofs found".to_string());
    }


     // Create zkSNARK circuit, eventuell auch in eine eigene Funktion auslagern
     let circuit = match BatchMerkleProofCircuit::create(&previous_commitment, &current_commitment, proofs.clone()) {
        Ok(circuit) => circuit,
        Err(e) => {
            println!("{}", format!("Error creating circuit for {} operations in epoch {}: {}", proofs.len(), epoch, e).red());
            return  HttpResponse::BadRequest().body("Could not create circuit".to_string());
        }
    };

    let rng = &mut OsRng;

    println!("{}", "Creating parameters with BLS12-381 pairing-friendly elliptic curve construction....".red().on_blue());
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).unwrap();

    println!("{}", "Creating proof for zkSNARK...".yellow());
    let proof = groth16::create_random_proof(circuit.clone(), &params, rng).unwrap();

    println!("{}: {:?}", "PROOF".red(), proof);

    println!("{}", "Prepare verifying key for zkSNARK...".yellow());
    let pvk = groth16::prepare_verifying_key(&params.vk);
    
    println!("{}", "Extracting public parameters for zkSNARK...".yellow());

    // let public_parameters = extract_public_parameters(&parsed_proofs);

    println!("{}", "Verifying zkSNARK proof...".yellow());
    groth16::verify_proof(
        &pvk,
        &proof,
        &[hex_to_scalar(&previous_commitment.as_str()), hex_to_scalar(&current_commitment.as_str())],
    ).unwrap();

    println!("{}", "zkSNARK with groth16 random parameters was successfully verified!".green());


    // Konvertieren Sie die `proof`-Variable in einen JSON-String
    /* let proof_json = serde_json::to_string(&proof).unwrap(); */

    // Erstellen Sie das JSON-Objekt für die Antwort
    let response = json!({
        "epoch": epoch_number,
        "proof": convert_proof_to_custom(&proof)
    });

    HttpResponse::Ok().json(response)

    // proof verifizieren und validieren, zkSNARK erstellen
    /* match verify_and_validate_proof(value).await {
        Ok(response) => HttpResponse::Ok().body(response),
        Err(err) => HttpResponse::BadRequest().body(err),
    } */
}


/// Initializes an empty IndexedMerkleTree with a specified size (8 for now) and returns the root.
/// This function is exposed as an HTTP GET request under the "/initialize-merkle-tree" endpoint.
/// TODO: really necessary?
#[get("/initialize-merkle-tree")]
async fn initialize_merkle_tree() -> impl Responder {
   let size: usize = 8;
   let tree = IndexedMerkleTree::initialize(size);

    HttpResponse::Ok().body(serde_json::to_string(&tree.get_root()).unwrap())
}


/// Creates Redis connections and initializes the IndexedMerkleTree.
///
/// # Returns
///
/// * `IndexedMerkleTree`: The initialized IndexedMerkleTree based on the data from Redis.
///
fn create_redis_connections_and_initialize_tree() -> IndexedMerkleTree {
    let mut redis_connections = create_redis_clients();
    let tree = IndexedMerkleTree::create_tree_from_redis(&mut redis_connections.derived_dict, &mut redis_connections.input_order);

    tree
}


/// Returns the commitment (tree root) of the IndexedMerkleTree initialized from Redis data.
/// This function is exposed as an HTTP GET request under the "/get-commitment" endpoint.
///
#[get("/get-commitment")]
async fn get_commitment() -> impl Responder {
    let tree = create_redis_connections_and_initialize_tree();
    HttpResponse::Ok().body(serde_json::to_string(&tree.get_commitment()).expect("Failed to serialize commitment"))
}


/// Returns the current state of the IndexedMerkleTree initialized from Redis data as a JSON object.
/// This function is exposed as an HTTP GET request under the "/get-current-tree" endpoint.
///
#[get("/get-current-tree")]
async fn get_current_tree() -> impl Responder {
    let tree = create_redis_connections_and_initialize_tree();

    HttpResponse::Ok().body(serde_json::to_string(&tree.get_root()).expect("Failed to serialize tree root"))
}


#[post("/get-epoch-operations")]
async fn get_epoch_operations(req_body: String) -> impl Responder {
    // versuchen proof id aus request body zu parsen
    let epoch: String = match serde_json::from_str(&req_body) {
        Ok(epoch) => epoch,
        Err(_) => return HttpResponse::BadRequest().body("Invalid epoch"),
    };

    let (_, previous_commitment, current_commitment, proofs) = get_epochs_and_proofs(&epoch.as_str()).unwrap();

    #[derive(Serialize, Deserialize)]
    struct Response {
        epoch: String,
        previous_commitment: String,
        current_commitment: String,
        proofs: Vec<ProofVariant>,
    }

    let resp = Response {
        epoch,
        previous_commitment,
        current_commitment,
        proofs,
    };

    HttpResponse::Ok().body(serde_json::to_string(&resp).unwrap())

}


#[get("/get-epochs")]
async fn get_epochs() -> impl Responder {
    let mut redis_connection = create_redis_clients();
    let epochs: Vec<String> = redis_connection.commitments.keys("*").unwrap();

    #[derive(Serialize, Deserialize)]
    struct Epoch {
        id: String,
        commitment: String,
    }

    #[derive(Serialize, Deserialize)]
    struct Response {
        epochs: Vec<Epoch>,
    }

    let mut resp = Response {
        epochs: Vec::new(),
    };

    for epoch in epochs {
        let value: String = redis_connection.commitments.get(&epoch).unwrap();
        resp.epochs.push(Epoch {
            id: epoch,
            commitment: value,
        });
    }


    HttpResponse::Ok().body(serde_json::to_string(&resp).unwrap())
}


#[get("/finalize-epoch")]
async fn finalize_epoch() -> impl Responder {
    intialize_or_increment_epoch_state().await;

    HttpResponse::Ok().body("Created next epoch successfully")
}


/// Initializes the epoch state by setting up the input table and incrementing the epoch number.
/// Periodically calls the `set_epoch_commitment` function to update the commitment for the current epoch.
///
/// # Behavior
/// 1. Initializes the input table by inserting an empty hash if it is empty.
/// 2. Updates the epoch number in the app state.
/// 3. Waits for a specified duration before starting the next epoch.
/// 4. Calls `set_epoch_commitment` to fetch and set the commitment for the current epoch.
/// 5. Repeats steps 2-4 periodically.
async fn intialize_or_increment_epoch_state() {
    let redis_connection = create_redis_clients();
    let mut derived_dict = redis_connection.derived_dict;
    let mut input_order = redis_connection.input_order;
    let mut app_state = redis_connection.app_state;
    let mut commitments = redis_connection.commitments;

    // beim ersten starten wird der Nullwert in die input tabelle geschrieben
    let derived_dict_keys: Vec<String> = input_order.lrange("input_order", 0, -1).unwrap(); // get all keys from the input order list
    if derived_dict_keys.len() == 0 { // if the dict is empty, we need to initialize the dict and the input order
        let empty_hash = Node::EMPTY_HASH.to_string(); // empty hash is always the first node (H(active=true, label=0^w, value=0^w, next=1^w))
        derived_dict.set::<&String, &String, String>(&empty_hash, &empty_hash).unwrap(); // set the empty hash as the first node in the derived dict
        input_order.rpush::<&str, String, u32>("input_order", empty_hash.clone()).unwrap(); // add the empty hash to the input order as first node
    }

     // epoch erhöhen zu beginn, da es sonst in der ersten epoche probleme gibt
     let result: Result<String, RedisError> = app_state.get(&"epoch");
     let epoch = match result {
         Ok(epoch) => { // if the epoch key exists, we increase it by 1 every x seconds
             let mut epoch_num = epoch.parse::<i32>().unwrap();
             epoch_num += 1;
             epoch_num.to_string()
         }
         Err(_) => {
             "0".to_string()
            }, // if the epoch key doesnt exist, we set it to 0 because its the first epoch
        };
        let _: () = app_state.set(&"epoch", &epoch).unwrap();
        app_state.set::<&'static str, &'static str, String>("epoch_operation", "0").unwrap();

     // fetch and set the commitment for the current epoch
    match set_epoch_commitment_and_proof(&mut app_state, &mut commitments).await {
        Ok(_) => (),
        Err(e) => eprintln!("Error: {:?}", e),
    };

    // warten for the next epoch to start, two minutes for now
    let wait_duration = Duration::from_secs(600);
    //let wait_duration = Duration::from_secs(300);
    sleep(wait_duration).await; 
}


/// Fetches the commitment for the current epoch and sets it in the Redis `commitments` connection.
///
/// # Arguments
/// * `app_state` - A mutable reference to the Redis connection storing the application state (only epoch number for now).
/// * `commitments` - A mutable reference to the Redis connection storing the commitments.
///
/// # Returns
/// * Result<(), Box<dyn std::error::Error>> - An empty `Result` indicating success or an error. TODO: probably better behavior
///
/// # Behavior
/// 1. Gets the current epoch number from the `app_state` Redis connection.
/// 2. Sends an HTTP GET request to the endpoint "http://127.0.0.1:8080/get-commitment".
/// 3. Stores the commitment response (merkle root hash) in the `commitments` Redis connection with the key format "epoch_{epoch_number}".
async fn set_epoch_commitment_and_proof(app_state: &mut redis::Connection, commitments: &mut redis::Connection) -> Result<(), Box<dyn std::error::Error>> {
    // zum einen wird die Epoche im Redis App State erhöht, zum anderen wir das Commitment für die Epoche gespeichert, also der aktuelle Zustand
    let client = Client::new();
    let epoch: String = app_state.get(&"epoch").unwrap();
    // Commitment setzen
    let res = client.get("http://127.0.0.1:8080/get-commitment").send().await?;
    let res = res.text().await?;

    commitments.set::<&String, &String, String>(&format!("epoch_{}", epoch), &res).unwrap();

    if epoch != "0" {
        let proof = client
            .post("http://127.0.0.1:8080/validate-epoch")
            .json(&epoch.as_str()) 
            .send()
            .await?;
    
        if proof.status().is_success() {
            let proof_json: serde_json::Value = proof.json().await?;
            println!("Response JSON: {:?}", proof_json["proof"]);
        } else {
            println!("Error: {}", proof.status());
            println!("Error: {}", proof.text().await?);
        }
    }


    Ok(())
}


#[derive(Debug, Default)]
struct EnvConfig {
    key_path: String,
    cert_path: String,
    ip: String,
    port: u16,
}


fn load_config() -> EnvConfig {
    let key_path = env::var("KEY_PATH").unwrap_or("key.pem".to_string());
    let cert_path = env::var("CERT_PATH").unwrap_or("cert.pem".to_string());
    let ip = env::var("IP").unwrap_or("127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or("8080".to_string()).parse().unwrap_or(8080);

    EnvConfig {
        key_path,
        cert_path,
        ip,
        port,
    }
}


/// Returns the merkle tree root of the given leaves
/// 
/* #[post("/get-merkle-tree")]
async fn get_merkle_tree(req_body: String) -> impl Responder {
    /* 
    DEN ANSATZ KANN ICH MIR SPAREN, DA IM PAPER TATSÄCHLICH JEDE OPERATION EINZELN BEHANDELT WIRD 
    DIE OPERATIONEN WERDEN ZWAR NICHT EINZELN VERÖFFENTLICHT, SONDERN NACH EINER FESTEN ZEITEPOCHE WIRD LEDIGLICH EIN BEWEIS ERSTELLT, DER BEWEIST, DASS
    DER SERVICE BEWEISE KENNT DIE BEWEISEN, DASS DIE OPERATIONEN VALIDE AUSGEFÜHRT WURDEN. ich behalte den unteren Ansatz trotzdem mal für Doku-Zwecke drin.
    
    / parse the leaves from the request body
    let leaves: Vec<DerivedEntry> = serde_json::from_str(&req_body).unwrap();

    let mut size = leaves.len();
    / Mit dem Bitweisen &-Operator kann geprüft werden, ob die Anzahl der Blätter im Baum eine Zweierpotenz ist.
    / Wenn die Zahl keine Zweierpotenz ist, wird sie so lange um eins erhöht, bis sie eine Zweierpotenz ist.
    while size & (size - 1) != 0 {
        size += 1;
    }
    / create the merkle tree with the given size and leaves
    let indexed_merkle_tree = IndexedMerkleTree::new(size, leaves); */

    // return the merkle tree root as a string in the response body
   /*  HttpResponse::Ok().body(serde_json::to_string(&indexed_merkle_tree.get_root()).unwrap()) */
}
 */

 /* fn create_tree() -> IndexedMerkleTree {
    let (_, mut derived_dict, mut input_order, _, _, _) = create_redis_clients();
    /* 
    Mit der Input_order könnten wir die Sortierung vornehmen und die Blätter dennoch in der Einfüge-Reihenfolge im Baum speichern.
    Evtl. mit Prof. Tischhauser absprechen, ob wir die im Paper gewünschte "Zufälligkeit" so interpretieren können
    */
    let first_node = Node::create_first_node(); // add the < 1, 0w, 0w, 1w > node to the tree (initialization node)
    let _: () = derived_dict.set(Node::create_empty_hash(), Node::create_empty_hash()).unwrap();
    let mut derived_dict_keys: Vec<String> = input_order.lrange("input_order", 0, -1).unwrap();
    derived_dict_keys.insert(0, first_node.hash.clone()); // add the hash of the first node to the list of keys 
    println!("{:?}", &derived_dict_keys);
        
    let mut size: usize = 8;
    while size < derived_dict_keys.len() {
        size *= 2;
    }

    // convert the keys to BigInts to sort them
    let mut big_int_keys = derived_dict_keys.iter().map(|key| {
        BigInt::from_str_radix(&key, 16).unwrap()
    }).collect::<Vec<BigInt>>();
    // sort the keys in reverse order (biggest first to solve the next pointer issue)
    big_int_keys.sort_by(|a, b| b.cmp(a));

    let mut prev_node = Node::create_tail(); // create tail node as "first previous node"
    let mut nodes: Vec<Node> = big_int_keys.iter().map(|key| {
        // its possible that the key is not 64 chars long, so we need to pad it with 0s
        let key_len = 64;
        let radix_key_str: String = key.to_str_radix(16); // convert back to hex as label
        let label: String = if radix_key_str.len() < key_len {
            let padding = "0".repeat(key_len - radix_key_str.len());
            format!("{}{}", padding, radix_key_str)
        } else {
            radix_key_str.clone()
        };
        let value: String = derived_dict.get(&label).unwrap();

        let next_node = prev_node.clone(); // use previous node as next pointer

        let node = Node::initialize_leaf(true, label.clone(), value, next_node.to_string());
        prev_node = label; // update previous node to current node

        node
    }).collect(); 

    nodes.reverse(); // reverse the nodes "again" to get the correct order

    // if the #nodes isnt a power of 2, add empty nodes to the tree
    let remaining_leaves = size - nodes.len();
    for _ in 0..remaining_leaves {
        let empty_hash = Node::create_empty_hash();
        let node = Node::initialize_leaf(false, empty_hash.clone(), empty_hash, Node::create_tail());
        nodes.push(node);
    }

    let tree = IndexedMerkleTree::new(nodes);
    tree
}
 */


/// The main function that initializes and runs the Actix web server.
///
/// # Behavior
/// 1. Loads environment variables using `dotenv` and sets up the server configuration.
/// 2. Spawns a task that runs the `initialize_or_increment_epoch_state` function in a loop for epoch-based behavior of the application
/// 3. Sets up CORS (Cross-Origin Resource Sharing) rules to allow specific origins and headers.
/// 4. Registers routes for various services.
/// 5. Binds the server to the configured IP and port.
/// 6. Runs the server and awaits its completion.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    spawn(async {
        loop {
            intialize_or_increment_epoch_state().await;
        }
    }); 

    let config = load_config();

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file(config.key_path, SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file(config.cert_path).unwrap();

    HttpServer::new(|| {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://localhost:3001")
            .allowed_origin("https://visualizer.sebastianpusch.de")
            .allow_any_method()
            .allow_any_header();
        App::new()
            .wrap(cors)
            .service(update)
            .service(generate_key)
            .service(get_dictionaries)
            .service(calculate_values)
            .service(get_commitment) 
            .service(get_current_tree) 
            .service(initialize_merkle_tree)
            .service(validate_proof)
            .service(validate_epoch)
            .service(finalize_epoch)
            .service(get_epochs)
            .service(get_epoch_operations)
    })
    .bind_openssl((config.ip, config.port), builder)? 
    /* .bind((config.ip, config.port))? */
    .run()
    .await 
}
