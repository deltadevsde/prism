pub mod transparency_dict;
pub mod indexed_merkle_tree;
pub mod zk_snark;

use redis::{Commands, RedisError};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier, SecretKey};
use base64::{Engine as _, engine::general_purpose};
use rand::rngs::OsRng;
use actix_cors::Cors;
use actix_web::{get, rt::{spawn}, post, App, HttpResponse, HttpServer, Responder};
use crypto_hash::{Algorithm, hex_digest};
use serde::{Serialize, Deserialize};
use serde_json::json;
use {transparency_dict::{IncomingEntry, ChainEntry, DerivedEntry, Entry, Operation}, indexed_merkle_tree::{Node, sha256}};
use indexed_merkle_tree::{IndexedMerkleTree, MerkleProof, UpdateProof};
/* use zk_snark::{MerkleCircuit}; */
use std::{time::Duration, hash};
use tokio::time::sleep;
use reqwest::Client;
use num::{BigInt, Num};




/// This function takes no arguments, creates and return new redis connections.
/// 
/// ## Returns the following tuple of redis connections
/// (Connection to the main dictionary (redis database with index 0), Connection to the derived dictionary (redis database with index 1))
/// 
pub fn create_redis_clients() -> (redis::Connection, redis::Connection, redis::Connection, redis::Connection, redis::Connection, redis::Connection) {
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let derived_client = redis::Client::open("redis://127.0.0.1/1").unwrap();
    let input_order = redis::Client::open("redis://127.0.0.1/2").unwrap();
    let app_state = redis::Client::open("redis://127.0.0.1/3").unwrap();
    let merkle_proos = redis::Client::open("redis://127.0.0.1/4").unwrap();
    let commitments = redis::Client::open("redis://127.0.0.1/5").unwrap();

    (client.get_connection().unwrap(), derived_client.get_connection().unwrap(), input_order.get_connection().unwrap(), app_state.get_connection().unwrap(), merkle_proos.get_connection().unwrap(), commitments.get_connection().unwrap())
}


/// This function takes no arguments, creates and returns an ed25519 keypair.
/// 
/// ## Returns the following keypair struct
/// pub struct Keypair {
///     pub secret: SecretKey,
///     pub public: PublicKey,
/// }
/// 
fn create_keypair() -> Keypair {
    // A random number generator that retrieves randomness from from the operating system. (no pseudo random numbers)
    let mut csprng = OsRng{};
    Keypair::generate(&mut csprng)
}

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
fn signature_is_valid(incoming_entry: &IncomingEntry, signature: Signature) -> bool {
    // load dictionary from redis
    let (mut con, _, _, _, _ ,_) = create_redis_clients();

    // extracts the value of the id from the incoming entry from the redis database
    let result: Result<String, RedisError> = con.get(&incoming_entry.id);

    // match the result of the redis query
    match result {
        // if the id exists, check if the signature is valid
        Ok(value) => {
            // parse hashchain from redis for the found id and store it in a vector
            let current_chain: Vec<ChainEntry> = serde_json::from_str(&value).unwrap();

            // iterate over the parsed hashchain and check if any public key can verify the signature
            current_chain.iter().any(|entry| {
                // decode the base64 encoded public key
                let public_key = PublicKey::from_bytes(&general_purpose::STANDARD_NO_PAD.decode(&entry.value.as_bytes()).unwrap()).unwrap();
                // try to verify verify the signature
                if is_not_revoked(&current_chain, entry.value.clone()) {
                    public_key.verify(incoming_entry.public_key.as_bytes(), &signature).is_ok()
                } else {
                    false
                }
            })
        },
        // if the id does not exist, return false
        Err(_) => false,
    }
}

         
fn update_entry(operation: Operation, incoming_entry: &IncomingEntry, signature: Signature) -> bool {
    let (mut con, mut derived_con, mut input_order, _, _, _) = create_redis_clients();


    let result: Result<String, RedisError> = con.get(&incoming_entry.id);
    match result {
        // add a new key to an existing id 
        Ok(value) => {
            // hashchain already exists

            if !signature_is_valid(incoming_entry, signature) {
               return false;
            }

            // parse hashchain
            let mut current_chain: Vec<ChainEntry> = serde_json::from_str(&value).unwrap();

            // create new entry
            let new_chain_entry = ChainEntry {
                // hash value + last hash to avoid collisions
                hash: hex_digest(
                    Algorithm::SHA256, 
                    // format: H(newPublicKey, previous_hash)
                    format!("{}, {}, {}", operation, &incoming_entry.public_key, &current_chain.last().unwrap().hash
                ).as_bytes()),
                previous_hash: current_chain.last().unwrap().hash.clone(),
                operation: operation,
                value: incoming_entry.public_key.clone(),
            };

            // add new entry to hashchain and update dict
            current_chain.push(new_chain_entry.clone());
            let _: () = con.set(&incoming_entry.id, serde_json::to_string(&current_chain).unwrap()).unwrap();

            // update derived dict
            let hashed_key = sha256(&incoming_entry.id);
            let _: () = derived_con.set(&hashed_key, new_chain_entry.hash).unwrap();

            true
        },
        // register a new id and asscociate an initial key
        Err(_) => {
            let new_chain = vec![ChainEntry {
                hash: hex_digest(Algorithm::SHA256, format!("{}, {}, {}",  Operation::Add, &incoming_entry.public_key, Node::create_empty_hash()).as_bytes()),
                previous_hash: Node::create_empty_hash(),
                operation: operation,
                value: incoming_entry.public_key.clone(),
            }];
            let _: () = con.set(&incoming_entry.id, serde_json::to_string(&new_chain).unwrap()).unwrap();
            // set derived dict
            let hashed_key = hex_digest(Algorithm::SHA256, incoming_entry.id.as_bytes());
            let _: () = derived_con.set(hashed_key.clone(), new_chain.last().unwrap().hash.clone()).unwrap();
            let _: () = input_order.rpush("input_order", hashed_key).unwrap();
            true
        }
    }
    
}

/// The function takes an IncomingEntry and a private key as arguments and returns a Signature.
/// 
/// The function creates a secret key from the private key string sent by the frontend, then it creates a keypair from the secret key,
/// and finally it signs a message (the new public key of the incoming entry) with the keypair and returns the signature.
/// 
fn sign_message_and_get_signature(incoming_entry: &IncomingEntry, private_key: &String) -> Signature {
    // create secret key from string
    let secret_key = SecretKey::from_bytes(&general_purpose::STANDARD_NO_PAD.decode(private_key.as_bytes()).unwrap()).unwrap();

    // create keypair from secret key
    let public_key: PublicKey = (&secret_key).into();
    let keypair = Keypair { secret: secret_key, public: public_key };

    // sign message and return signature
    keypair.sign(incoming_entry.public_key.as_bytes())
}

#[post("/update-entry")]
async fn update(req_body: String) -> impl Responder {
    let (mut con, _, _, mut app_state, mut proof_con, _) = create_redis_clients();

    let epoch: u32 = app_state.get("epoch").unwrap();
    
    // incoming entry with private key object
    #[derive(Deserialize)]
    struct EntryWithKey {
        operation: Operation,
        incoming_entry: IncomingEntry,
        private_key: String,
    }
    
    let tree = create_tree();
    let entry_with_key: EntryWithKey = serde_json::from_str(&req_body).unwrap();
    let result: Result<String, RedisError> = con.get(&entry_with_key.incoming_entry.id);
    // wenn der eintrag bereits vorliegt, muss ein update durchgeführt werden, sonst insert
    let update_proof = match result {
        // add a new key to an existing id 
        Ok(_) => true,
        Err(_) => false,
    };
    let signature = sign_message_and_get_signature(&entry_with_key.incoming_entry, &entry_with_key.private_key);
    let update_successful = update_entry(entry_with_key.operation, &entry_with_key.incoming_entry, signature);
    
    if update_successful {
        let new_tree = create_tree();
        let hashed_id = sha256(&entry_with_key.incoming_entry.id);
        let node = new_tree.find_leaf_by_label(&hashed_id).unwrap();

        let proofs = if update_proof {
            let new_index = tree.clone().find_node_index(node.clone()).unwrap();
            serde_json::to_string(&tree.clone().generate_proof_of_update(new_index, node)).unwrap()
        } else {
            serde_json::to_string(&tree.clone().generate_proof_of_insert(node)).unwrap()
        };
        let _: () = proof_con.set(format!("epoch_{}_{}", epoch, tree.get_commitment()), proofs).unwrap();
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

#[post("/calculate-values")]
async fn calculate_values(req_body: String) -> impl Responder {
    let (mut con, _, _, _, _, _) = create_redis_clients();
    let incoming_id: String = serde_json::from_str(&req_body).unwrap();
    let result: Result<String, RedisError> = con.get(&incoming_id);

    match result {
        // add a new key to an existing id 
        Ok(value) => {
            // parse hashchain
            let current_chain: Vec<ChainEntry> = serde_json::from_str(&value).unwrap();
            let chain_copy = current_chain.clone();
            let mut values = vec![];

            for entry in current_chain {
                if is_not_revoked(&chain_copy, entry.value.clone()) {
                    values.push(entry.value);
                }
            }

            let json_response = serde_json::to_string(&json!({
                "values": values
            })).unwrap();

            HttpResponse::Ok().body(json_response)
        },
        // register a new id and asscociate an initial key
        Err(_) => {
            HttpResponse::BadRequest().body("Could calculate values")
        }
    }

   

}

#[get("/get-dictionaries")]
async fn get_dictionaries() -> impl Responder {
    let (mut con, mut derived_con, _, _, _, _) = create_redis_clients();

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


#[post("/validate-proof")]
async fn validate_proof(req_body: String) -> impl Responder {
    let (_, _, _, _, mut proof_con, _) = create_redis_clients();
    
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

    // Versuchen Sie, den Proof zu deserialisieren und zu verifizieren
    if let Ok((non_membership_proof, first_proof, second_proof)) = serde_json::from_str::<(MerkleProof, UpdateProof, UpdateProof)>(&value) {
        if IndexedMerkleTree::verify_insert_proof(non_membership_proof, first_proof, second_proof) {
            HttpResponse::Ok().body("Proof is valid")
        } else {
            HttpResponse::BadRequest().body("Proof is not valid")
        }
    } else if let Ok(proof) = serde_json::from_str::<UpdateProof>(&value) {
        if IndexedMerkleTree::verify_update_proof(proof) {
            HttpResponse::Ok().body("Proof is valid")
        } else {
            HttpResponse::BadRequest().body("Proof is not valid")
        }
    } else {
        HttpResponse::BadRequest().body("Invalid proof format")
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


 fn create_tree() -> IndexedMerkleTree {
    let (_, mut derived_dict, mut input_order, _, _, _) = create_redis_clients();

    let derived_dict_keys: Vec<String> = input_order.lrange("input_order", 0, -1).unwrap();

    // sort the keys
    let mut sorted_keys = derived_dict_keys.clone();
    sorted_keys.sort();

    let mut nodes: Vec<Node> = sorted_keys.iter().map(|key| {
        let value: String = derived_dict.get(key).unwrap();
        Node::initialize_leaf(true, true, key.clone(), value, Node::create_tail())
    }).collect();
    
    let mut next_power_of_two: usize = 8;
    while next_power_of_two < derived_dict_keys.len() {
        next_power_of_two *= 2;
    }
    
    for i in 0..nodes.len() - 1 {
        let is_next_node_active = nodes[i + 1].active.as_deref().unwrap();
        if is_next_node_active == &true {
            nodes[i].next = nodes[i + 1].label.clone();
            nodes[i] = nodes[i].clone().calculate_node_hash();
        }
    }
    
    nodes.sort_by_cached_key(|node| {
        let label = node.label.as_deref().unwrap();
        derived_dict_keys
            .iter()
            .enumerate()
            .find(|(_, k)| {
                *k == label
            })
            .unwrap()
            .0
    });

    while nodes.len() < next_power_of_two {
        let empty_hash = Node::create_empty_hash();
        nodes.push(Node::initialize_leaf(false, true, empty_hash.clone(), empty_hash, Node::create_tail()));
    }

    // alle nodes überprüfen, ob sie linkes oder rechtes kind sind
    let tree = IndexedMerkleTree::new(nodes);
    tree
}



/// Returns the merkle tree root of the given leaves
/// 
#[get("/initialize-merkle-tree")]
async fn initialize_merkle_tree() -> impl Responder {
   let size: usize = 8;
   let tree = IndexedMerkleTree::initialize(size);

    HttpResponse::Ok().body(serde_json::to_string(&tree.get_root()).unwrap())
}

/// Returns the merkle tree root of the given leaves
/// 
#[get("/get-commitment")]
async fn get_commitment() -> impl Responder {
   let tree = create_tree();

    HttpResponse::Ok().body(serde_json::to_string(&tree.get_commitment()).unwrap())
}

/// get current tree
/// 
#[get("/get-current-tree")]
async fn get_current_tree() -> impl Responder {
   let current_tree = create_tree();

    HttpResponse::Ok().body(serde_json::to_string(&current_tree.get_root()).unwrap())
}



async fn my_async_function() {
    let (_, mut derived_dict, mut input_order, mut con, _, _) = create_redis_clients();

    // beim ersten starten wird der Nullwert in die input tabelle geschrieben
    let derived_dict_keys: Vec<String> = input_order.lrange("input_order", 0, -1).unwrap();
    if derived_dict_keys.len() == 0 {
        let empty_hash = Node::create_empty_hash();
        let _: () = derived_dict.set(&empty_hash, &empty_hash).unwrap();
        let _: () = input_order.rpush("input_order", empty_hash.clone()).unwrap();
    }

     // epoch erhöhen zu beginn, da es sonst in der ersten epoche probleme gibt
     let result: Result<String, RedisError> = con.get(&"epoch");
     let epoch = match result {
         Ok(epoch) => { 
             let mut epoch_num = epoch.parse::<i32>().unwrap();
             epoch_num += 1;
             epoch_num.to_string()
         }
         Err(_) => "0".to_string(),
     };
     let _: () = con.set(&"epoch", &epoch).unwrap();


    // 60 Sek warten
    sleep(Duration::from_secs(36000)).await;

    match send_request().await {
        Ok(_) => (),
        Err(e) => eprintln!("Error: {:?}", e),
    };
}


async fn send_request() -> Result<(), Box<dyn std::error::Error>> {
    // zum einen wird die Epoche im Redis App State erhöht, zum anderen wir das Commitment für die Epoche gespeichert, also der aktuelle Zustand

    let (_, _, _, mut con, _, mut commitments) = create_redis_clients();
    let client = Client::new();
    let epoch: String = con.get(&"epoch").unwrap();
    // Commitment setzen
    let res = client.get("http://127.0.0.1:8080/get-commitment").send().await?;
    let res = res.text().await?;

    let _: () = commitments.set(&format!("epoch_{}", epoch), &res).unwrap();

    Ok(())
}

#[actix_web::main] //3ddb5d016d6ea15984fbae4659f7e672d8723f1da00356b56ca64b6da1959c4d
async fn main() -> std::io::Result<()> {

    spawn(async {
        loop {
            my_async_function().await;
        }
    });

    HttpServer::new(|| {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin("https://visualization.sebastianpusch.de")
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
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await 
}