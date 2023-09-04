pub mod indexed_merkle_tree;
pub mod zk_snark;
pub mod storage;
mod utils;

use celestia_rpc::client::new_websocket;
use celestia_types::nmt::Namespace;
use clap::{Parser, Subcommand};
use actix_cors::Cors;
use actix_web::{web::{self, Data}, get, rt::{spawn}, post, App as ActixApp, HttpResponse, HttpServer, Responder};
use config::{ConfigBuilder, builder::DefaultState, FileFormat, File};
use bellman::groth16;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use serde_json::{self, json, Value};
use indexed_merkle_tree::{ProofVariant};
use indexed_merkle_tree::{sha256};
use storage::{Session, CelestiaConnection}; 
use core::panic;
use std::{time::Duration, sync::Mutex, process::Command};
use tokio::{time::sleep};
use num::{BigInt, Num};
use openssl::{ssl::{SslAcceptor, SslFiletype, SslMethod}, sign};
use std::env;
use dotenv::dotenv;
use std::sync::{Arc};


use crate::{storage::{RedisConnections, Operation, ChainEntry, Entry, DerivedEntry, UpdateEntryJson}, zk_snark::{convert_proof_to_custom, HashChainEntryCircuit}};
use crate::utils::{is_not_revoked, validate_epoch, validate_proof};

#[macro_use] extern crate log;


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
async fn update_entry(session: web::Data<Arc<Session>>, signature_with_key: web::Json<Value>,) -> impl Responder {
    // Check if JSON data can be structured as UpdateEntryJson
    let signature_with_key: UpdateEntryJson = match serde_json::from_value(signature_with_key.into_inner()) {
        Ok(entry_json) => entry_json,
        Err(_) => return HttpResponse::BadRequest().json("Could not parse JSON data. Wrong format."),
    };

    let epoch: u64 = session.db.get_epoch().unwrap();
    let epoch_operation: u64 = session.db.get_epoch_operation().unwrap();

    let tree = session.create_tree();

    let result: Result<Vec<ChainEntry>, &str> = session.db.get_hashchain(&signature_with_key.id);
    // if the entry already exists, an update must be performed, otherwise insert
    let update_proof = match result {
        // add a new key to an existing id 
        Ok(_) => true,
        Err(_) => false,
    };

    println!("update_proof: {:?}", &signature_with_key);

    let update_successful = session.update_entry(&signature_with_key);

    if update_successful {
        let new_tree = session.create_tree();
        let hashed_id = sha256(&signature_with_key.id);
        let node = new_tree.find_leaf_by_label(&hashed_id).unwrap();

        let proofs = if update_proof {
            let new_index = tree.clone().find_node_index(&node).unwrap();
            let (proof_of_update, _) = &tree.clone().generate_update_proof(new_index, node);
            let pre_processed_string = serde_json::to_string(proof_of_update).unwrap();
            format!(r#"{{"Update":{}}}"#, pre_processed_string)

        } else {
            let pre_processed_string = serde_json::to_string(&tree.clone().generate_proof_of_insert(&node)).unwrap();
            format!(r#"{{"Insert":{}}}"#, pre_processed_string)
        };

        session.db.add_merkle_proof(&epoch, &epoch_operation, &tree.get_commitment(), &proofs);
        session.db.increment_epoch_operation(); 
        HttpResponse::Ok().body("Updated entry successfully")
    } else {
        HttpResponse::BadRequest().body("Could not update entry")
    } 
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
async fn calculate_values(con: web::Data<Arc<Session>>, req_body: String) -> impl Responder {
    let incoming_id: String = serde_json::from_str(&req_body).unwrap();

    match con.db.get_hashchain(&incoming_id) {
        // id exists, calculate values
        Ok(value) => {
            let chain_copy = value.clone();
            let mut values = vec![];

            // add all non-revoked keys to values vector 
            for entry in value {
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
        Err(err) => {
            HttpResponse::BadRequest().body(format!("Couldn't calculate values: {}", err))
        }
    }
}


/// The `/get-dictionaries` endpoint retrieves both main and derived dictionaries from the Redis database.
///
/// The function returns a JSON object containing two fields: `dict` and `derived_dict`. Each field contains a list of dictionary entries.
///
#[get("/get-dictionaries")]
async fn get_hashchains(con: web::Data<Arc<Session>>) -> impl Responder {
    let keys: Vec<String> = con.db.get_keys();
    let derived_keys: Vec<String> = con.db.get_derived_keys();

    #[derive(Serialize, Deserialize)]
    struct Response {
        dict: Vec<Entry>,
        derived_dict: Vec<DerivedEntry>,
    }

    let mut resp = Response {
        dict: Vec::new(),
        derived_dict: Vec::new(),
    };
    for id in keys {
        let chain: Vec<ChainEntry> = con.db.get_hashchain(&id).unwrap();
        resp.dict.push(Entry {
            id: id,
            value: chain
        });
    }

    for id in derived_keys {
        let value: String = con.db.get_derived_value(&id).unwrap();
        resp.derived_dict.push(DerivedEntry {
            id,
            value: value
        });
    }
    HttpResponse::Ok().body(serde_json::to_string(&resp).unwrap())
}

#[get("/get-dictionary/{id}")]
async fn get_hashchain(con: web::Data<Arc<Session>>, id: web::Path<String>) -> impl Responder {
    let id_str = id.into_inner();
    let chain: Vec<ChainEntry> = match con.db.get_hashchain(&id_str) {
        Ok(chain) => chain,
        Err(_) => return HttpResponse::NotFound().body("No dictionary found for the given id"),
    };

    #[derive(Serialize, Deserialize)]
    struct Response {
        id: String,
        dict: Vec<ChainEntry>,
    }

    let resp = Response {
        id: id_str,
        dict: chain,
    };

    HttpResponse::Ok().body(serde_json::to_string(&resp).unwrap())
}

// get prev commitment, current commitments and proofs in between
// TODO: is this the right error return type?
pub fn get_epochs_and_proofs(con: web::Data<Arc<Session>>, epoch: &str) -> Result<(u64, String, String, Vec<ProofVariant>), Box<dyn std::error::Error>> {
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
    let current_commitment: String = match con.db.get_commitment(&epoch_number) {
       Ok(value) => value,
        Err(_) => return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find current commitment",
        )))
    };

    // Get previous commitment from database
    let previous_commitment: String = match con.db.get_commitment(&previous_epoch) {
        Ok(value) => value,
        Err(_) => return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find previous commitment",
        )))
    };

    let proofs = match con.db.get_proofs_in_epoch(&previous_epoch) {
        Ok(value) => value,
        Err(_) => return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find proofs in previous epoch",
        )))
    };

    Ok((epoch_number, previous_commitment, current_commitment, proofs))
}


/// Endpoint: /validate-proof
/// Validates a Merkle proof and returns whether it is valid or not.
///
/// This function receives a `proof_id` within the request body, which corresponds to the ID of a proof
/// stored in Redis. The proof can be either a single `UpdateProof` or a tuple containing a `MerkleProof`
/// and two `UpdateProof`s (which represents an insertion proof).
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
/// A `BadRequest` is returned if the proof cannot be deserialized or is not in the correct format,
/// or if the zkSNARK circuit creation or proof verification fails.
#[post("/validate-proof")]
async fn handle_validate_proof(con: web::Data<Arc<Session>>, req_body: String) -> impl Responder {
    // get proof id from redis
    let proof_id: String = match serde_json::from_str(&req_body) {
        Ok(proof_id) => proof_id,
        Err(_) => return HttpResponse::BadRequest().body("Invalid proof ID"),
    };
    let value: String = match con.db.get_proof(&proof_id) {
        Ok(value) => value,
        Err(_) => return HttpResponse::BadRequest().body("Could not find proof"),
    };

    match validate_proof(value) {
       Ok(_) => HttpResponse::Ok().body("Proof is valid"),
        Err(err) => HttpResponse::BadRequest().body(err),
    }
}

// TODO: better documentation needed
// This function validates an epoch by creating and verifying zkSNARK evidence for all transactions in the epoch and verifying them.
// req_body: A string containing the epoch number to be validated.
//
// Returns an HTTP response containing either a confirmation of successful validation or an error.
#[post("/validate-epoch")]
async fn handle_validate_epoch(con: web::Data<Arc<Session>>, req_body: String) -> impl Responder {
    debug!("Validating epoch {}", req_body);
    let epoch: String = match serde_json::from_str(&req_body) {
        Ok(epoch) => epoch,
        Err(_) => return HttpResponse::BadRequest().body("Invalid epoch"),
    };

    let (epoch_number , previous_commitment, current_commitment, proofs) = match get_epochs_and_proofs(con, &epoch.as_str()) {
        Ok(value) => value,
        Err(err) => {
            error!("validate-epoch: getting proofs for epoch {}: {}", epoch, err);
            return HttpResponse::BadRequest().body("Something went wrong while getting the proofs");
        },
    };

    debug!("validate-epoch: found {:?} proofs in epoch {}", proofs.len(), epoch);

    let proof = match validate_epoch(&previous_commitment, &current_commitment, &proofs) {
        Ok(proof) => proof,
        Err(err) => {
            return HttpResponse::BadRequest().body(err);
        },
    };

    // Create the JSON object for the response
    let response = json!({
        "epoch": epoch_number,
        "proof": convert_proof_to_custom(&proof)
    });

    HttpResponse::Ok().json(response)
}

#[post("/validate-hashchain-proof")]
async fn handle_validate_hashchain_proof(session: web::Data<Arc<Session>>, incoming_value: web::Json<Value>,) -> impl Responder {
    #[derive(Deserialize)]
    struct ValidateHashchainBody {
        pub_key: String, // public key from other company
        value: String, // clear text
    }  

    // Check if JSON data can be structured as UpdateEntryJson
    let incoming_value: ValidateHashchainBody = match serde_json::from_value(incoming_value.into_inner()) {
        Ok(incoming_value_json) => incoming_value_json,
        Err(_) => return HttpResponse::BadRequest().json("Could not parse JSON data. Wrong format."),
    };

    let hashchain = session.db.get_hashchain(&incoming_value.pub_key).unwrap();

    let circuit = match HashChainEntryCircuit::create(&incoming_value.value, hashchain) {
        Ok(circuit) => circuit,
        Err(e) => {
            error!("Error creating circuit: {}", e);
            return HttpResponse::BadRequest().json("Could not create circuit");
        }
    };

    let rng = &mut OsRng;

    // debug!("Creating parameters with BLS12-381 pairing-friendly elliptic curve construction....");
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).unwrap();

    // debug!("Creating proof for zkSNARK...");
    let proof = groth16::create_random_proof(circuit.clone(), &params, rng).unwrap();

    // debug!("Prepare verifying key for zkSNARK...");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    let public_param = HashChainEntryCircuit::create_public_parameter(&incoming_value.value);

    // debug!("Verifying zkSNARK proof...");
    match groth16::verify_proof(
        &pvk,
        &proof,
        &[public_param],
    ) {
        Ok(_) => {
            println!("Proof is valid");
            println!("Verified with: {:?}", public_param);
            return HttpResponse::Ok().json({
                json!({
                    "proof": convert_proof_to_custom(&proof),
                    "public_param": sha256(&incoming_value.value),
                })
            })
        },
        Err(_) => HttpResponse::BadRequest().body("Proof is invalid"),
    }
}

/// Returns the commitment (tree root) of the IndexedMerkleTree initialized from Redis data.
///
#[get("/get-commitment")]
async fn get_commitment(con: web::Data<Arc<Session>>) -> impl Responder {
    println!("get-commitment");
    HttpResponse::Ok().body(serde_json::to_string(&con.create_tree().get_commitment()).expect("Failed to serialize commitment"))
}


/// Returns the current state of the IndexedMerkleTree initialized from Redis data as a JSON object.
///
#[get("/get-current-tree")]
async fn get_current_tree(con: web::Data<Arc<Session>>) -> impl Responder {
    HttpResponse::Ok().body(serde_json::to_string(&con.create_tree().get_root()).expect("Failed to serialize tree root"))
}


#[post("/get-epoch-operations")]
async fn get_epoch_operations(con: web::Data<Arc<Session>>, req_body: String) -> impl Responder {
    //  try to parse proof id from request body
    let epoch: String = match serde_json::from_str(&req_body) {
        Ok(epoch) => epoch,
        Err(_) => return HttpResponse::BadRequest().body("Invalid epoch"),
    };

    let (_, previous_commitment, current_commitment, proofs) = get_epochs_and_proofs(con, &epoch.as_str()).unwrap();

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
async fn get_epochs(con: web::Data<Arc<Session>>) -> impl Responder {
    let mut epochs = con.db.get_epochs().unwrap();

    println!("get-epochs: {:?}", epochs);

    #[derive(Serialize, Deserialize)]
    struct Epoch {
        id: u64,
        commitment: String,
    }

    #[derive(Serialize, Deserialize)]
    struct Response {
        epochs: Vec<Epoch>,
    }

    let mut resp = Response {
        epochs: Vec::new(),
    };

    epochs.sort();

    for epoch in epochs {
        let value: String = con.db.get_commitment(&epoch).unwrap();
        resp.epochs.push(Epoch {
            id: epoch,
            commitment: value,
        });
    }


    HttpResponse::Ok().body(serde_json::to_string(&resp).unwrap())
}

#[get("/finalize-epoch")]
async fn handle_finalize_epoch(con: web::Data<Arc<Session>>) -> impl Responder {
    match con.finalize_epoch().await {
        Ok(proof) => HttpResponse::Ok().body(json!(convert_proof_to_custom(&proof)).to_string()),
        Err(err) => HttpResponse::BadRequest().body(err)
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

async fn lightclient_loop(session: &Arc<Session>) {
    panic!("lightclient_loop: not implemented yet");
}

async fn sequencer_loop(session: &Arc<Session>, duration: u64) {
    debug!("sequencer_loop: started");
    let derived_keys = session.db.get_derived_keys();
    if derived_keys.len() == 0 { // if the dict is empty, we need to initialize the dict and the input order
        session.db.initialize_derived_dict();
    }

    loop {
        // let mut db_guard = session.db.lock().unwrap();
        match session.finalize_epoch().await {
            Ok(_) => {
                //info!("sequencer_loop: finalized epoch {}", db_guard.get_epoch().unwrap());
            },
            Err(e) => error!("sequencer_loop: finalizing epoch: {}", e)
        }
        //drop(db_guard);
        sleep(Duration::from_secs(duration)).await;
    }
}

#[derive(Parser, Clone, Debug, Deserialize)]
#[command(author, version, about, long_about = None)]
struct CommandLineArgs {
    /// Log level
    #[arg(short, long)]
    log_level: Option<String>,

    /// Celestia Client websocket URL
    #[arg(short, long)]
    celestia_client: Option<String>,

    /// Celestia Namespace ID
    #[arg(short, long)]
    namespace_id: Option<String>,

    /// Duration between epochs in seconds
    #[arg(short, long)]
    epoch_time: Option<u64>,

    /// IP address
    #[arg(short, long)]
    ip: Option<String>,

    /// Port number
    #[arg(short, long)]
    port: Option<u16>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, Subcommand, Deserialize)]
enum Commands {
    LightClient,
    Sequencer,
}

#[derive(Debug, Deserialize)]
struct Config {
    ip: String,
    port: u16,
    log_level: String,
    celestia_connection_string: String,
    namespace_id: String,
    epoch_time: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ip: "127.0.0.1".to_string(),
            port: 8080,
            log_level: "DEBUG".to_string(),
            celestia_connection_string: "ws://localhost:26658".to_string(),
            namespace_id: "0000000000de1005".to_string(),
            epoch_time: 60,
        }
    }
}

fn load_config(args: CommandLineArgs) -> Result<Config, config::ConfigError> {
    let settings = ConfigBuilder::<DefaultState>::default()
        .add_source(File::from_str(include_str!("config.toml"), FileFormat::Toml))
        .build()?;

    println!("{}", settings.get_string("log_level").unwrap_or_default());

    Ok(Config {
        ip: args.ip.unwrap_or_default(),
        port: args.port.unwrap_or_default(),
        log_level: args.log_level.unwrap_or_default(),
        celestia_connection_string: args.celestia_client.unwrap_or_default(),
        namespace_id: args.namespace_id.unwrap_or_default(),
        epoch_time: args.epoch_time.unwrap_or_default() as u64,
    })
}

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
    let args = CommandLineArgs::parse();
    let config = load_config(args.clone()).unwrap();

    std::env::set_var("RUST_LOG", &config.log_level);

    pretty_env_logger::init();
    dotenv().ok();

    let session = Arc::new(Session { 
        db: Arc::new(RedisConnections::new()),
        da: Arc::new(CelestiaConnection{
            client: new_websocket(&config.celestia_connection_string, None).await.unwrap(),
            namespace_id: Namespace::new_v0(&config.namespace_id.as_bytes()).unwrap(),
            sync_target: Arc::new(Mutex::new(0)),
        })
    });
    /* da: Arc::new(CelestiaConnection{
        client: CelestiaClient::new_client(&config.celestia_client, None).await,
        namespace_id: NamespaceId::new_v0(&config.namespace_id).unwrap(),
    }), */
    let sequencer_session = Arc::clone(&session); 

    spawn(async move {
        match args.command {
            Commands::LightClient { } => {
                /* lightclient_loop(&sequencer_session).await; */
            },
            Commands::Sequencer { } => {
                sequencer_loop(&sequencer_session, config.epoch_time).await;
            },
        }
    });

    let ctx = Data::new(session);
    
    
    /* let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file(env.key_path, SslFiletype::PEM).unwrap();
    builder.set_certificate_chain_file(env.cert_path).unwrap(); */
    
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://localhost:3001")
            .allowed_origin("https://visualizer.sebastianpusch.de")
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();
        ActixApp::new()
            .app_data(ctx.clone())
            .wrap(cors)
            .service(get_hashchains)
            .service(get_hashchain)
            .service(get_commitment)
            .service(get_current_tree)
            .service(get_epochs)
            .service(get_epoch_operations)
            .service(update_entry)
            .service(calculate_values)
            .service(handle_validate_proof)
            .service(handle_validate_epoch)
            .service(handle_validate_hashchain_proof)
            .service(handle_finalize_epoch)
    })
    /* .bind_openssl((config.ip, config.port), builder)? */
    .bind((config.ip.clone(), config.port))?
    .run()
    .await
}