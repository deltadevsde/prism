use crate::{
    node_types::Sequencer,
    WebServerConfig, error::DeimosError,
};
use indexed_merkle_tree::{sha256, ProofVariant};
use actix_cors::Cors;
use actix_web::{
    get, post,
    web::{self, Data},
    App as ActixApp, HttpResponse, HttpServer, Responder, dev::Server,
};
use bellman::groth16;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{self, json, Value};

use std::sync::Arc;

use crate::{
    storage::{ChainEntry, DerivedEntry, Entry, UpdateEntryJson},
    utils::{is_not_revoked, validate_epoch_from_proof_variants, validate_proof},
    zk_snark::{serialize_proof, HashChainEntryCircuit},
};

pub struct WebServer {
    pub cfg: WebServerConfig,
}

impl WebServer {
    pub fn new(cfg: WebServerConfig) -> Self {
        WebServer { cfg }
    }

    pub fn start(&self, session: Arc<Sequencer>) -> Server {
        // TODO: do we need to handle the unwraps for the use in production here? if it fails, the server wont start and we can fix it
        /* let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder.set_private_key_file(env.key_path, SslFiletype::PEM).unwrap();
        builder.set_certificate_chain_file(env.cert_path).unwrap(); */
        info!("Starting webserver on {}:{}", self.cfg.ip, self.cfg.port);
        let ctx = Data::new(session.clone());
        let (ip, port) = (self.cfg.ip.clone(), self.cfg.port);

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
        /* .bind_openssl((self.ip, self.port), builder)? */
        .bind((ip, port)).expect("Could not bind to port")
        .run()
    }
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
async fn update_entry(
    session: web::Data<Arc<Sequencer>>,
    signature_with_key: web::Json<Value>,
) -> impl Responder {
    // Check if JSON data can be structured as UpdateEntryJson
    let signature_with_key: UpdateEntryJson =
        match serde_json::from_value(signature_with_key.into_inner()) {
            Ok(entry_json) => entry_json,
            Err(_) => {
                return HttpResponse::BadRequest().json("Could not parse JSON data. Wrong format.")
            }
        };

    // get epoch number and latest epoch operation number from database
    let epoch: u64 = session.db.get_epoch().unwrap();
    let epoch_operation: u64 = session.db.get_epoch_operation().unwrap();

    let tree = session.create_tree().unwrap();

    let result: Result<Vec<ChainEntry>, DeimosError> = session.db.get_hashchain(&signature_with_key.id);
    // if the entry already exists, an update must be performed, otherwise insert
    let update_proof = match result {
        // add a new key to an existing id
        Ok(_) => true,
        Err(_) => false,
    };

    let update_successful = session.update_entry(&signature_with_key);

    if update_successful {
        let new_tree = session.create_tree().unwrap();
        let hashed_id = sha256(&signature_with_key.id);
        let node = new_tree.find_leaf_by_label(&hashed_id).unwrap();

        let proofs = if update_proof {
            let new_index = tree.clone().find_node_index(&node).unwrap();
            let (proof_of_update, _) = &tree.clone().generate_update_proof(new_index, node).unwrap();
            let pre_processed_string = serde_json::to_string(proof_of_update).unwrap();
            format!(r#"{{"Update":{}}}"#, pre_processed_string)
        } else {
            let pre_processed_string =
                serde_json::to_string(&tree.clone().generate_proof_of_insert(&node).unwrap()).unwrap();
            format!(r#"{{"Insert":{}}}"#, pre_processed_string)
        };

        session
            .db
            .add_merkle_proof(&epoch, &epoch_operation, &tree.get_commitment().unwrap(), &proofs);
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
/// The function retrieves the hashchain associated with the provided ID from the database. It then iterates through the hashchain to find all
/// the non-revoked keys. The resulting list of non-revoked keys is returned as a JSON object like the following:
/// {
/// "values": [public_key1, public_key2, ...]
/// }
///
/// If the ID is not found in the database, the endpoint will return a BadRequest response with the message "Could not calculate values".
///
#[post("/calculate-values")] // all active values for a given id
async fn calculate_values(con: web::Data<Arc<Sequencer>>, req_body: String) -> impl Responder {
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
            }))
            .unwrap();
            // return values
            HttpResponse::Ok().body(json_response)
        }
        Err(err) => HttpResponse::BadRequest().body(format!("Couldn't calculate values: {}", err)),
    }
}

/// The `/get-dictionaries` endpoint retrieves both main and derived dictionaries from the database.
///
/// The function returns a JSON object containing two fields: `dict` and `derived_dict`. Each field contains a list of dictionary entries.
///
#[get("/get-dictionaries")]
async fn get_hashchains(con: web::Data<Arc<Sequencer>>) -> impl Responder {
    let keys: Vec<String> = match con.db.get_keys() {
        Ok(keys) => keys,
        Err(_) => return HttpResponse::NotFound().body("Keys not found"),
    };
    let derived_keys: Vec<String> = match con.db.get_derived_keys() {
        Ok(keys) => keys,
        Err(_) => return HttpResponse::NotFound().body("Derived Keys not found"),
    };

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
            value: chain,
        });
    }

    for id in derived_keys {
        let value: String = con.db.get_derived_value(&id).unwrap();
        resp.derived_dict.push(DerivedEntry { id, value: value });
    }
    HttpResponse::Ok().body(serde_json::to_string(&resp).unwrap())
}

#[get("/get-dictionary/{id}")]
async fn get_hashchain(con: web::Data<Arc<Sequencer>>, id: web::Path<String>) -> impl Responder {
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
pub fn get_epochs_and_proofs(
    con: web::Data<Arc<Sequencer>>,
    epoch: &str,
) -> Result<(u64, String, String, Vec<ProofVariant>), Box<dyn std::error::Error>> {
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
        Err(_) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Could not parse epoch number",
            )))
        }
    };

    // Calculate the previous epoch
    let previous_epoch = epoch_number - 1;

    // Get current commitment from database
    let current_commitment: String = match con.db.get_commitment(&epoch_number) {
        Ok(value) => value,
        Err(_) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not find current commitment",
            )))
        }
    };

    // Get previous commitment from database
    let previous_commitment: String = match con.db.get_commitment(&previous_epoch) {
        Ok(value) => value,
        Err(_) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not find previous commitment",
            )))
        }
    };

    let proofs = match con.db.get_proofs_in_epoch(&previous_epoch) {
        Ok(value) => value,
        Err(_) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not find proofs in previous epoch",
            )))
        }
    };

    Ok((
        epoch_number,
        previous_commitment,
        current_commitment,
        proofs,
    ))
}

/// Endpoint: /validate-proof
/// Validates a Merkle proof and returns whether it is valid or not.
///
/// This function receives a `proof_id` within the request body, which corresponds to the ID of a proof
/// stored in the database. The proof can be either a single `UpdateProof` or a tuple containing a `MerkleProof`
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
async fn handle_validate_proof(con: web::Data<Arc<Sequencer>>, req_body: String) -> impl Responder {
    // get proof id from the database
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
        Err(err) => HttpResponse::BadRequest().body(err.to_string()),
    }
}

// TODO: better documentation needed
// This function validates an epoch by creating and verifying zkSNARK evidence for all transactions in the epoch and verifying them.
// req_body: A string containing the epoch number to be validated.
//
// Returns an HTTP response containing either a confirmation of successful validation or an error.
#[post("/validate-epoch")]
async fn handle_validate_epoch(con: web::Data<Arc<Sequencer>>, req_body: String) -> impl Responder {
    debug!("Validating epoch {}", req_body);
    let epoch: String = match serde_json::from_str(&req_body) {
        Ok(epoch) => epoch,
        Err(_) => return HttpResponse::BadRequest().body("Invalid epoch"),
    };

    let (epoch_number, previous_commitment, current_commitment, proofs) =
        match get_epochs_and_proofs(con, &epoch.as_str()) {
            Ok(value) => value,
            Err(err) => {
                error!(
                    "validate-epoch: getting proofs for epoch {}: {}",
                    epoch, err
                );
                return HttpResponse::BadRequest()
                    .body("Something went wrong while getting the proofs");
            }
        };

    debug!(
        "validate-epoch: found {:?} proofs in epoch {}",
        proofs.len(),
        epoch
    );

    let (proof, _verifying_key) = match validate_epoch_from_proof_variants(
        &previous_commitment,
        &current_commitment,
        &proofs,
    ) {
        Ok(proof) => proof,
        Err(err) => {
            return HttpResponse::BadRequest().body(err.to_string());
        }
    };

    // Create the JSON object for the response
    let response = json!({
        "epoch": epoch_number,
        "proof": serialize_proof(&proof)
    });

    HttpResponse::Ok().json(response)
}

#[post("/validate-hashchain-proof")]
async fn handle_validate_hashchain_proof(
    session: web::Data<Arc<Sequencer>>,
    incoming_value: web::Json<Value>,
) -> impl Responder {
    #[derive(Deserialize)]
    struct ValidateHashchainBody {
        pub_key: String, // public key from other company
        value: String,   // clear text
    }

    // Check if JSON data can be structured as UpdateEntryJson
    let incoming_value: ValidateHashchainBody =
        match serde_json::from_value(incoming_value.into_inner()) {
            Ok(incoming_value_json) => incoming_value_json,
            Err(_) => {
                return HttpResponse::BadRequest().json("Could not parse JSON data. Wrong format.")
            }
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

    let public_param = match HashChainEntryCircuit::create_public_parameter(&incoming_value.value) {
        Ok(param) => param,
        Err(e) => {
            return HttpResponse::BadRequest().json(e.to_string());
        }
    };

    // debug!("Verifying zkSNARK proof...");
    match groth16::verify_proof(&pvk, &proof, &[public_param]) {
        Ok(_) => {
            info!("proof successfully verified with: {:?}", public_param);
            return HttpResponse::Ok().json({
                json!({
                    "proof": serialize_proof(&proof),
                    "public_param": sha256(&incoming_value.value),
                })
            });
        }
        Err(_) => HttpResponse::BadRequest().body("Proof is invalid"),
    }
}

/// Returns the commitment (tree root) of the IndexedMerkleTree initialized from the database.
///
#[get("/get-commitment")]
async fn get_commitment(con: web::Data<Arc<Sequencer>>) -> impl Responder {
    match con.create_tree() {
        Ok(tree) => {
            match tree.get_commitment() {
                Ok(commitment) => {
                    match serde_json::to_string(&commitment) {
                        Ok(serialized) => HttpResponse::Ok().body(serialized),
                        Err(_) => HttpResponse::InternalServerError().body("Failed to serialize commitment"),
                    }
                },
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/// Returns the current state of the IndexedMerkleTree initialized from the database as a JSON object.
///
#[get("/get-current-tree")]
async fn get_current_tree(con: web::Data<Arc<Sequencer>>) -> impl Responder {
    match con.create_tree() {
        Ok(tree) => {
            match tree.get_root() {
                Ok(node) => {
                    match serde_json::to_string(&node) {
                        Ok(serialized) => HttpResponse::Ok().body(serialized),
                        Err(_) => HttpResponse::InternalServerError().body("Failed to serialize tree"),
                    }
                },
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/get-epoch-operations")]
async fn get_epoch_operations(con: web::Data<Arc<Sequencer>>, req_body: String) -> impl Responder {
    //  try to parse proof id from request body
    let epoch: String = match serde_json::from_str(&req_body) {
        Ok(epoch) => epoch,
        Err(_) => return HttpResponse::BadRequest().body("Invalid epoch"),
    };

    let (_, previous_commitment, current_commitment, proofs) =
        get_epochs_and_proofs(con, &epoch.as_str()).unwrap();

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
async fn get_epochs(con: web::Data<Arc<Sequencer>>) -> impl Responder {
    let mut epochs = con.db.get_epochs().unwrap();

    #[derive(Serialize, Deserialize)]
    struct Epoch {
        id: u64,
        commitment: String,
    }

    #[derive(Serialize, Deserialize)]
    struct Response {
        epochs: Vec<Epoch>,
    }

    let mut resp = Response { epochs: Vec::new() };

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
async fn handle_finalize_epoch(con: web::Data<Arc<Sequencer>>) -> impl Responder {
    match con.finalize_epoch().await {
        Ok(proof) => HttpResponse::Ok().body(json!(serialize_proof(&proof)).to_string()),
        Err(err) => HttpResponse::BadRequest().body(err.to_string()),
    }
}
