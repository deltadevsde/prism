use actix_cors::Cors;
use actix_web::{
    dev::Server,
    get, post,
    web::{self, Data},
    App as ActixApp, HttpResponse, HttpServer, Responder,
};
use bellman::groth16;
use bls12_381::Bls12;
use indexed_merkle_tree::{sha256_mod, tree::Proof};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{self, json, Value};

use std::sync::Arc;

use crate::{
    cfg::WebServerConfig,
    error::DeimosResult,
    node_types::sequencer::Sequencer,
    storage::{ChainEntry, DerivedEntry, Entry, UpdateEntryJson},
    utils::{is_not_revoked, validate_proof},
    zk_snark::{BatchMerkleProofCircuit, Bls12Proof, HashChainEntryCircuit},
};

pub struct WebServer {
    pub cfg: WebServerConfig,
}

#[derive(Serialize, Deserialize)]
pub struct EpochData {
    epoch_number: u64,
    previous_commitment: String,
    current_commitment: String,
    proofs: Vec<Proof>,
}

impl WebServer {
    pub fn new(cfg: WebServerConfig) -> Self {
        WebServer { cfg }
    }

    pub fn start(&self, session: Arc<Sequencer>) -> Server {
        /* let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder.set_private_key_file(env.key_path, SslFiletype::PEM).unwrap();
        builder.set_certificate_chain_file(env.cert_path).unwrap(); */
        info!("starting webserver on {}:{}", self.cfg.host, self.cfg.port);
        let ctx = Data::new(session.clone());
        let (ip, port) = (self.cfg.host.clone(), self.cfg.port);

        HttpServer::new(move || {
            let cors = Cors::default()
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
        .bind((ip, port))
        .expect("Could not bind to port")
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
    let signature_with_key: UpdateEntryJson =
        match serde_json::from_value(signature_with_key.into_inner()) {
            Ok(entry_json) => entry_json,
            Err(_) => {
                return HttpResponse::BadRequest().json("Could not parse JSON data. Wrong format.")
            }
        };

    let epoch = match session.db.get_epoch() {
        Ok(e) => e,
        Err(e) => {
            return HttpResponse::InternalServerError().json(format!("Error getting epoch: {}", e))
        }
    };

    let epoch_operation = match session.db.get_epoch_operation() {
        Ok(eo) => eo,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(format!("Error getting epoch operation: {}", e))
        }
    };

    let tree = match session.create_tree() {
        Ok(t) => t,
        Err(e) => {
            return HttpResponse::InternalServerError().json(format!("Error creating tree: {}", e))
        }
    };

    let result: DeimosResult<Vec<ChainEntry>> = session.db.get_hashchain(&signature_with_key.id);
    let update_proof = result.is_ok();

    match session.update_entry(&signature_with_key) {
        Ok(_) => {
            let new_tree = match session.create_tree() {
                Ok(t) => t,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .json(format!("Error creating new tree: {}", e))
                }
            };
            let hashed_id = sha256_mod(&signature_with_key.id);
            let mut node = match new_tree.find_leaf_by_label(&hashed_id) {
                Some(n) => n,
                None => return HttpResponse::InternalServerError().json("Error finding leaf"),
            };

            let proofs = if update_proof {
                let new_index = match tree.clone().find_node_index(&node) {
                    Some(i) => i,
                    None => {
                        return HttpResponse::InternalServerError()
                            .json("Error finding node index: {}")
                    }
                };
                let update_proof = match tree.clone().update_node(new_index, node) {
                    Ok(p) => p,
                    Err(e) => {
                        return HttpResponse::InternalServerError()
                            .json(format!("Error updating node: {}", e))
                    }
                };
                match serde_json::to_string(&update_proof) {
                    Ok(pre_processed_string) => format!(r#"{{"Update":{}}}"#, pre_processed_string),
                    Err(e) => {
                        return HttpResponse::InternalServerError()
                            .json(format!("Error serializing update proof: {}", e))
                    }
                }
            } else {
                let insert_proof = match tree.clone().insert_node(&mut node) {
                    Ok(p) => p,
                    Err(e) => {
                        return HttpResponse::InternalServerError()
                            .json(format!("Error inserting node: {}", e))
                    }
                };
                match serde_json::to_string(&insert_proof) {
                    Ok(pre_processed_string) => format!(r#"{{"Insert":{}}}"#, pre_processed_string),
                    Err(e) => {
                        return HttpResponse::InternalServerError()
                            .json(format!("Error serializing insert proof: {}", e))
                    }
                }
            };

            let commitment = match tree.get_commitment() {
                Ok(c) => c,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .json(format!("Error getting commitment: {}", e))
                }
            };

            if let Err(err) =
                session
                    .db
                    .add_merkle_proof(&epoch, &epoch_operation, &commitment, &proofs)
            {
                return HttpResponse::InternalServerError()
                    .json(format!("Error adding merkle proof: {}", err));
            }

            if let Err(err) = session.db.increment_epoch_operation() {
                return HttpResponse::InternalServerError()
                    .json(format!("Error incrementing epoch operation: {}", err));
            }

            HttpResponse::Ok().body("Updated entry successfully")
        }
        Err(e) => HttpResponse::BadRequest().body(format!("Could not update entry: {}", e)),
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
    let incoming_id: String = match serde_json::from_str(&req_body) {
        Ok(id) => id,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid JSON: {}", e)),
    };

    match con.db.get_hashchain(&incoming_id) {
        Ok(value) => {
            let chain_copy = value.clone();
            let mut values = vec![];

            // add all non-revoked keys to values vector
            for entry in value {
                if is_not_revoked(&chain_copy, entry.value.clone()) {
                    values.push(entry.value);
                }
            }

            match serde_json::to_string(&json!({ "values": values })) {
                Ok(json_response) => HttpResponse::Ok().body(json_response),
                Err(e) => HttpResponse::InternalServerError()
                    .body(format!("Failed to serialize response: {}", e)),
            }
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
    let keys = match con.db.get_keys() {
        Ok(keys) => keys,
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Failed to get keys: {}", e))
        }
    };

    let derived_keys = match con.db.get_derived_keys() {
        Ok(keys) => keys,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to get derived keys: {}", e))
        }
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
        match con.db.get_hashchain(&id) {
            Ok(chain) => resp.dict.push(Entry { id, value: chain }),
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to get hashchain for id {}: {}", id, e))
            }
        }
    }

    for id in derived_keys {
        match con.db.get_derived_value(&id) {
            Ok(value) => resp.derived_dict.push(DerivedEntry { id, value }),
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to get derived value for id {}: {}", id, e))
            }
        }
    }

    match serde_json::to_string(&resp) {
        Ok(json_resp) => HttpResponse::Ok().body(json_resp),
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Failed to serialize response: {}", e))
        }
    }
}

#[get("/get-dictionary/{id}")]
async fn get_hashchain(con: web::Data<Arc<Sequencer>>, id: web::Path<String>) -> impl Responder {
    let id_str = id.into_inner();

    match con.db.get_hashchain(&id_str) {
        Ok(chain) => {
            #[derive(Serialize, Deserialize)]
            struct Response {
                id: String,
                dict: Vec<ChainEntry>,
            }

            let resp = Response {
                id: id_str,
                dict: chain,
            };

            match serde_json::to_string(&resp) {
                Ok(json_resp) => HttpResponse::Ok().body(json_resp),
                Err(e) => HttpResponse::InternalServerError()
                    .body(format!("Failed to serialize response: {}", e)),
            }
        }
        Err(e) => {
            HttpResponse::NotFound().body(format!("No dictionary found for the given id: {}", e))
        }
    }
}

// get prev commitment, current commitments and proofs in between
// TODO: is this the right error return type?
pub fn get_epochs_and_proofs(
    con: web::Data<Arc<Sequencer>>,
    epoch: &str,
) -> Result<EpochData, Box<dyn std::error::Error>> {
    if epoch == "0" {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Epoch 0 does not have a previous commitment",
        )));
    }

    let epoch_number = epoch.parse::<u64>().map_err(|_| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Could not parse epoch number",
        ))
    })?;

    let previous_epoch = epoch_number - 1;

    let current_commitment = con.db.get_commitment(&epoch_number).map_err(|_| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find current commitment",
        ))
    })?;

    let previous_commitment = con.db.get_commitment(&previous_epoch).map_err(|_| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find previous commitment",
        ))
    })?;

    let proofs = con.db.get_proofs_in_epoch(&previous_epoch).map_err(|_| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find proofs in previous epoch",
        ))
    })?;

    Ok(EpochData {
        epoch_number,
        previous_commitment,
        current_commitment,
        proofs,
    })
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
    let proof_id: String = match serde_json::from_str(&req_body) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().body("Invalid proof ID"),
    };

    match con.db.get_proof(&proof_id) {
        Ok(value) => match validate_proof(value) {
            Ok(_) => HttpResponse::Ok().body("Proof is valid"),
            Err(err) => HttpResponse::BadRequest().body(err.to_string()),
        },
        Err(_) => HttpResponse::BadRequest().body("Could not find proof"),
    }
}

// TODO: better documentation needed
// This function validates an epoch by creating and verifying zkSNARK evidence for all transactions in the epoch and verifying them.
// req_body: A string containing the epoch number to be validated.
//
// Returns an HTTP response containing either a confirmation of successful validation or an error.
#[post("/validate-epoch")]
async fn handle_validate_epoch(con: web::Data<Arc<Sequencer>>, req_body: String) -> impl Responder {
    let epoch: String = match serde_json::from_str(&req_body) {
        Ok(epoch) => epoch,
        Err(_) => return HttpResponse::BadRequest().body("Invalid epoch"),
    };

    match get_epochs_and_proofs(con, epoch.as_str()) {
        Ok(epoch_data) => {
            let EpochData {
                epoch_number,
                previous_commitment,
                current_commitment,
                proofs,
            } = epoch_data;

            match BatchMerkleProofCircuit::new(&previous_commitment, &current_commitment, proofs) {
                Ok(batch_circuit) => match batch_circuit.create_and_verify_snark() {
                    Ok((proof, _verifying_key)) => {
                        let serialized_proof: Bls12Proof = proof.into();
                        let response = json!({
                            "epoch": epoch_number,
                            "proof": serialized_proof,
                        });
                        HttpResponse::Ok().json(response)
                    }
                    Err(err) => HttpResponse::BadRequest().body(err.to_string()),
                },
                Err(err) => HttpResponse::BadRequest().body(err.to_string()),
            }
        }
        Err(err) => {
            error!(
                "validate-epoch: getting proofs for epoch {}: {}",
                epoch, err
            );
            HttpResponse::BadRequest().body("Something went wrong while getting the proofs")
        }
    }
}

#[post("/validate-hashchain-proof")]
async fn handle_validate_hashchain_proof(
    session: web::Data<Arc<Sequencer>>,
    incoming_value: web::Json<Value>,
) -> impl Responder {
    #[derive(Deserialize)]
    struct ValidateHashchainBody {
        pub_key: String,
        value: String,
    }

    let incoming_value: ValidateHashchainBody =
        match serde_json::from_value(incoming_value.into_inner()) {
            Ok(incoming_value_json) => incoming_value_json,
            Err(_) => {
                return HttpResponse::BadRequest().json("Could not parse JSON data. Wrong format.")
            }
        };

    let hashchain = match session.db.get_hashchain(&incoming_value.pub_key) {
        Ok(chain) => chain,
        Err(e) => {
            return HttpResponse::BadRequest().json(format!("Error getting hashchain: {}", e))
        }
    };

    let circuit = match HashChainEntryCircuit::create(&incoming_value.value, hashchain) {
        Ok(circuit) => circuit,
        Err(e) => {
            error!("creating circuit: {}", e);
            return HttpResponse::BadRequest().json("Could not create circuit");
        }
    };

    let rng = &mut OsRng;

    let params = match groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng) {
        Ok(params) => params,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(format!("Error generating parameters: {}", e))
        }
    };

    let proof = match groth16::create_random_proof(circuit.clone(), &params, rng) {
        Ok(proof) => proof,
        Err(e) => {
            return HttpResponse::InternalServerError().json(format!("Error creating proof: {}", e))
        }
    };

    let pvk = groth16::prepare_verifying_key(&params.vk);

    let public_param = match HashChainEntryCircuit::create_public_parameter(&incoming_value.value) {
        Ok(param) => param,
        Err(e) => return HttpResponse::BadRequest().json(e.to_string()),
    };

    match groth16::verify_proof(&pvk, &proof, &[public_param]) {
        Ok(_) => {
            let serialized_proof: Bls12Proof = proof.into();
            HttpResponse::Ok().json(json!({
                "proof": serialized_proof,
                "public_param": sha256_mod(&incoming_value.value),
            }))
        }
        Err(_) => HttpResponse::BadRequest().body("Proof is invalid"),
    }
}

/// Returns the commitment (tree root) of the IndexedMerkleTree initialized from the database.
///
#[get("/get-commitment")]
async fn get_commitment(con: web::Data<Arc<Sequencer>>) -> impl Responder {
    match con.create_tree() {
        Ok(tree) => match tree.get_commitment() {
            Ok(commitment) => match serde_json::to_string(&commitment) {
                Ok(serialized) => HttpResponse::Ok().body(serialized),
                Err(_) => {
                    HttpResponse::InternalServerError().body("Failed to serialize commitment")
                }
            },
            Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/// Returns the current state of the IndexedMerkleTree initialized from the database as a JSON object.
///
#[get("/get-current-tree")]
async fn get_current_tree(con: web::Data<Arc<Sequencer>>) -> impl Responder {
    match con.create_tree() {
        Ok(tree) => match tree.get_root() {
            Ok(node) => match serde_json::to_string(&node) {
                Ok(serialized) => HttpResponse::Ok().body(serialized),
                Err(_) => HttpResponse::InternalServerError().body("Failed to serialize tree"),
            },
            Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/get-epoch-operations")]
async fn get_epoch_operations(con: web::Data<Arc<Sequencer>>, req_body: String) -> impl Responder {
    let epoch: String = match serde_json::from_str(&req_body) {
        Ok(epoch) => epoch,
        Err(_) => return HttpResponse::BadRequest().body("Invalid epoch"),
    };

    match get_epochs_and_proofs(con, epoch.as_str()) {
        Ok(epoch_data) => match serde_json::to_string(&epoch_data) {
            Ok(json_data) => HttpResponse::Ok().body(json_data),
            Err(e) => HttpResponse::InternalServerError()
                .body(format!("Failed to serialize epoch data: {}", e)),
        },
        Err(err) => {
            error!(
                "validate-epoch: getting proofs for epoch {}: {}",
                epoch, err
            );
            HttpResponse::BadRequest().body("Something went wrong while getting the proofs")
        }
    }
}

#[get("/get-epochs")]
async fn get_epochs(con: web::Data<Arc<Sequencer>>) -> impl Responder {
    let mut epochs = match con.db.get_epochs() {
        Ok(epochs) => epochs,
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Failed to get epochs: {}", e))
        }
    };

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
        match con.db.get_commitment(&epoch) {
            Ok(value) => resp.epochs.push(Epoch {
                id: epoch,
                commitment: value,
            }),
            Err(e) => {
                return HttpResponse::InternalServerError().body(format!(
                    "Failed to get commitment for epoch {}: {}",
                    epoch, e
                ))
            }
        }
    }

    match serde_json::to_string(&resp) {
        Ok(json_resp) => HttpResponse::Ok().body(json_resp),
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Failed to serialize response: {}", e))
        }
    }
}

#[get("/finalize-epoch")]
async fn handle_finalize_epoch(con: web::Data<Arc<Sequencer>>) -> impl Responder {
    match con.finalize_epoch().await {
        Ok(epoch) => match serde_json::to_string(&epoch.proof) {
            Ok(json_proof) => HttpResponse::Ok().body(json_proof),
            Err(e) => HttpResponse::InternalServerError()
                .body(format!("Failed to serialize proof: {}", e)),
        },
        Err(err) => HttpResponse::BadRequest().body(err.to_string()),
    }
}
