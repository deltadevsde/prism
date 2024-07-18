use crate::{
    cfg::WebServerConfig,
    error::{DeimosError, DeimosResult, GeneralError},
    node_types::sequencer::Sequencer,
    storage::{ChainEntry, IncomingEntry},
    utils::{decode_signed_message, is_not_revoked, Signable},
};
use actix_cors::Cors;
use actix_web::{
    dev::Server,
    get, post,
    web::{self, Data},
    App as ActixApp, HttpResponse, HttpServer, Responder,
};
use ed25519::Signature;
use indexed_merkle_tree::{sha256_mod, tree::Proof};
use serde::{Deserialize, Serialize};
use serde_json::{self, json, Value};
use std::sync::Arc;

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

#[derive(Deserialize, Debug)]
pub struct UpdateEntryJson {
    pub signed_incoming_entry: String,
    pub public_key: String,
}

impl Signable for UpdateEntryJson {
    fn get_signature(&self) -> DeimosResult<Signature> {
        let signed_message_bytes = decode_signed_message(&self.signed_incoming_entry)?;

        // extract the first 64 bytes from the signed message which are the signature
        let signature_bytes: &[u8; 64] = match signed_message_bytes.get(..64) {
            Some(array_section) => match array_section.try_into() {
                Ok(array) => array,
                Err(e) => Err(DeimosError::General(GeneralError::DecodingError(format!(
                    "signed message to array: {}",
                    e
                ))))?,
            },
            None => Err(DeimosError::General(GeneralError::DecodingError(format!(
                "extracting signature from signed message: {}",
                &self.signed_incoming_entry
            ))))?,
        };

        Ok(Signature::from_bytes(signature_bytes))
    }

    fn get_content_to_sign(&self) -> DeimosResult<String> {
        let signed_message_bytes = decode_signed_message(&self.signed_incoming_entry)?;
        let message_bytes = &signed_message_bytes[64..];
        Ok(String::from_utf8_lossy(message_bytes).to_string())
    }

    fn get_public_key(&self) -> DeimosResult<String> {
        Ok(self.public_key.clone())
    }
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
                .service(get_commitment)
                .service(update_entry)
                .service(get_valid_keys)
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
///     - `signed_message`: An `UpdateEntryJson` object containing the id, operation, and value, signed by the public key.
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

    let incoming_entry_json = match signature_with_key.get_content_to_sign() {
        Ok(entry) => entry,
        Err(e) => {
            return HttpResponse::BadRequest().json(format!(
                "Error retrieving content from UpdateEntryJson: {}",
                e
            ))
        }
    };

    let incoming_entry: IncomingEntry = match serde_json::from_str(&incoming_entry_json) {
        Ok(entry) => entry,
        Err(e) => {
            return HttpResponse::BadRequest().json(format!("Error decoding signed content: {}", e))
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

    let result: DeimosResult<Vec<ChainEntry>> = session.db.get_hashchain(&incoming_entry.id);
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
            let hashed_id = sha256_mod(incoming_entry.id.as_bytes());
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

/// The /get-valid-keys endpoint calculates the non-revoked values associated with an ID.
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
#[post("/get-valid-keys")] // all active values for a given id
async fn get_valid_keys(con: web::Data<Arc<Sequencer>>, req_body: String) -> impl Responder {
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

/// Returns the commitment (tree root) of the IndexedMerkleTree initialized from the database.
///
#[get("/get-current-commitment")]
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
